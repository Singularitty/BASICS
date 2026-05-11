import angr
import claripy
import os

import src.global_vars as global_vars
from src.global_vars import CLIB_FUNCTIONS, GLOBAL_HOOKS, NO_EXECUTE_FUNCTIONS
from src.binary_data_extractor.core import BinaryDataExtractor
from src.exceptions import FailedLoopUnrolling, FailedConcolicExecution
from .models.memory_state import MemoryState
from .models.state_space import StateSpace
from .models.stack_frame import StackFrame
from .models.memory_transitions import MemoryTransition, OperationType, CanarySetup
from .models.call_emulator import CallEmulator
from .models.concolic_executor import ConcolicExecutor, _rss_mb
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

_GLIBC_PREFIXES = ("__isoc23_", "__isoc99_", "__")
_NO_STACK_EFFECT_USER_HELPERS = {
    "globalReturnsTrue",
    "globalReturnsFalse",
    "globalReturnsTrueOrFalse",
    "globalReturnsTrueOrFalseFromStatic",
    "printLine",
    "printIntLine",
}

def _clib_name_for_plt(plt_name, clib_names):
    """Return the matching clib name for a PLT symbol, handling glibc versioned prefixes."""
    if plt_name in clib_names:
        return plt_name
    for prefix in _GLIBC_PREFIXES:
        if plt_name.startswith(prefix):
            stripped = plt_name[len(prefix):]
            if stripped in clib_names:
                return stripped
    return None


class StateSpaceConstructor:

    def __init__(self, binary_data: BinaryDataExtractor, binary_name, current_dir, binary_path, max_iter, max_states=None, max_recursion_depth=1) -> None:

        self.project = binary_data.project
        self.cfg = binary_data.cfg
        self.analysis_entry_addr = binary_data.analysis_entry_addr
        self.user_functions = binary_data.functions
        self.loops = binary_data.loops
        self.state_space = StateSpace(current_dir, binary_name)
        self.max_iter = max_iter
        self.binary_path = binary_path
        self.max_states = max_states
        self.max_recursion_depth = max_recursion_depth
        self._hook_all_clib_plt()
        # Block-address → function-entry-address map, used to check whether a
        # fall-through address belongs to the same function as its predecessor.
        self._block_func_map: dict[int, int] = {}
        for func in self.cfg.kb.functions.values():
            try:
                for ba in func.block_addrs:
                    self._block_func_map[ba] = func.addr
            except Exception:
                pass

    @staticmethod
    def hook_clib_plt(project):
        """Pre-hook every clib PLT entry (including glibc-versioned names) to prevent
        symbolic explosion in reaching_state before any user-call summarisation."""
        clib_names = {f["Function"] for f in CLIB_FUNCTIONS}
        plt = project.loader.main_object.plt
        ret_unc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
        for name, addr in plt.items():
            if _clib_name_for_plt(name, clib_names) and not project.is_hooked(addr):
                project.hook(addr, ret_unc())
                GLOBAL_HOOKS.add(addr)

    def _hook_all_clib_plt(self):
        StateSpaceConstructor.hook_clib_plt(self.project)

    def construct_state_space(self):
        """
        Constructs the state space of the binary.
        """
        # Build initial state
        entry_addr = self.analysis_entry_addr
        node = self.__get_any_node(entry_addr)
        if node is None:
            raise ValueError(f"Entry node {hex(entry_addr)} was not present in the CFG")
        entry_instruction = node.block.capstone.insns[0]
        initial_state = MemoryState(instruction=entry_instruction)

        # Stack to maintain paths and their respective states/facts.
        # Facts are intentionally simple: constants and integer bounds for
        # rbp-relative locals/registers, enough for common Juliet guard patterns.
        stack = [(node, (node.addr,), initial_state, {}, {}, {}, {})]
        processed = set()
        processed_count = 0

        while stack:
            current_node, path_addrs, current_state, local_constants, register_constants, local_bounds, register_bounds = stack.pop()
            processed_count += 1
            if processed_count % 25 == 0:
                self.__check_memory_limit()
            state_key = self.state_space._state_key(current_state)
            facts_key = self.__facts_key(local_bounds, register_bounds)
            work_key = (current_node.addr, state_key, facts_key)
            if work_key in processed:
                continue
            processed.add(work_key)

            current_state, local_constants, register_constants, local_bounds, register_bounds = self.__process_node(
                current_node,
                current_state,
                local_constants.copy(),
                register_constants.copy(),
                local_bounds.copy(),
                register_bounds.copy(),
            )
            if self.max_states is not None and len(self.state_space.graph) >= self.max_states:
                print(f"Reached --max-states limit ({self.max_states}); stopping state-space expansion.")
                break

            if current_node.name is not None and self.__is_in_loop(current_node) and self.max_iter > 0:
                current_state = self.__process_loop(current_node, current_state)

            # Get successors
            successors = self.__get_successors(current_node)
            for successor in successors:
                if successor.addr not in path_addrs:
                    succ_locals, succ_regs, succ_local_bounds, succ_reg_bounds = self.__facts_for_successor(
                        current_node,
                        successor,
                        local_constants,
                        register_constants,
                        local_bounds,
                        register_bounds,
                    )
                    new_path_addrs = path_addrs + (successor.addr,)
                    stack.append((successor, new_path_addrs, current_state, succ_locals, succ_regs, succ_local_bounds, succ_reg_bounds))

    def __check_memory_limit(self):
        mem_limit = global_vars.MEMORY_LIMIT_MB
        if mem_limit is None:
            return
        rss = _rss_mb()
        if rss > mem_limit:
            raise MemoryError(f"Memory limit {mem_limit:.0f} MB exceeded ({rss:.0f} MB RSS)")

    def __process_node(
        self,
        node,
        current_state,
        local_constants=None,
        register_constants=None,
        local_bounds=None,
        register_bounds=None,
    ) -> tuple[MemoryState, dict, dict, dict, dict]:
        local_constants = local_constants or {}
        register_constants = register_constants or {}
        local_bounds = local_bounds or {}
        register_bounds = register_bounds or {}
        if not node.is_simprocedure:
            function_name = node.name.split("+")[0] if node.name is not None else f"sub_{node.addr:x}"
            if not current_state.contains_stack_frame(function_name):
                new_stack_frame = StackFrame()
                new_stack_frame.initialize()
                current_state = current_state.add_stack_frame(function_name, new_stack_frame)
                self.state_space.add_state(current_state)
            for ins in node.block.capstone.insns:
                self.__track_simple_facts(ins, local_constants, register_constants, local_bounds, register_bounds)
                if not current_state.contains_stack_frame(function_name) and ins.mnemonic == "endbr64":
                    new_stack_frame = StackFrame()
                    new_stack_frame.initialize()
                    next_state = current_state.add_stack_frame(function_name, new_stack_frame)
                    self.state_space.add_state(next_state)
                    self.state_space.add_transition(current_state, next_state, MemoryTransition(node.block.capstone.insns[0], self.cfg, fname=function_name))
                    current_state = next_state
                elif ins.mnemonic != "endbr64":
                    current_state = self.__transition_state(
                        ins,
                        function_name,
                        node,
                        current_state,
                        local_constants,
                        register_constants,
                        register_bounds,
                    )
        return current_state, local_constants, register_constants, local_bounds, register_bounds

    def __process_loop(self, node, current_state) -> MemoryState:
        if not global_vars.SCAN_MODE:
            print("Loop detected.\nPerforming loop emulation...")
        loop = next(filter(lambda l: l.continue_edges[0][0].addr == node.addr, self.loops), None)
        if loop is not None and self.__loop_has_only_scalar_counter_writes(loop):
            if not global_vars.SCAN_MODE:
                print("Loop has no stack-buffer writes. Skipping loop emulation.")
            return current_state
        try:
            fname, difs = self.__loop_emulator(node, current_state)
        except FailedConcolicExecution:
            print(f"Failed to execute loop.")
            print("Retrying without function hooks...")
            for addr in GLOBAL_HOOKS:
                self.project.unhook(addr)
            try:
                fname, difs = self.__loop_emulator(node, current_state)
                print("Loop emulation successful.")
            except FailedConcolicExecution:
                print("Failed to execute loop. Skipping loop emulation.")
                difs = []
            except FailedLoopUnrolling:
                print("Failed to unroll loop. Skipping loop emulation.")
                difs = []
            finally:
                ret_unc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
                for addr in GLOBAL_HOOKS:
                    if not self.project.is_hooked(addr):
                        self.project.hook(addr, ret_unc())
        except FailedLoopUnrolling:
            print("Failed to unroll loop. Skipping loop emulation.")
            return current_state
        if len(difs) > 0:
            old_frame = current_state.get_stack_frame(fname)
            new_frame = old_frame.write_multiple_bytes(difs)
            next_state = current_state.add_stack_frame(fname, new_frame)
            jump_ins = self.__get_any_node(node.addr).block.capstone.insns[-1]
            next_state = next_state.add_instruction(jump_ins)
            self.state_space.add_state(next_state)
            self.state_space.add_transition(current_state, next_state, MemoryTransition(jump_ins, self.cfg))
            return next_state
        return current_state

    def __loop_has_only_scalar_counter_writes(self, loop):
        saw_write = False
        for loop_node in getattr(loop, "body_nodes", []):
            try:
                block = self.project.factory.block(loop_node.addr)
            except Exception:
                return False
            for ins in block.capstone.insns:
                if ins.mnemonic == "call":
                    return False
                if not ins.operands:
                    continue
                dst = ins.operands[0]
                if dst.type != X86_OP_MEM:
                    continue
                saw_write = True
                mem = dst.value.mem
                if ins.reg_name(mem.base) != "rbp" or mem.index != 0:
                    return False
                if getattr(dst, "size", 0) > 4:
                    return False
        return saw_write

    def __transition_state(self, ins, function_name, node, current_state: MemoryState, local_constants=None, register_constants=None, register_bounds=None) -> MemoryState:
        local_constants = local_constants or {}
        register_constants = register_constants or {}
        register_bounds = register_bounds or {}
        transition = MemoryTransition(ins, self.cfg)
        if transition.type is not None:
            next_state = None
            match transition.type.operation_type:
                case OperationType.PUSH:
                    new_frame =  current_state.get_stack_frame(function_name).push(critical = transition.type.critical,
                                                                                   data_size = transition.type.data_size)
                    next_state = current_state.add_stack_frame(function_name, new_frame)
                    next_state = next_state.add_instruction(ins)
                case OperationType.POP:
                    new_frame = current_state.get_stack_frame(function_name).pop(data_size = transition.type.data_size)
                    next_state = current_state.add_stack_frame(function_name, new_frame)
                    next_state = next_state.add_instruction(ins)
                case OperationType.FRAME_EXTENSION:
                    new_frame = current_state.get_stack_frame(function_name).extend(transition.type.size)
                    next_state = current_state.add_stack_frame(function_name, new_frame)
                    next_state = next_state.add_instruction(ins)
                case OperationType.WRITE:
                        current_frame = current_state.get_stack_frame(function_name)
                        if current_frame.canary and not current_frame.canary_written:
                            new_frame = current_state.get_stack_frame(function_name).write_canary()
                            next_state = current_state.add_stack_frame(function_name, new_frame)
                            next_state = next_state.add_instruction(ins)
                        else:
                            if hasattr(transition.type, "index_register"):
                                new_frame = self.__indexed_write_frame(
                                    current_frame,
                                    transition.type,
                                    register_constants,
                                    register_bounds,
                                )
                            else:
                                address = transition.type.address
                                new_frame = current_frame.write(address, transition.type.data_size.value)
                            next_state = current_state.add_stack_frame(function_name, new_frame)
                            next_state = next_state.add_instruction(ins)
                case OperationType.CANARY:
                    new_frame = current_state.get_stack_frame(function_name)
                    new_frame.setup_canary()
                    next_state = current_state.add_stack_frame(function_name, new_frame)
                    next_state = next_state.add_instruction(ins)
                case OperationType.BUFFER_ALLOCATION:
                    address = transition.type.offset
                    new_frame = current_state.get_stack_frame(function_name)
                    new_frame.map_buffer(address)
                    next_state = current_state.add_stack_frame(function_name, new_frame)
                    next_state = next_state.add_instruction(ins)
                case OperationType.INDIRECT:
                    call_name = self.__determine_function_name(ins)
                    call_name = self.__sanitize_function_name(call_name)
                    if call_name is None:
                        return current_state
                    if call_name in _NO_STACK_EFFECT_USER_HELPERS:
                        return current_state
                    clib_call = False
                    for function in CLIB_FUNCTIONS:
                        if function["Function"] == call_name:
                            clib_call = True
                    if clib_call:
                        call = CallEmulator(current_state.get_stack_frame(function_name),
                                            ins,
                                            node,
                                            self.cfg,
                                            self.project,
                                            self.user_functions,
                                            self.binary_path)
                        stack_changes = call.stack_changes
                        #print(stack_changes)
                        if len(stack_changes) == 0:
                            return current_state
                        else:
                            old_frame = current_state.get_stack_frame(function_name)
                            new_frame = old_frame.write_multiple_bytes(stack_changes)
                            next_state = current_state.add_stack_frame(function_name, new_frame)
                            next_state = next_state.add_instruction(ins)
                    elif any(x.name == call_name for x in self.user_functions) and not current_state.contains_stack_frame(call_name):
                        current_state = self.__summarize_user_call(ins, function_name, node, current_state)
                        new_frame = StackFrame()
                        new_frame.initialize()
                        next_state = current_state.add_stack_frame(call_name, new_frame)
                        next_state = next_state.add_instruction(ins)
                    elif any(x.name == call_name for x in self.user_functions) and current_state.contains_stack_frame(call_name):
                        print(f"Recursive call to {call_name} (depth {self.max_recursion_depth}). Skipping.")
                        return current_state
                    elif call_name in NO_EXECUTE_FUNCTIONS:
                        return current_state
                    else:
                        if not global_vars.SCAN_MODE:
                            print(f"Unknown function call: {call_name}, skipping...")
                        return current_state
                case _:
                    return current_state
            self.state_space.add_state(next_state)
            self.state_space.add_transition(current_state, next_state, transition)
            return next_state
        return current_state

    def __indexed_write_frame(self, frame, write_op, register_constants, register_bounds):
        index_value = register_constants.get(write_op.index_register)
        if index_value is not None and index_value >= 0:
            offset = write_op.address + (index_value * write_op.scale)
            if abs(offset) <= frame.get_stack_size() + 1024:
                return frame.write(offset, write_op.data_size.value)

        index_bounds = register_bounds.get(write_op.index_register)
        if index_bounds is not None:
            low, high = index_bounds
            if low is not None and high is not None and low >= 0 and high - low <= 1024:
                offsets = [write_op.address + (index_value * write_op.scale) for index_value in range(low, high + 1)]
                if any(abs(offset) > frame.get_stack_size() + 1024 for offset in offsets):
                    offsets = []
                new_frame = frame
                for offset in offsets:
                    new_frame = new_frame.write(offset, write_op.data_size.value)
                if offsets:
                    return new_frame

        # Common C idiom: buf[n] = '\0' after a bounded input call.  If the
        # destination is a known byte buffer but the exact return bound is not
        # tracked, conservatively mark the known buffer bytes instead of
        # inventing a canary-reaching write.
        buffer_offset = abs(write_op.address)
        buffer_size = frame.get_buffer(buffer_offset)
        if write_op.data_size.value == 1 and write_op.scale == 1 and buffer_size is not None:
            start = frame.get_rbp() + buffer_offset - 1
            end = max(frame.get_rbp(), start - buffer_size + 1)
            return frame.write_multiple_bytes(range(end, start + 1))

        base_index = frame.get_rbp() + abs(write_op.address) - 1
        low_index = max(0, min(base_index, frame.get_rbp()))
        high_index = min(frame.get_stack_size() - 1, max(base_index, frame.get_rbp() + 32))
        return frame.write_multiple_bytes(range(low_index, high_index + 1))

    def __track_simple_facts(self, ins, local_constants, register_constants, local_bounds, register_bounds):
        if len(ins.operands) < 2:
            if ins.mnemonic == "call":
                self.__clear_register_facts(
                    register_constants,
                    register_bounds,
                    ("rax", "eax", "ax", "al", "rcx", "ecx", "rdx", "edx", "rsi", "esi", "rdi", "edi"),
                )
            return
        if ins.mnemonic not in ("mov", "movsxd"):
            if ins.mnemonic in ("call", "cdqe", "cltq"):
                if ins.mnemonic == "call":
                    self.__clear_register_facts(
                        register_constants,
                        register_bounds,
                        ("rax", "eax", "ax", "al", "rcx", "ecx", "rdx", "edx", "rsi", "esi", "rdi", "edi"),
                    )
                if ins.mnemonic in ("cdqe", "cltq") and "eax" in register_bounds:
                    register_bounds["rax"] = register_bounds["eax"]
                return
            if ins.operands[0].type == X86_OP_REG:
                dst_reg = ins.reg_name(ins.operands[0].reg)
                register_constants.pop(dst_reg, None)
                register_bounds.pop(dst_reg, None)
            return

        dst, src = ins.operands[0], ins.operands[1]
        if dst.type == X86_OP_MEM:
            mem = dst.value.mem
            if ins.reg_name(mem.base) == "rbp" and mem.index == 0:
                slot = mem.disp
                if src.type == X86_OP_IMM:
                    local_constants[slot] = int(src.imm)
                    local_bounds[slot] = (int(src.imm), int(src.imm))
                elif src.type == X86_OP_REG:
                    src_reg = ins.reg_name(src.reg)
                    value = register_constants.get(src_reg)
                    if value is None:
                        local_constants.pop(slot, None)
                    else:
                        local_constants[slot] = value
                    bounds = register_bounds.get(src_reg)
                    if bounds is None:
                        local_bounds.pop(slot, None)
                    else:
                        local_bounds[slot] = bounds
                else:
                    local_constants.pop(slot, None)
                    local_bounds.pop(slot, None)
            return

        if dst.type != X86_OP_REG:
            return
        dst_reg = ins.reg_name(dst.reg)
        if src.type == X86_OP_IMM:
            register_constants[dst_reg] = int(src.imm)
            register_bounds[dst_reg] = (int(src.imm), int(src.imm))
        elif src.type == X86_OP_REG:
            src_reg = ins.reg_name(src.reg)
            value = register_constants.get(src_reg)
            if value is None:
                register_constants.pop(dst_reg, None)
            else:
                register_constants[dst_reg] = value
            bounds = register_bounds.get(src_reg)
            if bounds is None:
                register_bounds.pop(dst_reg, None)
            else:
                register_bounds[dst_reg] = bounds
        elif src.type == X86_OP_MEM:
            mem = src.value.mem
            if ins.reg_name(mem.base) == "rbp" and mem.index == 0 and mem.disp in local_constants:
                register_constants[dst_reg] = local_constants[mem.disp]
            else:
                register_constants.pop(dst_reg, None)
            if ins.reg_name(mem.base) == "rbp" and mem.index == 0 and mem.disp in local_bounds:
                register_bounds[dst_reg] = local_bounds[mem.disp]
            else:
                register_bounds.pop(dst_reg, None)
        else:
            register_constants.pop(dst_reg, None)
            register_bounds.pop(dst_reg, None)

        if dst_reg == "eax" and "eax" in register_constants:
            register_constants["rax"] = register_constants["eax"]
        if dst_reg == "eax" and "eax" in register_bounds:
            register_bounds["rax"] = register_bounds["eax"]

    def __clear_register_facts(self, register_constants, register_bounds, regs):
        for reg in regs:
            register_constants.pop(reg, None)
            register_bounds.pop(reg, None)

    def __facts_key(self, local_bounds, register_bounds):
        return (
            tuple(sorted(local_bounds.items())),
            tuple(sorted(register_bounds.items())),
        )

    def __facts_for_successor(self, node, successor, local_constants, register_constants, local_bounds, register_bounds):
        succ_locals = local_constants.copy()
        succ_regs = register_constants.copy()
        succ_local_bounds = local_bounds.copy()
        succ_reg_bounds = register_bounds.copy()
        self.__apply_branch_bounds(node, successor, succ_local_bounds, succ_reg_bounds)
        return succ_locals, succ_regs, succ_local_bounds, succ_reg_bounds

    def __apply_branch_bounds(self, node, successor, local_bounds, register_bounds):
        if node.is_simprocedure or node.block is None:
            return
        insns = node.block.capstone.insns
        if len(insns) < 2:
            return
        jump = insns[-1]
        cmp_ins = insns[-2]
        if cmp_ins.mnemonic != "cmp" or len(cmp_ins.operands) != 2:
            return
        if cmp_ins.operands[1].type != X86_OP_IMM:
            return

        key, bounds_map_name = self.__cmp_lvalue(cmp_ins)
        if key is None:
            return
        bounds_map = local_bounds if bounds_map_name == "local" else register_bounds

        target = jump.operands[0].imm if jump.operands and jump.operands[0].type == X86_OP_IMM else None
        if target is None:
            return
        branch_taken = successor.addr == target
        fallthrough = successor.addr == node.addr + node.size
        if not branch_taken and not fallthrough:
            return

        value = int(cmp_ins.operands[1].imm)
        current = bounds_map.get(key, (None, None))
        new_bounds = self.__bounds_after_jump(jump.mnemonic, value, branch_taken, current)
        if new_bounds is not None:
            bounds_map[key] = new_bounds

    def __cmp_lvalue(self, cmp_ins):
        lhs = cmp_ins.operands[0]
        if lhs.type == X86_OP_MEM:
            mem = lhs.value.mem
            if cmp_ins.reg_name(mem.base) == "rbp" and mem.index == 0:
                return mem.disp, "local"
        if lhs.type == X86_OP_REG:
            return cmp_ins.reg_name(lhs.reg), "register"
        return None, None

    def __bounds_after_jump(self, mnemonic, value, branch_taken, current):
        low, high = current

        def merge(new_low, new_high):
            if new_low is not None:
                new_low = new_low if low is None else max(low, new_low)
            else:
                new_low = low
            if new_high is not None:
                new_high = new_high if high is None else min(high, new_high)
            else:
                new_high = high
            return (new_low, new_high)

        if mnemonic in ("jg", "jnle"):
            return merge(value + 1, None) if branch_taken else merge(None, value)
        if mnemonic in ("jge", "jnl"):
            return merge(value, None) if branch_taken else merge(None, value - 1)
        if mnemonic in ("jl", "jnge", "js"):
            return merge(None, value - 1) if branch_taken else merge(value, None)
        if mnemonic in ("jle", "jng"):
            return merge(None, value) if branch_taken else merge(value + 1, None)
        if mnemonic in ("ja", "jnbe"):
            return merge(value + 1, None) if branch_taken else merge(None, value)
        if mnemonic in ("jae", "jnb"):
            return merge(value, None) if branch_taken else merge(None, value - 1)
        if mnemonic in ("jb", "jnae"):
            return merge(None, value - 1) if branch_taken else merge(value, None)
        if mnemonic in ("jbe", "jna"):
            return merge(None, value) if branch_taken else merge(value + 1, None)
        if mnemonic in ("je", "jz"):
            return merge(value, value) if branch_taken else current
        return None

    def __summarize_user_call(self, ins, function_name, node, current_state):
        current_frame = current_state.get_stack_frame(function_name)

        # Temporarily hook any clib PLT entries not yet emulated so that
        # reaching_state doesn't hit symbolic strlen/strcpy/etc. which makes
        # each simgr step extremely expensive.  Uses fuzzy matching to handle
        # glibc-versioned names like __isoc23_scanf.
        clib_names = {f["Function"] for f in CLIB_FUNCTIONS}
        plt = self.project.loader.main_object.plt
        ret_unc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
        temp_hooked = []
        for name, addr in plt.items():
            if _clib_name_for_plt(name, clib_names) and not self.project.is_hooked(addr):
                self.project.hook(addr, ret_unc())
                temp_hooked.append(addr)
        for func in self.user_functions:
            if func.addr == self.analysis_entry_addr:
                continue
            if self.__function_has_self_call(func) and not self.project.is_hooked(func.addr):
                self.project.hook(func.addr, ret_unc())
                temp_hooked.append(func.addr)

        try:
            pre_call_state = ConcolicExecutor.reaching_state(self.project, node.addr)
            instruction_index = self.__instruction_index_in_block(node, ins.address)
            pre_call_state = ConcolicExecutor.advance_instructions(self.project, pre_call_state, instruction_index)
            stack_pointer = pre_call_state.regs.rsp
            stack_before = pre_call_state.solver.eval(
                pre_call_state.memory.load(stack_pointer, current_frame.get_stack_size()),
                cast_to=bytes,
            )
            post_call_state = ConcolicExecutor.step_from_state(self.project, pre_call_state, steps=1)
            stack_after = post_call_state.solver.eval(
                post_call_state.memory.load(stack_pointer, current_frame.get_stack_size()),
                cast_to=bytes,
            )
            difs = self.stack_comparison(stack_before, stack_after)
        except (FailedConcolicExecution, ValueError):
            return current_state
        finally:
            for addr in temp_hooked:
                self.project.unhook(addr)

        if not difs:
            return current_state
        new_frame = current_frame.write_multiple_bytes(difs)
        next_state = current_state.add_stack_frame(function_name, new_frame)
        next_state = next_state.add_instruction(ins)
        self.state_space.add_state(next_state)
        self.state_space.add_transition(current_state, next_state, MemoryTransition(ins, self.cfg))
        return next_state

    def __instruction_index_in_block(self, node, instruction_addr):
        for index, instruction in enumerate(node.block.capstone.insns):
            if instruction.address == instruction_addr:
                return index
        return 0

    def __function_has_self_call(self, func):
        try:
            block_addrs = list(func.block_addrs)
        except Exception:
            return False
        for addr in block_addrs:
            try:
                block = self.project.factory.block(addr)
            except Exception:
                continue
            for ins in block.capstone.insns:
                if ins.mnemonic != "call" or not ins.operands:
                    continue
                try:
                    if ins.operands[0].imm == func.addr:
                        return True
                except Exception:
                    continue
        return False

    def __loop_emulator(self, node, state, max_iterations=20) -> (str, list[int]):
        function_name = node.name.split("+")[0]

        loop = next(filter(lambda l: l.continue_edges[0][0].addr == node.addr, self.loops), None)
        assert loop is not None, f"Loop not found for node {node.addr}"

        loop_entry = loop.continue_edges[0][0].addr

        # A recursive function appears as a loop with no break-edges (the only
        # "exit" is a return instruction, not a CFG break-edge).  Bail out
        # before calling reaching_state — that concolic query is prohibitively
        # expensive for recursive functions with symbolic inputs.
        if not loop.break_edges:
            raise FailedLoopUnrolling(f"No break edges for loop at {hex(loop_entry)}; likely a recursive function")

        entry_addr = node.function_address
        try:
            exit_addr = loop.break_edges[0][-1].addr
        except IndexError:
            raise FailedConcolicExecution(f"Could not find target address {hex(loop_entry)} after executing loop at {hex(entry_addr)}")

        current_stack_frame = state.get_stack_frame(function_name)

        # Start concolic execution from the containing function's entry, not the
        # global analysis entry.  When the analysis entry is a wrapper (e.g.
        # _good()) that calls several sub-functions, using the global entry forces
        # angr to navigate the full call chain on every reaching_state call,
        # multiplying cost by the number of sub-functions.
        pre_loop_state = ConcolicExecutor.reaching_state(self.project, loop_entry, start_addr=entry_addr)
        stack_pointer = pre_loop_state.regs.rsp

        stack_memory_before = pre_loop_state.solver.eval(pre_loop_state.memory.load(stack_pointer, current_stack_frame.get_stack_size()), cast_to=bytes)

        iteration_count = 0

        simgr = self.project.factory.simgr(pre_loop_state)

        while iteration_count < self.max_iter:
            simgr.step()

            if len(simgr.active) == 0:
                raise FailedLoopUnrolling("No active states left to execute. The loop may not have executed properly.")

            # Prune states to prevent exponential explosion when loop body
            # contains branches over unconstrained values (e.g. socket return codes).
            if len(simgr.active) > global_vars.CONCOLIC_ACTIVE_LIMIT:
                simgr.active = sorted(
                    simgr.active,
                    key=lambda s: abs(s.addr - exit_addr),
                )[:global_vars.CONCOLIC_ACTIVE_LIMIT]

            for active_state in simgr.active:
                if active_state.addr == loop_entry:
                    iteration_count += 1
                    if iteration_count >= self.max_iter:
                        break

            # Check if any state has reached the loop exit
            if any(active_state.addr == exit_addr for active_state in simgr.active):
                break

        post_loop_state = next((s for s in simgr.active if s.addr == exit_addr), None)

        if post_loop_state is None:
            print(f"Could not find target address {hex(exit_addr)} after executing loop at {hex(entry_addr)}\nSkipping loop emulation\nMaybe try to increase the maximum number of iterations with the --max-iterations flag. (default is 20)\n")
            return function_name, []

        stack_memory_after = post_loop_state.solver.eval(post_loop_state.memory.load(stack_pointer, current_stack_frame.get_stack_size()), cast_to=bytes)

        difs = self.stack_comparison(stack_memory_before, stack_memory_after)
        return function_name, difs

    def stack_comparison(self, stack_before, stack_after):

        diffs = []

        stack_size = len(stack_before)

        if len(stack_before) != len(stack_after):
            raise ValueError(f"Stacks have different sizes after executing Loop.")

        for i in range(len(stack_before)):
            if stack_before[i] != stack_after[i]:
                diffs.append(self.convert_indice(i, stack_size))

        return diffs

    def convert_indice(self, indice, stack_size):
        """Converts the index given by the emulator to the index of the stack array.
        """
        if indice == 0:
            return stack_size - 1
        return ((stack_size - 1) - indice) % (stack_size - 1)

    def __determine_function_name(self, ins):
        call_addr = ins.operands[0].imm
        for func in self.cfg.kb.functions.values():
            if func.addr == call_addr:
                return func.name

    def __sanitize_function_name(self, function_name):
        if function_name is None:
            return None
        if "isoc99" in function_name or "isoc23" in function_name:
            return function_name.split("_")[-1]
        if function_name[0:2] == "__":
            return function_name[2:]
        return function_name

    def __is_in_loop(self, node) -> bool:
        for loop in self.loops:
            if node.addr == loop.continue_edges[0][0].addr:
                return True
        return False

    def __get_any_node(self, addr):
        if hasattr(self.cfg, "get_any_node"):
            return self.cfg.get_any_node(addr)
        return self.cfg.model.get_any_node(addr)

    def __get_successors(self, node):
        model = self.cfg if hasattr(self.cfg, "get_successors") else self.cfg.model
        succs = list(model.get_successors(node))

        # CFGFast does not record call-return edges for PLT calls — the block
        # ending with `call plt_stub` only lists the PLT entry as successor, but
        # the block that continues AFTER the call (at node.addr + node.size) is
        # left with no predecessor and is never visited.  Recover it here by
        # adding the fall-through block — but only if it belongs to the current
        # function (prevents bleeding into adjacent functions in memory).
        if node.block is not None:
            fallthrough = node.addr + node.size
            ft_node = model.get_any_node(fallthrough)
            if ft_node is not None and ft_node not in succs:
                # Only add the fall-through if both addresses belong to the same
                # function — prevents bleeding into adjacent functions in memory.
                n_func = self._block_func_map.get(node.addr)
                ft_func = self._block_func_map.get(fallthrough)
                if n_func is not None and n_func == ft_func:
                    succs.append(ft_node)

        skip_call_addr = None
        if not node.is_simprocedure and node.block is not None:
            insns = node.block.capstone.insns
            if insns and insns[-1].mnemonic == "call":
                call_name = self.__sanitize_function_name(self.__determine_function_name(insns[-1]))
                clib_names = {f["Function"] for f in CLIB_FUNCTIONS}
                if (
                    call_name in _NO_STACK_EFFECT_USER_HELPERS
                    or call_name in NO_EXECUTE_FUNCTIONS
                    or call_name in clib_names
                ):
                    try:
                        skip_call_addr = insns[-1].operands[0].imm
                    except Exception:
                        skip_call_addr = None
        if skip_call_addr is not None:
            succs = [succ for succ in succs if succ.addr != skip_call_addr]

        return succs
