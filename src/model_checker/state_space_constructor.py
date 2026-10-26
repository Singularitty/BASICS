import angr
import claripy
import os
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser

import src.global_vars as global_vars
from src.global_vars import CLIB_FUNCTIONS, GLOBAL_HOOKS, NO_EXECUTE_FUNCTIONS
from src.binary_data_extractor.core import BinaryDataExtractor
from src.exceptions import FailedLoopUnrolling, FailedConcolicExecution
from .models.memory_state import MemoryState
from .models.state_space import StateSpace
from .models.stack_frame import StackFrame
from .models.memory_transitions import MemoryTransition, OperationType, CanarySetup, PointerWriteOperation
from .models.call_emulator import CallEmulator
from .models import emulation_trace
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
# Registers a callee may clobber; pointer facts about them die at a call's return.
_CALLER_SAVED_REGISTERS = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
_ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_REGISTER_64 = {
    sub: full
    for full, subs in {
        "rax": ("eax", "ax", "al", "ah"), "rbx": ("ebx", "bx", "bl", "bh"),
        "rcx": ("ecx", "cx", "cl", "ch"), "rdx": ("edx", "dx", "dl", "dh"),
        "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
        "rbp": ("ebp", "bp", "bpl"), "rsp": ("esp", "sp", "spl"),
        **{f"r{n}": (f"r{n}d", f"r{n}w", f"r{n}b") for n in range(8, 16)},
    }.items()
    for sub in subs + (full,)
}


class _ConcreteWcslen(angr.SimProcedure):
    """Model glibc's four-byte ``wchar_t`` strings used by Juliet.

    angr does not currently ship a wcslen SimProcedure.  Returning an
    unconstrained value here makes Juliet's variable-length alloca symbolic,
    which in turn explodes even for the labelled non-vulnerable cases.
    """

    def run(self, string):
        for index in range(4096):
            wchar = self.state.memory.load(string + index * 4, 4, endness="Iend_LE")
            if self.state.solver.is_true(wchar == 0):
                return index
            if self.state.solver.symbolic(wchar):
                break
        return self.state.solver.Unconstrained("wcslen", self.state.arch.bits)

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
        self._pointer_store_cache = {}
        self._written_globals = None
        self._constant_return_cache = {}
        self._current_path = None
        self.binary_path = binary_path
        self.max_states = max_states
        self.max_recursion_depth = max_recursion_depth
        self._dwarf_buffers = self.__load_dwarf_stack_buffers()
        self._dwarf_runtime_bias = {}
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
        self._dynamic_write_allocations = {}
        # rbp-slot stores of an alloca pointer: address -> (requested size, offset)
        self._alloca_pointer_stores = {}
        self._inlined_alloca_overflow_writes = self.__find_inlined_alloca_overflow_writes()

    @staticmethod
    def hook_clib_plt(project):
        """Pre-hook every clib PLT entry (including glibc-versioned names) to prevent
        symbolic explosion in reaching_state before any user-call summarisation."""
        clib_names = {f["Function"] for f in CLIB_FUNCTIONS}
        plt = project.loader.main_object.plt
        ret_unc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
        for name, addr in plt.items():
            clib_name = _clib_name_for_plt(name, clib_names)
            if not clib_name or project.is_hooked(addr):
                continue
            # Loop bounds in Juliet frequently depend on strlen after memset.
            # ReturnUnconstrained turns those deterministic bounds symbolic and
            # causes exponential loop exploration.  Preserve the concrete
            # memory/length semantics needed to reach loop exits.
            if clib_name in {"strlen", "memset", "wcslen"}:
                if clib_name == "wcslen":
                    project.hook(addr, _ConcreteWcslen())
                    continue
                procedure = angr.SIM_PROCEDURES["libc"].get(clib_name)
                if procedure is not None:
                    project.hook(addr, procedure())
                    continue
            if not project.is_hooked(addr):
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
        # pointer_facts maps registers, rbp slots and globals that hold a stack
        # address to (frame name, offset, alloca size), so stores through
        # pointers can be applied to the frame that owns the buffer, possibly
        # a caller's.  The offset is rbp-relative, or relative to the start of
        # a dynamic allocation of the given size.
        stack = [(node, (node.addr,), initial_state, {}, {}, {}, {}, {})]
        processed = set()
        processed_count = 0

        while stack:
            current_node, path_addrs, current_state, local_constants, register_constants, local_bounds, register_bounds, pointer_facts = stack.pop()
            processed_count += 1
            if processed_count % 25 == 0:
                self.__check_memory_limit()
            state_key = self.state_space._state_key(current_state)
            facts_key = self.__facts_key(local_bounds, register_bounds)
            work_key = (
                current_node.addr,
                state_key,
                facts_key,
                self.__pointer_assignment_key(path_addrs),
                tuple(sorted(pointer_facts.items(), key=repr)),
            )
            if work_key in processed:
                continue
            processed.add(work_key)

            current_state, local_constants, register_constants, local_bounds, register_bounds, pointer_facts = self.__process_node(
                current_node,
                current_state,
                local_constants.copy(),
                register_constants.copy(),
                local_bounds.copy(),
                register_bounds.copy(),
                path_addrs,
                pointer_facts.copy(),
            )
            if self.max_states is not None and len(self.state_space.graph) >= self.max_states:
                print(f"Reached --max-states limit ({self.max_states}); stopping state-space expansion.")
                break

            if current_node.name is not None and self.__is_in_loop(current_node) and self.max_iter > 0:
                current_state = self.__process_loop(current_node, current_state)

            # Get successors
            successors = self.__get_successors(current_node)
            for successor in successors:
                if self.__branch_infeasible(current_node, successor, local_constants, register_constants):
                    continue
                if successor.addr not in path_addrs:
                    succ_locals, succ_regs, succ_local_bounds, succ_reg_bounds = self.__facts_for_successor(
                        current_node,
                        successor,
                        local_constants,
                        register_constants,
                        local_bounds,
                        register_bounds,
                    )
                    succ_pointers = self.__pointer_facts_for_successor(current_node, successor, pointer_facts)
                    new_path_addrs = path_addrs + (successor.addr,)
                    stack.append((successor, new_path_addrs, current_state, succ_locals, succ_regs, succ_local_bounds, succ_reg_bounds, succ_pointers))

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
        path_addrs=None,
        pointer_facts=None,
    ) -> tuple[MemoryState, dict, dict, dict, dict, dict]:
        self._current_path = self.__path_with_loop_bodies(path_addrs)
        local_constants = local_constants or {}
        register_constants = register_constants or {}
        local_bounds = local_bounds or {}
        register_bounds = register_bounds or {}
        pointer_facts = pointer_facts if pointer_facts is not None else {}
        if not node.is_simprocedure:
            function_name = node.name.split("+")[0] if node.name is not None else f"sub_{node.addr:x}"
            if not current_state.contains_stack_frame(function_name):
                new_stack_frame = StackFrame()
                new_stack_frame.initialize()
                self.__apply_dwarf_buffers(new_stack_frame, function_name)
                current_state = current_state.add_stack_frame(function_name, new_stack_frame)
                self.state_space.add_state(current_state)
            for ins in node.block.capstone.insns:
                self.__track_simple_facts(ins, local_constants, register_constants, local_bounds, register_bounds)
                self.__track_constant_facts(ins, register_constants)
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
                        pointer_facts,
                    )
                # After the transition: a store or call uses the facts that
                # held before the instruction executed.
                self.__track_pointer_facts(ins, function_name, pointer_facts)
        return current_state, local_constants, register_constants, local_bounds, register_bounds, pointer_facts

    def __process_loop(self, node, current_state) -> MemoryState:
        if not global_vars.SCAN_MODE:
            print("Loop detected.\nPerforming loop emulation...")
        fname = self.__function_name_for_node(node)
        loop = next(filter(lambda l: l.continue_edges[0][0].addr == node.addr, self.loops), None)
        if loop is not None and self.__loop_has_only_scalar_counter_writes(loop):
            if not global_vars.SCAN_MODE:
                print("Loop has no stack-buffer writes. Skipping loop emulation.")
            return current_state
        if global_vars.LOOP_SIMULATION == "static":
            difs = self.__static_loop_stack_write_indices(loop, current_state, fname, node)
            return self.__apply_loop_stack_writes(node, current_state, fname, difs)
        try:
            fname, difs = self.__loop_emulator(node, current_state)
        except FailedConcolicExecution as exc:
            print(f"Failed to execute loop: {exc}" if global_vars.DEBUG else "Failed to execute loop.")
            print("Retrying without function hooks...")
            for addr in GLOBAL_HOOKS:
                self.project.unhook(addr)
            try:
                fname, difs = self.__loop_emulator(node, current_state)
                print("Loop emulation successful.")
            except FailedConcolicExecution as exc:
                print(
                    f"Failed to execute loop: {exc}. Skipping loop emulation."
                    if global_vars.DEBUG else
                    "Failed to execute loop. Skipping loop emulation."
                )
                difs = self.__loop_fallback_indices(loop, current_state, fname, node)
            except FailedLoopUnrolling:
                print("Failed to unroll loop. Skipping loop emulation.")
                difs = self.__loop_fallback_indices(loop, current_state, fname, node)
            finally:
                ret_unc = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
                for addr in GLOBAL_HOOKS:
                    if not self.project.is_hooked(addr):
                        self.project.hook(addr, ret_unc())
        except FailedLoopUnrolling:
            print("Failed to unroll loop. Skipping loop emulation.")
            difs = self.__loop_fallback_indices(loop, current_state, fname, node)
        return self.__apply_loop_stack_writes(node, current_state, fname, difs)

    def __loop_fallback_indices(self, loop, current_state, function_name, loop_node):
        if global_vars.LOOP_SIMULATION != "concolic-static":
            return []
        return self.__static_loop_stack_write_indices(
            loop, current_state, function_name, loop_node
        )

    def __apply_loop_stack_writes(self, node, current_state, function_name, difs):
        if len(difs) > 0:
            old_frame = current_state.get_stack_frame(function_name)
            new_frame = old_frame.write_multiple_bytes(difs)
            next_state = current_state.add_stack_frame(function_name, new_frame)
            jump_ins = self.__get_any_node(node.addr).block.capstone.insns[-1]
            next_state = next_state.add_instruction(jump_ins)
            self.state_space.add_state(next_state)
            self.state_space.add_transition(current_state, next_state, MemoryTransition(jump_ins, self.cfg))
            return next_state
        return current_state

    def __function_name_for_node(self, node):
        try:
            func = self.cfg.kb.functions.get_by_addr(node.function_address)
            if func is not None:
                return func.name
        except Exception:
            pass
        return node.name.split("+")[0] if node.name is not None else f"sub_{node.addr:x}"

    def __static_loop_stack_write_indices(self, loop, current_state, function_name, loop_node):
        """Conservative fallback for simple stack-copy loops when angr loop emulation fails."""
        if loop is None or not current_state.contains_stack_frame(function_name):
            return []
        aliases = self.__stack_pointer_aliases_until(loop_node)
        body_nodes = sorted(getattr(loop, "body_nodes", []), key=lambda n: n.addr)
        for body_node in body_nodes:
            try:
                block = self.project.factory.block(body_node.addr)
            except Exception:
                continue
            for ins in block.capstone.insns:
                self.__update_stack_aliases(ins, aliases)
                if not ins.operands:
                    continue
                dst = ins.operands[0]
                if dst.type != X86_OP_MEM:
                    continue
                mem = dst.value.mem
                base = self.__canonical_ins_register(ins, mem.base)
                index = self.__canonical_ins_register(ins, mem.index)
                base_target = aliases.get(base)
                if base_target not in ("rsp", "rbp"):
                    continue
                if index is not None:
                    frame = current_state.get_stack_frame(function_name)
                    if global_vars.DEBUG:
                        print(
                            f"Static loop fallback: indexed stack write at {hex(ins.address)} "
                            f"via {base}+{index}; using full-frame write."
                        )
                    return list(range(frame.get_stack_size()))
        return []

    def __stack_pointer_aliases_until(self, loop_node):
        aliases = {"rsp": "rsp", "rbp": "rbp"}
        try:
            func = self.cfg.kb.functions.get_by_addr(loop_node.function_address)
            block_addrs = sorted(func.block_addrs)
        except Exception:
            block_addrs = [loop_node.addr]
        for addr in block_addrs:
            if addr >= loop_node.addr:
                continue
            try:
                block = self.project.factory.block(addr)
            except Exception:
                continue
            for ins in block.capstone.insns:
                self.__update_stack_aliases(ins, aliases)
        return aliases

    def __update_stack_aliases(self, ins, aliases):
        if len(ins.operands) < 2:
            return
        dst = ins.operands[0]
        src = ins.operands[1]
        if dst.type != X86_OP_REG:
            return
        dst_reg = self.__canonical_ins_register(ins, dst.reg)
        if ins.mnemonic == "mov" and src.type == X86_OP_REG:
            src_reg = self.__canonical_ins_register(ins, src.reg)
            if src_reg in aliases:
                aliases[dst_reg] = aliases[src_reg]
            else:
                aliases.pop(dst_reg, None)
        elif ins.mnemonic == "lea" and src.type == X86_OP_MEM:
            base = self.__canonical_ins_register(ins, src.value.mem.base)
            if base in aliases:
                aliases[dst_reg] = aliases[base]
            else:
                aliases.pop(dst_reg, None)
        elif ins.mnemonic in ("add", "sub") and dst_reg not in ("rsp", "rbp"):
            aliases.pop(dst_reg, None)

    def __canonical_ins_register(self, ins, reg_id):
        if reg_id == 0:
            return None
        name = ins.reg_name(reg_id)
        aliases = {
            "esp": "rsp", "sp": "rsp", "spl": "rsp",
            "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
            "eax": "rax", "ax": "rax", "al": "rax",
            "ebx": "rbx", "bx": "rbx", "bl": "rbx",
            "ecx": "rcx", "cx": "rcx", "cl": "rcx",
            "edx": "rdx", "dx": "rdx", "dl": "rdx",
            "esi": "rsi", "si": "rsi", "sil": "rsi",
            "edi": "rdi", "di": "rdi", "dil": "rdi",
            "r8d": "r8", "r8w": "r8", "r8b": "r8",
            "r9d": "r9", "r9w": "r9", "r9b": "r9",
        }
        return aliases.get(name, name)

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

    def __transition_state(self, ins, function_name, node, current_state: MemoryState, local_constants=None, register_constants=None, register_bounds=None, pointer_facts=None) -> MemoryState:
        local_constants = local_constants or {}
        register_constants = register_constants or {}
        register_bounds = register_bounds or {}
        pointer_facts = pointer_facts or {}
        if ins.address in self._inlined_alloca_overflow_writes:
            frame = current_state.get_stack_frame(function_name)
            next_state = current_state.add_stack_frame(
                function_name, frame.write_multiple_bytes(range(frame.get_stack_size()))
            )
            next_state = next_state.add_instruction(ins)
            self.state_space.add_state(next_state)
            self.state_space.add_transition(current_state, next_state, MemoryTransition(ins, self.cfg))
            return next_state
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
                case OperationType.WRITE if isinstance(transition.type, PointerWriteOperation):
                    return self.__pointer_write_state(
                        ins, transition, current_state, pointer_facts, register_constants
                    )
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
                    self.__apply_dwarf_buffers(new_frame, function_name)
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
                        pointer_destinations = self.__pointer_call_destinations(function_name, current_state, pointer_facts)
                        call = CallEmulator(current_state.get_stack_frame(function_name),
                                            ins,
                                            node,
                                            self.cfg,
                                            self.project,
                                            self.user_functions,
                                            self.binary_path,
                                            path_blocks=self._current_path,
                                            pointer_destinations={
                                                reg: destination[1:] for reg, destination in pointer_destinations.items()
                                            })
                        stack_changes = call.stack_changes
                        # The destination may be a caller's buffer reached through a pointer argument.
                        written_frame = function_name
                        if call.pointer_destination_register is not None:
                            written_frame = pointer_destinations[call.pointer_destination_register][0]
                        #print(stack_changes)
                        if len(stack_changes) == 0:
                            if call.function_name == "gets":
                                next_state = current_state.add_instruction(ins)
                            else:
                                return current_state
                        else:
                            old_frame = current_state.get_stack_frame(written_frame)
                            new_frame = old_frame.write_multiple_bytes(stack_changes)
                            next_state = current_state.add_stack_frame(written_frame, new_frame)
                            next_state = next_state.add_instruction(ins)
                    elif any(x.name == call_name for x in self.user_functions) and not current_state.contains_stack_frame(call_name):
                        if global_vars.USER_CALL_SIMULATION == "concolic":
                            current_state = self.__summarize_user_call(
                                ins, function_name, node, current_state
                            )
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
                        emulation_trace.record(function=call_name, call_addr=hex(ins.address), outcome="unknown_call")
                        return current_state
                case _:
                    return current_state
            self.state_space.add_state(next_state)
            self.state_space.add_transition(current_state, next_state, transition)
            return next_state
        return current_state

    def __apply_dwarf_buffers(self, frame, function_name):
        for offset, size in self._dwarf_buffers.get(function_name, ()):
            frame.buffer_map[abs(int(offset))] = int(size)

    def __load_dwarf_stack_buffers(self):
        """Recover fixed local-array boundaries from the benchmark's DWARF."""
        buffers = {}
        try:
            with open(self.binary_path, "rb") as stream:
                elf = ELFFile(stream)
                if not elf.has_dwarf_info():
                    return buffers
                dwarf = elf.get_dwarf_info()
                parser = DWARFExprParser(dwarf.structs)
                for cu in dwarf.iter_CUs():
                    for die in cu.iter_DIEs():
                        if die.tag != "DW_TAG_subprogram":
                            continue
                        name_attr = die.attributes.get("DW_AT_name")
                        if name_attr is None:
                            continue
                        name = name_attr.value.decode(errors="replace") if isinstance(name_attr.value, bytes) else str(name_attr.value)
                        recovered = []
                        for child in die.iter_children():
                            self.__collect_dwarf_array_variables(child, cu, parser, recovered)
                        if recovered:
                            buffers[name] = recovered
        except Exception as exc:
            if global_vars.DEBUG:
                print(f"Could not read DWARF stack buffers: {exc}")
        return buffers

    def __collect_dwarf_array_variables(self, die, cu, parser, recovered):
        if die.tag == "DW_TAG_variable":
            location = die.attributes.get("DW_AT_location")
            type_attr = die.attributes.get("DW_AT_type")
            if location is not None and type_attr is not None:
                try:
                    operations = parser.parse_expr(bytes(location.value))
                    if operations and operations[0].op_name == "DW_OP_fbreg":
                        type_die = die.get_DIE_from_attribute("DW_AT_type")
                        size = self.__dwarf_array_size(type_die, cu)
                        if size:
                            # On x86-64 with a frame pointer, CFA is rbp+16.
                            recovered.append((int(operations[0].args[0]) + 16, int(size)))
                except Exception:
                    pass
        for child in die.iter_children():
            self.__collect_dwarf_array_variables(child, cu, parser, recovered)

    def __dwarf_array_size(self, die, cu):
        visited = set()
        while die is not None and die.offset not in visited:
            visited.add(die.offset)
            if die.tag == "DW_TAG_array_type":
                size_attr = die.attributes.get("DW_AT_byte_size")
                if size_attr is not None:
                    return int(size_attr.value)
                type_attr = die.attributes.get("DW_AT_type")
                element = die.get_DIE_from_attribute("DW_AT_type") if type_attr else None
                element_size = self.__dwarf_type_size(element, cu)
                count = 1
                for child in die.iter_children():
                    if child.tag != "DW_TAG_subrange_type":
                        continue
                    count_attr = child.attributes.get("DW_AT_count")
                    upper_attr = child.attributes.get("DW_AT_upper_bound")
                    count *= int(count_attr.value) if count_attr else int(upper_attr.value) + 1 if upper_attr else 1
                return element_size * count if element_size else None
            type_attr = die.attributes.get("DW_AT_type")
            if type_attr is None:
                return None
            die = die.get_DIE_from_attribute("DW_AT_type")
        return None

    def __dwarf_type_size(self, die, cu):
        visited = set()
        while die is not None and die.offset not in visited:
            visited.add(die.offset)
            size_attr = die.attributes.get("DW_AT_byte_size")
            if size_attr is not None:
                return int(size_attr.value)
            type_attr = die.attributes.get("DW_AT_type")
            if type_attr is None:
                return None
            die = die.get_DIE_from_attribute("DW_AT_type")
        return None

    def __find_inlined_alloca_overflow_writes(self):
        """Find constant indirect writes beyond a recovered dynamic alloca.

        GCC expands fixed-size memcpy/memmove calls into register-indirect movs
        even at -O0.  MemoryTransition intentionally ignores arbitrary [reg]
        writes, so the entire Juliet alloca-copy family otherwise disappears.
        This small forward analysis follows constant allocation sizes and
        pointer spills within each recovered function.
        """
        overflow_writes = set()
        for func in self.cfg.kb.functions.values():
            constants = {}
            aliases = {}
            local_aliases = {}
            current_alloc_size = None
            requested_alloc_size = None
            instructions = []
            for addr in sorted(getattr(func, "block_addrs", ())):
                try:
                    instructions.extend(self.project.factory.block(addr).capstone.insns)
                except Exception:
                    continue
            seen = set()
            for ins in instructions:
                if ins.address in seen:
                    continue
                seen.add(ins.address)
                ops = ins.operands
                if not ops:
                    continue

                # Flag writes through a pointer known to refer to the latest
                # dynamic allocation.  Constant displacements are sufficient
                # for GCC's unrolled memcpy/memmove expansion.
                dst = ops[0]
                if dst.type == X86_OP_MEM:
                    mem = dst.value.mem
                    base = self.__canonical_ins_register(ins, mem.base)
                    alias = aliases.get(base)
                    if alias is not None:
                        self._dynamic_write_allocations[ins.address] = int(alias[0])
                    if alias is not None and mem.index == 0:
                        alloc_size, base_offset, _ = alias
                        end = base_offset + int(mem.disp or 0) + int(getattr(dst, "size", 0) or 0)
                        if alloc_size > 0 and end > alloc_size:
                            if global_vars.DEBUG:
                                print(
                                    f"Inlined alloca overflow candidate in {func.name} at {hex(ins.address)}: "
                                    f"write_end={end}, allocation={alloc_size}"
                                )
                            overflow_writes.add(ins.address)

                if ins.mnemonic in ("div", "idiv") and len(ops) == 1 and ops[0].type == X86_OP_REG:
                    divisor = constants.get(self.__canonical_ins_register(ins, ops[0].reg))
                    dividend = constants.get("rax")
                    if divisor not in (None, 0) and dividend is not None:
                        constants["rax"], constants["rdx"] = divmod(dividend, divisor)
                    else:
                        constants.pop("rax", None)
                        constants.pop("rdx", None)
                    continue
                if len(ops) < 2:
                    continue
                src = ops[1]
                if dst.type == X86_OP_REG:
                    dst_reg = self.__canonical_ins_register(ins, dst.reg)
                    if ins.mnemonic == "lea" and src.type == X86_OP_MEM:
                        mem = src.value.mem
                        base = self.__canonical_ins_register(ins, mem.base)
                        index = self.__canonical_ins_register(ins, mem.index)
                        source_alias = aliases.get(base) or aliases.get(index)
                        if source_alias is not None:
                            size, offset, logical_size = source_alias
                            aliases[dst_reg] = (size, offset + int(mem.disp or 0), logical_size)
                        else:
                            aliases.pop(dst_reg, None)
                        constants.pop(dst_reg, None)
                    elif ins.mnemonic in ("mov", "movabs", "movsxd"):
                        if src.type == X86_OP_IMM:
                            constants[dst_reg] = int(src.imm)
                            aliases.pop(dst_reg, None)
                        elif src.type == X86_OP_REG:
                            src_reg = self.__canonical_ins_register(ins, src.reg)
                            if src_reg in constants:
                                constants[dst_reg] = constants[src_reg]
                            else:
                                constants.pop(dst_reg, None)
                            if src_reg == "rsp" and current_alloc_size is not None:
                                logical_size = current_alloc_size
                                if requested_alloc_size is not None:
                                    logical_size = min(requested_alloc_size, current_alloc_size)
                                aliases[dst_reg] = (current_alloc_size, 0, logical_size)
                            elif src_reg in aliases:
                                aliases[dst_reg] = aliases[src_reg]
                            else:
                                aliases.pop(dst_reg, None)
                        elif src.type == X86_OP_MEM:
                            mem = src.value.mem
                            if self.__canonical_ins_register(ins, mem.base) == "rbp" and mem.index == 0:
                                alias = local_aliases.get(int(mem.disp))
                                if alias is not None:
                                    aliases[dst_reg] = alias
                                else:
                                    aliases.pop(dst_reg, None)
                            else:
                                aliases.pop(dst_reg, None)
                            constants.pop(dst_reg, None)
                    elif ins.mnemonic in ("add", "sub") and src.type == X86_OP_IMM:
                        delta = int(src.imm) * (1 if ins.mnemonic == "add" else -1)
                        if dst_reg == "rax" and constants.get("rax") == 15 and delta > 8:
                            # GCC -O0 alloca(n): mov eax,0x10; sub rax,1; add rax,n+8
                            requested_alloc_size = delta - 8
                        if dst_reg in constants:
                            constants[dst_reg] += delta
                        if dst_reg in aliases:
                            size, offset, logical_size = aliases[dst_reg]
                            aliases[dst_reg] = (size, offset + delta, logical_size)
                    elif ins.mnemonic == "add" and src.type == X86_OP_REG:
                        src_reg = self.__canonical_ins_register(ins, src.reg)
                        if dst_reg not in aliases and src_reg in aliases:
                            aliases[dst_reg] = aliases[src_reg]
                        constants.pop(dst_reg, None)
                    elif ins.mnemonic == "and" and src.type == X86_OP_IMM and dst_reg in constants:
                        constants[dst_reg] &= int(src.imm)
                    elif ins.mnemonic in ("shr", "shl") and src.type == X86_OP_IMM:
                        if dst_reg in constants:
                            shift = int(src.imm)
                            constants[dst_reg] = constants[dst_reg] >> shift if ins.mnemonic == "shr" else constants[dst_reg] << shift
                        if dst_reg in aliases:
                            size, _, logical_size = aliases[dst_reg]
                            aliases[dst_reg] = (size, 0, logical_size)
                    elif ins.mnemonic == "imul" and len(ops) == 3 and ops[1].type == X86_OP_REG and ops[2].type == X86_OP_IMM:
                        source = constants.get(self.__canonical_ins_register(ins, ops[1].reg))
                        if source is not None:
                            constants[dst_reg] = source * int(ops[2].imm)
                    elif ins.mnemonic == "sub" and dst_reg == "rsp":
                        size = constants.get(self.__canonical_ins_register(ins, src.reg)) if src.type == X86_OP_REG else int(src.imm) if src.type == X86_OP_IMM else None
                        if size is not None and 0 < size < 0x1000:
                            current_alloc_size = size
                elif dst.type == X86_OP_MEM and src.type == X86_OP_REG:
                    mem = dst.value.mem
                    if self.__canonical_ins_register(ins, mem.base) == "rbp" and mem.index == 0:
                        src_reg = self.__canonical_ins_register(ins, src.reg)
                        if src_reg in aliases:
                            local_aliases[int(mem.disp)] = aliases[src_reg]
                            _, offset, logical_size = aliases[src_reg]
                            self._alloca_pointer_stores[ins.address] = (logical_size, offset)
        return overflow_writes

    def __indexed_write_frame(self, frame, write_op, register_constants, register_bounds):
        # buffer[i] = v where buffer is a known local array: an index proven to
        # land outside it is an overflow, modelled like a proven libc overflow.
        buffer_size = frame.get_buffer(abs(write_op.address))
        element_size = write_op.data_size.value

        def outside_buffer(index):
            return buffer_size is not None and (index < 0 or index * write_op.scale + element_size > buffer_size)

        index_value = register_constants.get(write_op.index_register)
        if index_value is not None and 2**31 <= index_value < 2**32:
            # int index sign-extended by cdqe, e.g. data = -1
            index_value -= 2**32
        if index_value is not None and index_value >= 0:
            if outside_buffer(index_value):
                return frame.write_multiple_bytes(range(frame.get_stack_size()))
            offset = write_op.address + (index_value * write_op.scale)
            if abs(offset) <= frame.get_stack_size() + 1024:
                return frame.write(offset, write_op.data_size.value)

        index_bounds = register_bounds.get(write_op.index_register)
        if index_bounds is not None:
            index_bounds = tuple(
                bound - 2**32 if bound is not None and 2**31 <= bound < 2**32 else bound
                for bound in index_bounds
            )
            low, high = index_bounds
            if buffer_size is not None and low is not None and low >= 0 and (high is None or outside_buffer(high)):
                # e.g. `if (data >= 0) buffer[data] = 1;` with data from input
                return frame.write_multiple_bytes(range(frame.get_stack_size()))
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

    def __pointer_write_state(self, ins, transition, current_state, pointer_facts, register_constants):
        """Apply `mov [reg+disp], src` when reg is known to point into a stack frame.

        The frame may belong to a caller (a sink writing through its pointer
        argument).  Same policy as the static libc model: a store that stays
        inside the pointed-to buffer cannot violate a stack property and is not
        modelled; a store proven to leave it marks the whole frame written.
        """
        write_op = transition.type
        target = pointer_facts.get(_REGISTER_64.get(write_op.base_register))
        if target is None:
            return current_state
        frame_name, pointer_offset, alloca_size = target
        if not current_state.contains_stack_frame(frame_name):
            return current_state
        index_value = 0
        if write_op.index_register is not None:
            index_value = register_constants.get(write_op.index_register)
            if index_value is None:
                return current_state
            if 2**63 <= index_value < 2**64:
                index_value -= 2**64
        start = pointer_offset + write_op.displacement + index_value * write_op.scale
        end = start + write_op.data_size
        frame = current_state.get_stack_frame(frame_name)
        buffer = (0, alloca_size) if alloca_size is not None else self.__pointer_target_buffer(frame_name, frame, pointer_offset)
        if buffer is not None:
            buffer_start, buffer_size = buffer
            if buffer_start <= start and end <= buffer_start + buffer_size:
                return current_state
        elif end <= 0:
            # No known buffer: only a store reaching the saved rbp or return
            # address is a proven overflow.
            return current_state
        if global_vars.DEBUG:
            base = "alloca" if alloca_size is not None else "rbp"
            print(
                f"Pointer store at {hex(ins.address)} writes {frame_name}[{base}{start:+#x}..{base}{end:+#x}) "
                f"outside buffer {buffer}; using full-frame write."
            )
        new_frame = frame.write_multiple_bytes(range(frame.get_stack_size()))
        if (new_frame.stack_frame == frame.stack_frame).all():
            return current_state
        next_state = current_state.add_stack_frame(frame_name, new_frame)
        next_state = next_state.add_instruction(ins)
        self.state_space.add_state(next_state)
        self.state_space.add_transition(current_state, next_state, transition)
        return next_state

    def __pointer_target_buffer(self, frame_name, frame, pointer_offset):
        """(rbp offset, size) of the buffer a stack pointer points into, if known."""
        for offset, size in self._dwarf_buffers.get(frame_name, ()):
            start = -abs(int(offset))
            if start <= pointer_offset < start + int(size):
                return start, int(size)
        if pointer_offset >= 0:
            return None
        # Buffers mapped from `lea` have no DWARF size: bound them by the
        # nearest mapped local above, like the static libc model does.
        key = abs(pointer_offset)
        size = frame.get_buffer(key)
        if size is None:
            return None
        upper_neighbors = [bid for bid in frame.get_buffer_ids() if isinstance(bid, int) and bid < key]
        if upper_neighbors:
            size = min(size, key - max(upper_neighbors))
        return pointer_offset, size

    def __pointer_call_destinations(self, function_name, current_state, pointer_facts):
        """Argument registers that point into another function's frame buffer.

        Returns {register: (frame name, frame, rbp offset, bytes left in buffer)}
        for the static libc model, which otherwise only sees the current frame.
        The offset is None for a dynamic allocation.
        """
        destinations = {}
        for reg in _ARGUMENT_REGISTERS:
            target = pointer_facts.get(reg)
            if target is None or target[0] == function_name:
                continue
            frame_name, pointer_offset, alloca_size = target
            if not current_state.contains_stack_frame(frame_name):
                continue
            frame = current_state.get_stack_frame(frame_name)
            if alloca_size is not None:
                if 0 <= pointer_offset < alloca_size:
                    destinations[reg] = (frame_name, frame, None, alloca_size - pointer_offset)
                continue
            buffer = self.__pointer_target_buffer(frame_name, frame, pointer_offset)
            if buffer is None:
                continue
            buffer_start, buffer_size = buffer
            destinations[reg] = (frame_name, frame, pointer_offset, buffer_start + buffer_size - pointer_offset)
        return destinations

    def __pointer_slot_key(self, ins, function_name, mem, pointer_facts):
        """Key of a memory operand that can hold a pointer fact: an rbp slot,
        a slot reached through a pointer to it (`*dataPtr = data`), or a global."""
        if mem.index != 0 or mem.segment != 0:
            return None
        base = ins.reg_name(mem.base) if mem.base != 0 else None
        base = _REGISTER_64.get(base, base)
        if base == "rbp":
            return ("slot", function_name, mem.disp)
        if base == "rip":
            return ("global", ins.address + ins.size + mem.disp)
        target = pointer_facts.get(base)
        if target is not None and target[2] is None:
            return ("slot", target[0], target[1] + mem.disp)
        return None

    def __track_pointer_facts(self, ins, function_name, pointer_facts):
        """Follow stack addresses through registers, rbp slots and globals.

        `lea reg, [rbp-x]` creates a fact; mov/lea/add/sub propagate it; any
        other write to the register or memory location kills it.  Facts about
        argument registers survive a call into the callee (see
        __pointer_facts_for_successor), which is how a sink learns that its
        parameter points into the caller's frame.
        """
        mnemonic = ins.mnemonic
        ops = ins.operands
        if mnemonic == "call" or mnemonic.startswith("j") or mnemonic in ("push", "cmp", "test", "nop", "endbr64", "leave", "ret"):
            return
        if mnemonic in ("cdqe", "cltq", "cqo", "cdq", "cwd") or (mnemonic in ("mul", "div", "idiv") or (mnemonic == "imul" and len(ops) == 1)):
            pointer_facts.pop("rax", None)
            pointer_facts.pop("rdx", None)
            return
        if mnemonic.startswith("rep") or mnemonic in ("movsb", "movsw", "movsq", "stosb", "stosw", "stosd", "stosq"):
            for reg in ("rdi", "rsi", "rcx"):
                pointer_facts.pop(reg, None)
        if not ops:
            return
        dst = ops[0]
        if dst.type == X86_OP_MEM:
            key = self.__pointer_slot_key(ins, function_name, dst.value.mem, pointer_facts)
            if key is None:
                return
            target = None
            if mnemonic == "mov" and len(ops) == 2 and ops[1].type == X86_OP_REG and dst.size == 8:
                target = pointer_facts.get(_REGISTER_64.get(ins.reg_name(ops[1].reg)))
                alloca_store = self._alloca_pointer_stores.get(ins.address)
                if target is None and alloca_store is not None:
                    # data = alloca(n), recovered by the per-function pre-pass.
                    alloca_size, offset = alloca_store
                    target = (function_name, offset, alloca_size)
            if target is not None:
                pointer_facts[key] = target
            else:
                pointer_facts.pop(key, None)
            return
        if dst.type != X86_OP_REG:
            return
        dst_reg = _REGISTER_64.get(ins.reg_name(dst.reg))
        if dst_reg is None:
            return
        src = ops[1] if len(ops) == 2 else None
        target = None
        if mnemonic == "lea" and src is not None and src.type == X86_OP_MEM and dst.size == 8:
            mem = src.value.mem
            base = _REGISTER_64.get(ins.reg_name(mem.base)) if mem.base != 0 else None
            if mem.index == 0 and base == "rbp":
                target = (function_name, mem.disp, None)
            elif mem.index == 0 and base in pointer_facts:
                frame_name, offset, alloca_size = pointer_facts[base]
                target = (frame_name, offset + mem.disp, alloca_size)
        elif mnemonic == "mov" and src is not None and dst.size == 8:
            if src.type == X86_OP_REG:
                target = pointer_facts.get(_REGISTER_64.get(ins.reg_name(src.reg)))
            elif src.type == X86_OP_MEM:
                key = self.__pointer_slot_key(ins, function_name, src.value.mem, pointer_facts)
                target = pointer_facts.get(key) if key is not None else None
        elif mnemonic in ("add", "sub") and src is not None and src.type == X86_OP_IMM and dst.size == 8 and dst_reg in pointer_facts:
            frame_name, offset, alloca_size = pointer_facts[dst_reg]
            delta = int(src.imm) if mnemonic == "add" else -int(src.imm)
            target = (frame_name, offset + delta, alloca_size)
        elif mnemonic == "xchg" and src is not None and src.type == X86_OP_REG:
            src_reg = _REGISTER_64.get(ins.reg_name(src.reg))
            src_target = pointer_facts.pop(src_reg, None)
            if dst.size == 8:
                target = src_target
                if dst_reg in pointer_facts:
                    pointer_facts[src_reg] = pointer_facts[dst_reg]
        if dst_reg in ("rbp", "rsp"):
            return
        if target is not None:
            pointer_facts[dst_reg] = target
        else:
            pointer_facts.pop(dst_reg, None)

    def __pointer_facts_for_successor(self, node, successor, pointer_facts):
        succ_pointers = pointer_facts.copy()
        insns = node.block.capstone.insns if not node.is_simprocedure and node.block is not None else []
        # Entering the callee keeps the argument registers; returning to the
        # fall-through clobbers the caller-saved ones.
        if insns and insns[-1].mnemonic == "call" and successor.addr == node.addr + node.size:
            for reg in _CALLER_SAVED_REGISTERS:
                succ_pointers.pop(reg, None)
        return succ_pointers

    def __track_simple_facts(self, ins, local_constants, register_constants, local_bounds, register_bounds):
        if ins.mnemonic == "call":
            for reg in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                slot = register_constants.pop("&" + reg, None)
                if slot is not None:
                    local_constants.pop(slot, None)
                    local_bounds.pop(slot, None)
        elif ins.operands and ins.operands[0].type == X86_OP_REG:
            dst_name = ins.reg_name(ins.operands[0].reg)
            register_constants.pop("&" + dst_name, None)
            if (
                ins.mnemonic == "lea"
                and len(ins.operands) == 2
                and ins.operands[1].type == X86_OP_MEM
                and ins.reg_name(ins.operands[1].mem.base) == "rbp"
            ):
                # Remember which register holds the address of which local.
                register_constants["&" + dst_name] = ins.operands[1].mem.disp
            elif ins.mnemonic == "mov" and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM:
                mem = ins.operands[1].mem
                if ins.reg_name(mem.base) == "rbp" and mem.index == 0 and ("&", mem.disp) in local_constants:
                    # int *dataPtr = &data; ... reload of dataPtr
                    register_constants["&" + dst_name] = local_constants[("&", mem.disp)]
                elif mem.index == 0 and mem.disp == 0 and "&" + ins.reg_name(mem.base) in register_constants:
                    # data = *dataPtr: load the local the pointer refers to
                    slot = register_constants["&" + ins.reg_name(mem.base)]
                    for facts, source in ((register_constants, local_constants), (register_bounds, local_bounds)):
                        if slot in source:
                            facts[dst_name] = source[slot]
                        else:
                            facts.pop(dst_name, None)
                    if dst_name == "eax":
                        for facts in (register_constants, register_bounds):
                            if "eax" in facts:
                                facts["rax"] = facts["eax"]
                            else:
                                facts.pop("rax", None)
                    return
        elif (
            ins.mnemonic == "mov"
            and len(ins.operands) == 2
            and ins.operands[0].type == X86_OP_MEM
            and ins.operands[1].type == X86_OP_REG
        ):
            mem = ins.operands[0].mem
            src_name = ins.reg_name(ins.operands[1].reg)
            if ins.reg_name(mem.base) == "rbp" and mem.index == 0:
                # dataPtr = &data stored in a local
                if "&" + src_name in register_constants:
                    local_constants[("&", mem.disp)] = register_constants["&" + src_name]
                else:
                    local_constants.pop(("&", mem.disp), None)
            elif mem.index == 0 and mem.disp == 0 and "&" + ins.reg_name(mem.base) in register_constants:
                # *dataPtr = data: the store lands in the referenced local
                slot = register_constants["&" + ins.reg_name(mem.base)]
                for facts, source in ((local_constants, register_constants), (local_bounds, register_bounds)):
                    if src_name in source:
                        facts[slot] = source[src_name]
                    else:
                        facts.pop(slot, None)
                return
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
            # cmp/test only read their operands
            if ins.mnemonic in ("cmp", "test"):
                return
            if ins.operands[0].type == X86_OP_REG:
                dst_reg = ins.reg_name(ins.operands[0].reg)
                register_constants.pop(dst_reg, None)
                register_bounds.pop(dst_reg, None)
            elif ins.operands[0].type == X86_OP_MEM and ins.reg_name(ins.operands[0].mem.base) == "rbp":
                # e.g. the loop increment `add DWORD PTR [rbp-0x4], 0x1`
                slot = ins.operands[0].mem.disp
                local_constants.pop(slot, None)
                local_bounds.pop(slot, None)
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

    def __track_constant_facts(self, ins, register_constants):
        """
        Constants the simple tracker misses: loads of globals that nothing in
        the binary writes (`if (globalFalse)`, `if (GLOBAL_CONST_FIVE == 5)`),
        and calls to helpers that only return a constant (`staticReturnsFalse()`).
        """
        if ins.mnemonic == "call":
            target = ins.operands[0].imm if ins.operands and ins.operands[0].type == X86_OP_IMM else None
            value = self.__constant_return_value(target) if target is not None else None
            if value is not None:
                register_constants["eax"] = register_constants["rax"] = value
            return
        if ins.mnemonic not in ("mov", "movsxd") or len(ins.operands) != 2:
            return
        dst, src = ins.operands
        if dst.type != X86_OP_REG or src.type != X86_OP_MEM:
            return
        if ins.reg_name(src.mem.base) != "rip" or src.mem.index != 0:
            return
        address = ins.address + ins.size + src.mem.disp
        if address in self.__globals_written():
            return
        try:
            data = self.project.loader.memory.load(address, src.size)
        except Exception:
            return
        value = int.from_bytes(data, "little", signed=True)
        dst_reg = ins.reg_name(dst.reg)
        register_constants[dst_reg] = value
        if dst_reg == "eax":
            register_constants["rax"] = value

    def __globals_written(self):
        """Addresses of globals stored to anywhere in the user code (computed once)."""
        if self._written_globals is not None:
            return self._written_globals
        written = set()
        for func in self.user_functions:
            for block_addr in func.block_addrs:
                try:
                    insns = self.project.factory.block(block_addr).capstone.insns
                except Exception:
                    continue
                for ins in insns:
                    if ins.operands and ins.operands[0].type == X86_OP_MEM and ins.reg_name(ins.operands[0].mem.base) == "rip":
                        start = ins.address + ins.size + ins.operands[0].mem.disp
                        written.update(range(start, start + max(1, ins.operands[0].size)))
        self._written_globals = written
        return written

    def __constant_return_value(self, function_addr):
        """`int staticReturnsFalse() { return 0; }`: the constant, else None."""
        if function_addr in self._constant_return_cache:
            return self._constant_return_cache[function_addr]
        value = None
        func = self.cfg.kb.functions.function(addr=function_addr)
        if func is not None and len(func.block_addrs) == 1:
            try:
                insns = self.project.factory.block(function_addr).capstone.insns
            except Exception:
                insns = []
            if insns and insns[-1].mnemonic == "ret" and not any(ins.mnemonic == "call" for ins in insns):
                for ins in insns:
                    if len(ins.operands) == 2 and ins.operands[0].type == X86_OP_REG and ins.reg_name(ins.operands[0].reg) in ("eax", "rax"):
                        value = int(ins.operands[1].imm) if ins.mnemonic == "mov" and ins.operands[1].type == X86_OP_IMM else None
        self._constant_return_cache[function_addr] = value
        return value

    def __path_with_loop_bodies(self, path_addrs):
        """
        The DFS never revisits a block, so a path through a loop goes header ->
        exit and skips the body (e.g. the alloca inside `for (i = 0; i < 1; i++)`).
        Insert the body blocks of every loop the path passes through, after the
        loop's first block on the path, for the call-site analysis.
        """
        if path_addrs is None or not self.loops:
            return path_addrs
        on_path = set(path_addrs)
        insert_after = {}
        for loop in self.loops:
            body = sorted({body_node.addr for body_node in loop.body_nodes})
            missing = [addr for addr in body if addr not in on_path]
            present = [addr for addr in path_addrs if addr in set(body)]
            if missing and present:
                insert_after.setdefault(present[0], []).extend(missing)
        if not insert_after:
            return path_addrs
        expanded = []
        for addr in path_addrs:
            expanded.append(addr)
            expanded.extend(insert_after.get(addr, ()))
        return tuple(expanded)

    def __branch_infeasible(self, node, successor, local_constants, register_constants):
        """True when a known constant decides the block's conditional jump against this successor."""
        if node.is_simprocedure or node.block is None:
            return False
        # A loop condition is re-evaluated on every iteration; the DFS only
        # sees its first evaluation, so it must not prune the loop exit.
        if any(node.addr in {body_node.addr for body_node in loop.body_nodes} for loop in self.loops):
            return False
        insns = node.block.capstone.insns
        if len(insns) < 2 or not insns[-1].mnemonic.startswith("j") or insns[-1].mnemonic == "jmp":
            return False
        jump, test = insns[-1], insns[-2]
        if not jump.operands or jump.operands[0].type != X86_OP_IMM or len(test.operands) != 2:
            return False
        lhs, rhs = test.operands

        def value_of(operand):
            if operand.type == X86_OP_IMM:
                return int(operand.imm)
            if operand.type == X86_OP_REG:
                return register_constants.get(test.reg_name(operand.reg))
            if operand.type == X86_OP_MEM and test.reg_name(operand.mem.base) == "rbp" and operand.mem.index == 0:
                return local_constants.get(operand.mem.disp)
            return None

        left, right = value_of(lhs), value_of(rhs)
        if left is None or right is None:
            return False
        width = 8 * lhs.size
        mask = (1 << width) - 1

        def signed(value):
            value &= mask
            return value - (1 << width) if value >> (width - 1) else value

        if test.mnemonic == "test":
            result = left & right & mask
            taken = {
                "je": result == 0, "jz": result == 0, "jne": result != 0, "jnz": result != 0,
                "js": signed(result) < 0, "jns": signed(result) >= 0,
                "jg": signed(result) > 0, "jle": signed(result) <= 0,
            }.get(jump.mnemonic)
        elif test.mnemonic == "cmp":
            a, b = signed(left), signed(right)
            ua, ub = left & mask, right & mask
            taken = {
                "je": a == b, "jz": a == b, "jne": a != b, "jnz": a != b,
                "jg": a > b, "jge": a >= b, "jl": a < b, "jle": a <= b,
                "ja": ua > ub, "jae": ua >= ub, "jb": ua < ub, "jbe": ua <= ub,
                "js": signed(left - right) < 0, "jns": signed(left - right) >= 0,
            }.get(jump.mnemonic)
        else:
            return False
        if taken is None:
            return False
        target = jump.operands[0].imm
        if successor.addr == target:
            return not taken
        if successor.addr == node.addr + node.size:
            return taken
        return False

    def __clear_register_facts(self, register_constants, register_bounds, regs):
        for reg in regs:
            register_constants.pop(reg, None)
            register_bounds.pop(reg, None)

    def __pointer_assignment_key(self, path_addrs):
        """
        Which instruction last stored a pointer to a local (`lea reg,[rbp-x];
        mov [rbp-y],reg`) into each slot along this path, and which calls the
        path made.  Paths that point a local at different buffers or fill it
        differently then reach a merge point as distinct work items instead of
        being deduplicated.
        """
        last_store = {}
        for addr in path_addrs:
            for slot, ins_addr in self.__block_pointer_stores(addr):
                last_store[(self._block_func_map.get(addr), slot)] = ins_addr
        return tuple(sorted(last_store.items(), key=repr))

    def __block_pointer_stores(self, addr):
        cached = self._pointer_store_cache.get(addr)
        if cached is not None:
            return cached
        stores = []
        try:
            insns = self.project.factory.block(addr).capstone.insns
        except Exception:
            insns = []
        local_pointers = set()
        for ins in insns:
            if ins.mnemonic == "call":
                # Which library calls ran on the path (e.g. memset(data, 'A', 99)
                # in one branch, 49 in the other) also decides string lengths.
                stores.append(("call", ins.address))
                continue
            if len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if ins.mnemonic == "lea" and dst.type == X86_OP_REG:
                if src.type == X86_OP_MEM and ins.reg_name(src.mem.base) == "rbp":
                    local_pointers.add(ins.reg_name(dst.reg))
                else:
                    local_pointers.discard(ins.reg_name(dst.reg))
            elif dst.type == X86_OP_REG:
                local_pointers.discard(ins.reg_name(dst.reg))
            elif (
                ins.mnemonic == "mov"
                and dst.type == X86_OP_MEM
                and ins.reg_name(dst.mem.base) == "rbp"
                and src.type == X86_OP_REG
                and ins.reg_name(src.reg) in local_pointers
            ):
                stores.append((dst.mem.disp, ins.address))
        self._pointer_store_cache[addr] = stores
        return stores

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
        if len(cmp_ins.operands) != 2:
            return
        if cmp_ins.mnemonic == "test":
            # test reg, reg sets flags like cmp reg, 0
            lhs, rhs = cmp_ins.operands
            if lhs.type != X86_OP_REG or rhs.type != X86_OP_REG or lhs.reg != rhs.reg:
                return
            value = 0
        elif cmp_ins.mnemonic == "cmp" and cmp_ins.operands[1].type == X86_OP_IMM:
            value = int(cmp_ins.operands[1].imm)
        else:
            return

        key, bounds_map_name = self.__cmp_lvalue(cmp_ins)
        if key is None:
            return
        bounds_map = local_bounds if bounds_map_name == "local" else register_bounds
        # `mov eax, [rbp-8]; test eax, eax`: the bound also holds for the local,
        # which later blocks reload.
        loaded_slot = None
        if bounds_map_name == "register":
            for prior in reversed(insns[:-2]):
                if len(prior.operands) == 2 and prior.operands[0].type == X86_OP_REG and prior.reg_name(prior.operands[0].reg) == key:
                    src = prior.operands[1]
                    if prior.mnemonic == "mov" and src.type == X86_OP_MEM and prior.reg_name(src.mem.base) == "rbp" and src.mem.index == 0:
                        loaded_slot = src.mem.disp
                    break

        target = jump.operands[0].imm if jump.operands and jump.operands[0].type == X86_OP_IMM else None
        if target is None:
            return
        branch_taken = successor.addr == target
        fallthrough = successor.addr == node.addr + node.size
        if not branch_taken and not fallthrough:
            return

        current = bounds_map.get(key, (None, None))
        new_bounds = self.__bounds_after_jump(jump.mnemonic, value, branch_taken, current)
        if new_bounds is not None:
            bounds_map[key] = new_bounds
            if loaded_slot is not None:
                local_bounds[loaded_slot] = new_bounds

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
            stack_size = current_frame.get_stack_size()
            stack_pointer = pre_call_state.solver.eval(pre_call_state.regs.rsp)
            # Run the callee to its return and keep the bytes it wrote into
            # this frame (e.g. through a pointer argument or a global).
            with ConcolicExecutor.real_libc_procedures(self.project):
                written, _ = ConcolicExecutor.run_call_recording_writes(
                    self.project,
                    pre_call_state,
                    ins.address + ins.size,
                    stack_pointer,
                    stack_pointer + stack_size,
                )
            difs = sorted({self.convert_indice(address - stack_pointer, stack_size) for address in written})
        except (FailedConcolicExecution, ValueError) as exc:
            if global_vars.DEBUG:
                print(f"User-call summary failed at {hex(ins.address)}: {exc}")
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
        loop_project = self.project
        pre_loop_state = ConcolicExecutor.reaching_state(loop_project, loop_entry, start_addr=entry_addr)
        stack_pointer = pre_loop_state.regs.rsp
        concrete_sp = pre_loop_state.solver.eval(stack_pointer)
        observed_writes_by_instruction = {}

        def record_stack_write(write_state):
            try:
                address = write_state.solver.eval(write_state.inspect.mem_write_address)
                length_expr = write_state.inspect.mem_write_length
                length = write_state.solver.eval(length_expr) if length_expr is not None else 1
            except Exception:
                return
            instruction_writes = observed_writes_by_instruction.setdefault(write_state.addr, set())
            for byte_address in range(address, address + max(1, int(length))):
                instruction_writes.add(byte_address)

        pre_loop_state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            action=record_stack_write,
        )

        stack_memory_before = pre_loop_state.solver.eval(pre_loop_state.memory.load(stack_pointer, current_stack_frame.get_stack_size()), cast_to=bytes)

        simgr = loop_project.factory.simgr(pre_loop_state)
        pre_loop_state.globals["loop_iterations"] = 0
        # The iteration bound applies per path. The step cap only guards
        # against paths that never return to the loop entry.
        max_steps = (self.max_iter + 1) * max(1, len(loop.body_nodes)) * 4

        for _ in range(max_steps):
            simgr.step()

            if len(simgr.active) == 0:
                if simgr.stashes.get("bounded"):
                    break
                raise FailedLoopUnrolling("No active states left to execute. The loop may not have executed properly.")

            # Prune states to prevent exponential explosion when loop body
            # contains branches over unconstrained values (e.g. socket return codes).
            if len(simgr.active) > global_vars.CONCOLIC_ACTIVE_LIMIT:
                simgr.stashes["active"] = sorted(
                    simgr.active,
                    key=lambda s: abs(s.addr - exit_addr),
                )[:global_vars.CONCOLIC_ACTIVE_LIMIT]

            for active_state in simgr.active:
                if active_state.addr == loop_entry:
                    active_state.globals["loop_iterations"] = active_state.globals.get("loop_iterations", 0) + 1
            simgr.move("active", "bounded", lambda s: s.globals.get("loop_iterations", 0) > self.max_iter)

            # Check if any state has reached the loop exit
            if any(active_state.addr == exit_addr for active_state in simgr.active):
                break

        post_loop_state = next((s for s in simgr.active if s.addr == exit_addr), None)

        if post_loop_state is None:
            print(f"Could not find target address {hex(exit_addr)} after executing loop at {hex(entry_addr)}\nSkipping loop emulation\nMaybe try to increase the maximum number of iterations with the --max-iterations flag. (default is 128)\n")
            return function_name, []

        stack_memory_after = post_loop_state.solver.eval(post_loop_state.memory.load(stack_pointer, current_stack_frame.get_stack_size()), cast_to=bytes)

        # Loop vulnerability classification is based on the explicit
        # dynamic-allocation and DWARF-buffer boundary proofs below.  Raw byte
        # differences are not projected into the abstract frame: a CFG node can
        # be revisited with a partially constructed frame, and ordinary locals
        # near rbp (especially the loop counter) can then be mistaken for saved
        # frame metadata.  The observed addresses still preserve zero-to-zero
        # writes and are used by both precise boundary checks.
        difs = []
        frame_limit = concrete_sp + current_stack_frame.get_stack_size()
        for instruction_addr, allocation_size in self._dynamic_write_allocations.items():
            writes = {
                address for address in observed_writes_by_instruction.get(instruction_addr, ())
                if concrete_sp <= address < frame_limit
            }
            if writes and max(writes) - min(writes) + 1 > allocation_size:
                if global_vars.DEBUG:
                    print(
                        f"Proven loop overflow of dynamic allocation size={allocation_size} "
                        f"at {hex(instruction_addr)}."
                    )
                difs = list(range(current_stack_frame.get_stack_size()))
                break
        concrete_rbp = pre_loop_state.solver.eval(pre_loop_state.regs.rbp)
        for writes in observed_writes_by_instruction.values():
            if not writes:
                continue
            write_min, write_max = min(writes), max(writes)
            if write_max - write_min + 1 != len(writes):
                continue
            for offset, size in self._dwarf_buffers.get(function_name, ()):
                if len(writes) != int(size):
                    continue
                bias = write_min - (concrete_rbp + int(offset))
                if abs(bias) <= 32:
                    self._dwarf_runtime_bias[function_name] = bias
                    break
        dwarf_bias = self._dwarf_runtime_bias.get(function_name, 0)
        for offset, size in self._dwarf_buffers.get(function_name, ()):
            start = concrete_rbp + int(offset) + dwarf_bias
            end = start + int(size)
            boundary_width = min(8, int(size))
            crosses_upper_boundary = any(
                all(address in writes for address in range(end - boundary_width, end + boundary_width))
                for writes in observed_writes_by_instruction.values()
            )
            crosses_lower_boundary = any(
                all(address in writes for address in range(start - boundary_width, start + boundary_width))
                for writes in observed_writes_by_instruction.values()
            )
            if crosses_upper_boundary or crosses_lower_boundary:
                if global_vars.DEBUG:
                    crossing = [
                        (hex(ins_addr), min(writes), max(writes), len(writes))
                        for ins_addr, writes in observed_writes_by_instruction.items()
                        if (
                            all(address in writes for address in range(end - boundary_width, end + boundary_width))
                            or all(address in writes for address in range(start - boundary_width, start + boundary_width))
                        )
                    ]
                    print(
                        f"Proven loop overflow of DWARF buffer offset={offset} size={size}; "
                        f"buffer_range=({start},{end}); crossing={crossing}; "
                        "marking the stack-overflow state."
                    )
                difs = list(range(current_stack_frame.get_stack_size()))
                break
        if global_vars.DEBUG:
            print(
                f"Loop stack differences: count={len(difs)} "
                f"range={((min(difs), max(difs)) if difs else None)} "
                f"buffers={current_stack_frame.buffer_map} "
                f"write_ranges={[(hex(addr), min(w), max(w), len(w)) for addr, w in observed_writes_by_instruction.items() if w]}"
            )
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
        if ins.operands and ins.operands[0].type == X86_OP_IMM:
            call_addr = ins.operands[0].imm
        else:
            # Indirect call (function pointer): use the target CFG recovery resolved.
            call_addr = self.__resolved_indirect_call_target(ins)
            if call_addr is None:
                return None
        func = self.cfg.kb.functions.function(addr=call_addr)
        return func.name if func is not None else None

    def __resolved_indirect_call_target(self, ins):
        try:
            node = self.cfg.model.get_any_node(ins.address, anyaddr=True)
            successors = self.cfg.model.get_successors_and_jumpkinds(node, excluding_fakeret=True)
        except Exception:
            return None
        targets = {succ.addr for succ, jumpkind in successors if jumpkind == "Ijk_Call"}
        targets = {
            addr for addr in targets
            if (target := self.cfg.kb.functions.function(addr=addr)) is not None
            and target.name != "UnresolvableCallTarget"
        }
        if len(targets) == 1:
            return targets.pop()
        return self.__static_function_pointer(ins, node)

    def __static_function_pointer(self, ins, node):
        """Follow `lea reg, [rip+f]` through registers and rbp slots up to `call reg`."""
        if not ins.operands or ins.operands[0].type != X86_OP_REG:
            return None
        try:
            func = self.cfg.kb.functions.function(addr=node.function_address)
        except Exception:
            return None
        if func is None:
            return None
        registers, slots = {}, {}
        for block_addr in sorted(func.block_addrs):
            if block_addr > ins.address:
                continue
            for prior in self.project.factory.block(block_addr).capstone.insns:
                if prior.address >= ins.address:
                    break
                if len(prior.operands) != 2 or prior.mnemonic not in ("mov", "lea"):
                    continue
                dst, src = prior.operands
                if dst.type == X86_OP_REG:
                    dst_name = prior.reg_name(dst.reg)
                    value = None
                    if prior.mnemonic == "lea" and src.type == X86_OP_MEM and prior.reg_name(src.mem.base) == "rip":
                        value = prior.address + prior.size + src.mem.disp
                    elif prior.mnemonic == "mov" and src.type == X86_OP_REG:
                        value = registers.get(prior.reg_name(src.reg))
                    elif prior.mnemonic == "mov" and src.type == X86_OP_MEM and prior.reg_name(src.mem.base) == "rbp":
                        value = slots.get(src.mem.disp)
                    registers[dst_name] = value
                elif dst.type == X86_OP_MEM and prior.mnemonic == "mov" and prior.reg_name(dst.mem.base) == "rbp":
                    slots[dst.mem.disp] = registers.get(prior.reg_name(src.reg)) if src.type == X86_OP_REG else None
        target = registers.get(ins.reg_name(ins.operands[0].reg))
        if target is not None and self.cfg.kb.functions.function(addr=target) is not None:
            return target
        return None

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

        # CFGFast may attach a function return to every compatible call site in
        # the binary.  The caller's fall-through is already explored from its
        # call block below, so following these synthetic return edges leaks a
        # testcase entry into unrelated Juliet support functions (and was the
        # direct cause of the CWE-135 timeout cluster).
        if node.block is not None:
            insns = node.block.capstone.insns
            if insns and insns[-1].mnemonic.startswith("ret"):
                return []

        # CFGFast does not record call-return edges for PLT calls — the block
        # ending with `call plt_stub` only lists the PLT entry as successor, but
        # the block that continues AFTER the call (at node.addr + node.size) is
        # left with no predecessor and is never visited.  Recover it here by
        # adding the fall-through block — but only if it belongs to the current
        # function (prevents bleeding into adjacent functions in memory).
        block_insns = node.block.capstone.insns if node.block is not None else []
        # Only a call returns to the next block; a jmp-terminated block has no
        # fall-through edge, and adding one creates infeasible paths that run
        # both arms of an if/else.
        if block_insns and block_insns[-1].mnemonic == "call":
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

        # Function-pointer calls: CFGFast often leaves only its
        # UnresolvableCallTarget placeholder; follow the target resolved by
        # __determine_function_name instead so the callee body is explored.
        if not node.is_simprocedure and node.block is not None:
            insns = node.block.capstone.insns
            if insns and insns[-1].mnemonic == "call" and insns[-1].operands and insns[-1].operands[0].type != X86_OP_IMM:
                target = self.__resolved_indirect_call_target(insns[-1])
                target_node = model.get_any_node(target) if target is not None else None
                if target_node is not None:
                    succs = [
                        succ for succ in succs
                        if (func := self.cfg.kb.functions.function(addr=succ.addr)) is None
                        or func.name != "UnresolvableCallTarget"
                    ]
                    if target_node not in succs:
                        succs.append(target_node)

        return succs
