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
                self.__apply_dwarf_buffers(new_stack_frame, function_name)
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

    def __transition_state(self, ins, function_name, node, current_state: MemoryState, local_constants=None, register_constants=None, register_bounds=None) -> MemoryState:
        local_constants = local_constants or {}
        register_constants = register_constants or {}
        register_bounds = register_bounds or {}
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
                            if call.function_name == "gets":
                                next_state = current_state.add_instruction(ins)
                            else:
                                return current_state
                        else:
                            old_frame = current_state.get_stack_frame(function_name)
                            new_frame = old_frame.write_multiple_bytes(stack_changes)
                            next_state = current_state.add_stack_frame(function_name, new_frame)
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
                        alloc_size, base_offset = alias
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
                            size, offset = source_alias
                            aliases[dst_reg] = (size, offset + int(mem.disp or 0))
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
                                aliases[dst_reg] = (current_alloc_size, 0)
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
                        if dst_reg in constants:
                            constants[dst_reg] += delta
                        if dst_reg in aliases:
                            size, offset = aliases[dst_reg]
                            aliases[dst_reg] = (size, offset + delta)
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
                            size, _ = aliases[dst_reg]
                            aliases[dst_reg] = (size, 0)
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
        return overflow_writes

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

        iteration_count = 0

        simgr = loop_project.factory.simgr(pre_loop_state)

        while iteration_count < self.max_iter:
            simgr.step()

            if len(simgr.active) == 0:
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
