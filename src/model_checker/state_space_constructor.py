import angr
import claripy
import os

from src.global_vars import CLIB_FUNCTIONS, GLOBAL_HOOKS, NO_EXECUTE_FUNCTIONS
from src.binary_data_extractor.core import BinaryDataExtractor
from src.exceptions import FailedLoopUnrolling, FailedConcolicExecution
from .models.memory_state import MemoryState
from .models.state_space import StateSpace
from .models.stack_frame import StackFrame
from .models.memory_transitions import MemoryTransition, OperationType, CanarySetup
from .models.call_emulator import CallEmulator

class StateSpaceConstructor:
    
    def __init__(self, binary_data: BinaryDataExtractor, binary_name, current_dir, binary_path, max_iter) -> None:
        
        self.project = binary_data.project
        self.cfg = binary_data.cfg
        self.user_functions = binary_data.functions
        self.loops = binary_data.loops
        self.state_space = StateSpace(current_dir, binary_name)
        self.max_iter = max_iter
        self.binary_path = binary_path
        
    def construct_state_space(self):
        """
        Constructs the state space of the binary.
        """
        # Build initial state
        entry_point = self.project.loader.main_object.get_symbol("main")
        node = self.cfg.get_any_node(entry_point.rebased_addr)
        entry_instruction = node.block.capstone.insns[0]
        initial_state = MemoryState(instruction=entry_instruction)
        
        # Stack to maintain paths and their respective states
        stack = [([node], initial_state)]  # Each element is a tuple (path, state)

        while stack:
            path, current_state = stack.pop()
            current_node = path[-1]

            current_state = self.__process_node(current_node, current_state)

            if self.__is_in_loop(current_node) and self.max_iter > 0:
                current_state = self.__process_loop(current_node, current_state)

            # Get successors
            successors = self.cfg.get_successors(current_node)
            for successor in successors:
                if successor not in path:
                    new_path = path + [successor]
                    stack.append((new_path, current_state))
        
    def __process_node(self, node, current_state) -> MemoryState:
        if not node.is_simprocedure and node.name is not None:
            function_name = node.name.split("+")[0]
            if not current_state.contains_stack_frame("main"):
                new_stack_frame = StackFrame()
                new_stack_frame.initialize()
                current_state = current_state.add_stack_frame("main", new_stack_frame)
                self.state_space.add_state(current_state)
            for ins in node.block.capstone.insns:
                if not current_state.contains_stack_frame(function_name) and ins.mnemonic == "endbr64":
                    new_stack_frame = StackFrame()
                    new_stack_frame.initialize()
                    next_state = current_state.add_stack_frame(function_name, new_stack_frame)
                    self.state_space.add_state(next_state)
                    self.state_space.add_transition(current_state, next_state, MemoryTransition(node.block.capstone.insns[0], self.cfg, fname=function_name))
                    current_state = next_state
                elif ins.mnemonic != "endbr64":
                    current_state = self.__transition_state(ins, function_name, node, current_state)
        return current_state
    
    def __process_loop(self, node, current_state) -> MemoryState:
        print("Loop detected.\nPerforming loop emulation...")
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
                for addr in GLOBAL_HOOKS:
                    self.project.hook(addr, lambda _: None, length=4)
        except FailedLoopUnrolling:
            print("Failed to unroll loop. Skipping loop emulation.")
            return current_state
        if len(difs) > 0:
            old_frame = current_state.get_stack_frame(fname)
            new_frame = old_frame.write_multiple_bytes(difs)
            next_state = current_state.add_stack_frame(fname, new_frame)
            jump_ins = self.cfg.get_any_node(node.addr).block.capstone.insns[-1]
            next_state = next_state.add_instruction(jump_ins)
            self.state_space.add_state(next_state)
            self.state_space.add_transition(current_state, next_state, MemoryTransition(jump_ins, self.cfg))
            return next_state
        return current_state
        
    def __transition_state(self, ins, function_name, node, current_state: MemoryState) -> MemoryState:        
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
                            address = transition.type.address    
                            new_frame = current_state.get_stack_frame(function_name).write(address, transition.type.data_size.value)
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
                        new_frame = StackFrame()
                        new_frame.initialize()
                        next_state = current_state.add_stack_frame(call_name, new_frame)
                        next_state = next_state.add_instruction(ins)
                    elif call_name in NO_EXECUTE_FUNCTIONS:
                        return current_state
                    else:
                        print(f"Unknown function call: {call_name}, skipping...")
                        return current_state
                case _:
                    return current_state
            self.state_space.add_state(next_state)
            self.state_space.add_transition(current_state, next_state, transition)
            return next_state
        return current_state
        
    def __loop_emulator(self, node, state, max_iterations=20) -> (str, list[int]):
        function_name = node.name.split("+")[0]
        

        loop = next(filter(lambda l: l.continue_edges[0][0].addr == node.addr, self.loops), None)
        assert loop is not None, f"Loop not found for node {node.addr}"
        
        entry_addr = node.function_address
        loop_entry = loop.continue_edges[0][0].addr
        try:
            exit_addr = loop.break_edges[0][-1].addr
        except IndexError:
            raise FailedConcolicExecution(f"Could not find target address {hex(loop_entry)} after executing loop at {hex(entry_addr)}")

        current_stack_frame = state.get_stack_frame(function_name)

        main_addr = self.project.loader.main_object.get_symbol("main")
        entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        
        simgr = self.project.factory.simgr(entry_state)

        # Explore paths to find the loop entry
        simgr.explore(find=loop_entry)

        if not simgr.found:
            raise FailedConcolicExecution(f"Could not find target address {hex(loop_entry)} after executing loop at {hex(entry_addr)}")


        pre_loop_state = simgr.found[0]
        stack_pointer = pre_loop_state.regs.rsp
        
        stack_memory_before = pre_loop_state.solver.eval(pre_loop_state.memory.load(stack_pointer, current_stack_frame.get_stack_size()), cast_to=bytes)
        
        iteration_count = 0
        
        simgr = self.project.factory.simgr(pre_loop_state)

        while iteration_count < self.max_iter:
            simgr.step()
            
            if len(simgr.active) == 0:
                raise FailedLoopUnrolling("No active states left to execute. The loop may not have executed properly.")
            
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
        if "isoc99" in function_name:
            return function_name.split("_")[-1]
        if function_name[0:2] == "__":
            return function_name[2:]
        return function_name
    
    def __is_in_loop(self, node) -> bool:
        for loop in self.loops:
            if node.addr == loop.continue_edges[0][0].addr:
                return True
        return False