import angr
import claripy

from abc import ABC, abstractmethod

from pwn import cyclic

from src.model_checker.models.wrappers import MemoryAddress
from src.model_checker.models.concolic_executor import ConcolicExecutor
from src.exceptions import FailedConcolicExecution
from src.global_vars import GLOBAL_HOOKS, ANGR_OPTION

def nothing(state):
    pass

class EmulatedFunction(ABC):
    
    def __init__(self, fname, project, entry_addr, target_addr, stack_size, args: list) -> None:
        self.fname = fname
        self.project = project
        self.entry_addr = entry_addr
        self.target_addr = target_addr
        self.stack_size = stack_size
        self.arguments = list(args)
        self.stack_before = None
        self.stack_after = None
    
    def run(self):
        failed = False
        try:
            self.execute()
        except FailedConcolicExecution:
            print(f"Failed to execute {self.fname} at address {hex(self.target_addr)}")
            print("Retrying without function hooks...")
            for addr in GLOBAL_HOOKS:
                self.project.unhook(addr)
            try:
                self.execute()
                print("Execution successful without hooks.")
            except FailedConcolicExecution:
                print(f"Failed to execute {self.fname} at address {hex(self.target_addr)}")
                print("Skipping...")
                failed = True
            finally:
               for addr in GLOBAL_HOOKS:
                    self.project.hook(addr, nothing, length=4)
        # After a function is executed, DO NOT EXECUTE IT AGAIN
        # Otherwise the program might break :(
        self.project.hook(self.target_addr, nothing, length=4)
        GLOBAL_HOOKS.add(self.target_addr)
        #except FailedConcolicExecution:
        #    print(f"Retrying to execute {self.fname} at address {hex(self.target_addr)} with function hooks...")
        #    for addr in GLOBAL_HOOKS:
        #        self.project.hook(addr, nothing, length=4)
        #   try:
        #        self.execute()
        #        print("Execution successful with hooks.")
        #    except FailedConcolicExecution:
        #        failed = True
        #        print("Failed to execute function, skipping...")
        #    finally:
        #        for addr in GLOBAL_HOOKS:
        #            self.project.unhook(addr)
        return [] if failed else self.stack_comparison()
    
    @abstractmethod
    def execute(self):
        ...

    def execute_call_site(self, pre_call_hook=None, steps=3):
        pre_call_state = ConcolicExecutor.reaching_state(self.project, self.target_node.addr)
        pre_call_state = ConcolicExecutor.advance_instructions(
            self.project,
            pre_call_state,
            self.__instruction_index_in_block(),
        )
        self.stack_pointer = pre_call_state.regs.rsp

        if pre_call_hook is not None:
            pre_call_hook(pre_call_state)

        self.stack_before = pre_call_state.solver.eval(
            pre_call_state.memory.load(self.stack_pointer, self.stack_size),
            cast_to=bytes,
        )
        post_call_state = ConcolicExecutor.step_from_state(self.project, pre_call_state, steps=steps)
        self.stack_after = post_call_state.solver.eval(
            post_call_state.memory.load(self.stack_pointer, self.stack_size),
            cast_to=bytes,
        )

    def __instruction_index_in_block(self):
        for index, instruction in enumerate(self.target_node.block.capstone.insns):
            if instruction.address == self.target_addr:
                return index
        return 0
    
    def convert_indice(self, indice, stack_size):
        """Converts the index given by the emulator to the index of the stack array.
        """
        if indice == 0:
            return stack_size - 1
        return ((stack_size - 1) - indice) % (stack_size - 1)

    def stack_comparison(self):

        diffs = []

        if len(self.stack_before) != len(self.stack_after):
            raise ValueError(f"Stacks have different sizes after executing {self.fname}.")

        for i in range(len(self.stack_before)):
            if self.stack_before[i] != self.stack_after[i]:
                diffs.append(self.convert_indice(i, self.stack_size)) 

        return diffs
    
    def concolic_input(self):
        
        input = []
        
        if len(self.stack_before) != len(self.stack_after):
            raise ValueError(f"Stacks have different sizes after executing {self.fname}.")
        
        for i in range(len(self.stack_before)):
            if self.stack_before[i] != self.stack_after[i]:
                input.append(self.stack_after[i])
        
        result = ""
        for byte in input:
            result += chr(byte)
        return result

class Strcpy(EmulatedFunction):
    
    destination_on_stack = True
    source_on_stack = True
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("strcpy", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None
    
    def execute(self):
        self.source_on_stack = False
        for arg, details in self.buffer_map.items():
            #print(arg)
            if arg == "rsi":
                if details[1] is not None:
                    self.source_on_stack = True
                    break
                break

        def pre_call_hook(pre_call_state):
            if not self.source_on_stack:
                print("Source buffer is not on current stack frame")
                stdin = cyclic(self.stack_size)
                cyclic_input = claripy.BVV(stdin)
                buffer_addr = pre_call_state.regs.rbp + 0x8 * 2
                pre_call_state.memory.store(buffer_addr, cyclic_input)
                pre_call_state.regs.rsi = buffer_addr

        self.execute_call_site(pre_call_hook)
            
            
            
class Gets(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("gets", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None
    
    def execute(self):
        def pre_call_hook(pre_call_state):
            pre_call_state.libc.buf_symbolic_bytes = 0x1000
            pre_call_state.libc.maximum_buffer_size = 0x1000

        self.execute_call_site(pre_call_hook)
            
class Scanf(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("scanf", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None
    
    def execute(self):
        self.execute_call_site()
            
class Strcat(EmulatedFunction):

    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("strcat", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None

    def execute(self):
        self.execute_call_site()


class Sprintf(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("sprintf", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None
        self.source_on_stack = True

    def execute(self):
        found_source = False
        for arg, details in self.buffer_map.items():
            if arg == "rdx":
                found_source = True
                if details[1] is None:
                    self.source_on_stack = False
                    break
                break

        def pre_call_hook(pre_call_state):
            if not found_source or not self.source_on_stack:
                print("Source buffer is not on current stack frame")
                stdin = cyclic(self.stack_size)
                cyclic_input = claripy.BVV(stdin)
                buffer_addr = pre_call_state.regs.rbp + 0x8 * 2
                pre_call_state.memory.store(buffer_addr, cyclic_input)
                pre_call_state.regs.rdx = buffer_addr

        self.execute_call_site(pre_call_hook)

class CLibGeneric(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size, fname) -> None:
        super().__init__(fname, project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None

    def execute(self):
        self.execute_call_site()
