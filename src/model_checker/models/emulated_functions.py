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

# Register holding the destination buffer, when it is not rdi.
_DESTINATION_REGISTERS = {"read": "rsi", "recv": "rsi", "scanf": "rsi", "fscanf": "rdx", "sscanf": "rdx"}

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
        self.written_offsets = []
        self.target_node = None
        self.call_size = None
        # True when the recorded writes leave the known destination buffer.
        self.destination_overflow = False

    def bind_call_site(self, target_node, call_instruction):
        """The CFG node holding the call and the call instruction itself."""
        self.target_node = target_node
        self.call_size = call_instruction.size

    def run(self):
        failed = False
        try:
            self.execute()
        except FailedConcolicExecution:
            print(f"Failed to execute {self.fname} at address {hex(self.target_addr)}")
            print("Retrying without function hooks...")
            # Retry with the stubbed PLT entries unhooked, then put the same
            # procedures back so later queries see an unchanged project.
            saved = [(addr, self.project.hooked_by(addr)) for addr in GLOBAL_HOOKS if self.project.is_hooked(addr)]
            for addr, _ in saved:
                self.project.unhook(addr)
            try:
                self.execute()
                print("Execution successful without hooks.")
            except FailedConcolicExecution:
                print(f"Failed to execute {self.fname} at address {hex(self.target_addr)}")
                print("Skipping...")
                failed = True
            finally:
                for addr, procedure in saved:
                    if not self.project.is_hooked(addr):
                        self.project.hook(addr, procedure)
        return [] if failed else self.stack_comparison()
    
    @abstractmethod
    def execute(self):
        ...

    def execute_call_site(self, pre_call_hook=None):
        pre_call_state = ConcolicExecutor.reaching_state(self.project, self.target_node.addr)
        pre_call_state = ConcolicExecutor.advance_instructions(
            self.project,
            pre_call_state,
            self.__instruction_index_in_block(),
        )

        if pre_call_hook is not None:
            pre_call_hook(pre_call_state)

        stack_pointer = pre_call_state.solver.eval(pre_call_state.regs.rsp)
        self.stack_pointer = stack_pointer
        with ConcolicExecutor.real_libc_procedures(self.project):
            written, post_call_state = ConcolicExecutor.run_call_recording_writes(
                self.project,
                pre_call_state,
                self.target_addr + self.call_size,
                stack_pointer,
                stack_pointer + self.stack_size,
            )
        self.written_offsets = sorted(address - stack_pointer for address in written)
        destination = getattr(self, "buffer_map", {}).get(_DESTINATION_REGISTERS.get(self.fname, "rdi"))
        if destination is not None and destination[1] is not None and written:
            rbp = pre_call_state.solver.eval(pre_call_state.regs.rbp)
            start = rbp + int(destination[0])
            end = start + int(destination[1])
            self.destination_overflow = any(not start <= address < end for address in written)
        self.stack_before = pre_call_state.solver.eval(
            pre_call_state.memory.load(stack_pointer, self.stack_size), cast_to=bytes,
        )
        if post_call_state is not None:
            self.stack_after = post_call_state.solver.eval(
                post_call_state.memory.load(stack_pointer, self.stack_size), cast_to=bytes,
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
        """Stack-array indices written by the call, from the recorded writes."""
        return [self.convert_indice(offset, self.stack_size) for offset in self.written_offsets]
    
    def concolic_input(self):
        
        input = []

        if self.stack_after is None:
            return ""
        for offset in self.written_offsets:
            input.append(self.stack_after[offset])
        
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
            # Only invent attacker input when the reached state has no concrete
            # source (e.g. the analysis entry is the sink itself).
            if not self.source_on_stack and pre_call_state.regs.rsi.symbolic:
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
            if (not found_source or not self.source_on_stack) and pre_call_state.regs.rdx.symbolic:
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
