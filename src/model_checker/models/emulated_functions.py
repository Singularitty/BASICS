import angr
import claripy

from abc import ABC, abstractmethod

from pwn import cyclic

from src.model_checker.models.wrappers import MemoryAddress
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
        main_addr = self.project.loader.main_object.get_symbol("main")
        if ANGR_OPTION is None:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, mode=ANGR_OPTION, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        else:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, add_options={
                                                                                                        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                        })

        self.source_on_stack = False
        for arg, details in self.buffer_map.items():
            #print(arg)
            if arg == "rsi":
                if details[1] is not None:
                    self.source_on_stack = True
                    break
                break


        simgr = self.project.factory.simgr(self.entry_state)
        simgr.explore(find=self.target_addr)
        
        #print(source)
        #print(destination)
        #else:
        #    self.entry_state = self.project.factory.entry_state(addr=self.entry_addr, add_options={angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
        #print(hex(self.target_addr))
        #print(hex(self.entry_addr))
        if simgr.found:
            pre_call_state = simgr.found[0]
            self.stack_pointer = pre_call_state.regs.rsp
            if not self.source_on_stack:
                print("Source buffer is not on current stack frame")
                stdin = cyclic(self.stack_size)
                cyclic_input = claripy.BVV(stdin)
                buffer_adrr = self.entry_state.regs.rbp + 0x8 * 2 # just toss the argument on the stack, this is bull
                self.entry_state = self.project.factory.entry_state(addr=self.entry_addr, add_options={angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
                pre_call_state.memory.store(buffer_adrr, cyclic_input)
                pre_call_state.regs.rsi = buffer_adrr
            
            # Fill stack with null bytes
            #if self.source_on_stack:
            #    pre_call_state.memory.store(self.stack_pointer, b'\x00' * self.stack_size)
            #    pre_call_state.memory.store(self.source_addr, self.source_buffer)
            
            # Save the stack before the call
            self.stack_before = pre_call_state.solver.eval(pre_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            
            for _ in range(3):
                simgr.step(stash="found")
            post_call_state = simgr.found[0]
            
            # Save the stack after the call
            self.stack_after = post_call_state.solver.eval(post_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            
            #print(self.stack_before)
            #print(self.stack_after)
            del self.entry_state
            del simgr
        else:
            del self.entry_state
            del simgr
            raise FailedConcolicExecution
            
            
            
class Gets(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("gets", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None
    
    def execute(self):
        
        main_addr = self.project.loader.main_object.get_symbol("main")
        if ANGR_OPTION is not None:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, mode=ANGR_OPTION, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        else:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        self.entry_state.libc.buf_symbolic_bytes = 0x1000
        self.entry_state.libc.maximum_buffer_size = 0x1000
        simgr = self.project.factory.simgr(self.entry_state)
        simgr.explore(find=self.target_addr)
        
        if simgr.found:
            pre_call_state = simgr.found[0]
            self.stack_pointer = pre_call_state.regs.rsp
            # Save the stack before the call
            self.stack_before = pre_call_state.solver.eval(pre_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            
            for _ in range(3):
                simgr.step(stash="found")
            post_call_state = simgr.found[0]
            
            # Save the stack after the call
            self.stack_after = post_call_state.solver.eval(post_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            
            #print(self.stack_before)
            #print(self.stack_after)
            del self.entry_state
            del simgr
        else:
            del self.entry_state
            del simgr
            raise FailedConcolicExecution
            
class Scanf(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("scanf", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None
    
    def execute(self):
        main_addr = self.project.loader.main_object.get_symbol("main")
        if ANGR_OPTION is not None:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, mode=ANGR_OPTION, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        else:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        #self.entry_state.libc.maximum_buffer_size = 0x1000
        #self.entry_state.libc.

        simgr = self.project.factory.simgr(self.entry_state)
        
        simgr.explore(find=self.target_addr)
        
        if simgr.found:
            pre_call_state = simgr.found[0]
            self.stack_pointer = pre_call_state.regs.rsp
            # Save the stack before the call
            self.stack_before = pre_call_state.solver.eval(pre_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            
            for _ in range(3):
                simgr.step(stash="found")
            post_call_state = simgr.found[0]
            
            # Save the stack after the call
            self.stack_after = post_call_state.solver.eval(post_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            del self.entry_state
            del simgr
        else:
            del self.entry_state
            del simgr
            raise FailedConcolicExecution
            
class Strcat(EmulatedFunction):

    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("strcat", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None

    def execute(self):
        main_addr = self.project.loader.main_object.get_symbol("main")
        if ANGR_OPTION is not None:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, mode=ANGR_OPTION, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        else:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })

        simgr = self.project.factory.simgr(self.entry_state)
        simgr.explore(find=self.target_addr)

        if simgr.found:
            pre_call_state = simgr.found[0]
            self.stack_pointer = pre_call_state.regs.rsp
            # Save the stack before the call
            self.stack_before = pre_call_state.solver.eval(pre_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)

            for _ in range(3):
                simgr.step(stash="found")
            post_call_state = simgr.found[0]

            # Save the stack after the call
            self.stack_after = post_call_state.solver.eval(post_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            del self.entry_state
            del simgr
        else:
            del self.entry_state
            del simgr
            raise FailedConcolicExecution


class Sprintf(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size) -> None:
        super().__init__("sprintf", project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None
        self.source_on_stack = True

    def execute(self):
        main_addr = self.project.loader.main_object.get_symbol("main")
        if ANGR_OPTION is not None:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, mode=ANGR_OPTION, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        else:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })

        found_source = False
        for arg, details in self.buffer_map.items():
            if arg == "rdx":
                found_source = True
                if details[1] is None:
                    self.source_on_stack = False
                    break
                break

        simgr = self.project.factory.simgr(self.entry_state)
        simgr.explore(find=self.target_addr)

        if simgr.found:
            pre_call_state = simgr.found[0]
            self.stack_pointer = pre_call_state.regs.rsp
            if not found_source or not self.source_on_stack:
                print("Source buffer is not on current stack frame")
                stdin = cyclic(self.stack_size)
                cyclic_input = claripy.BVV(stdin)
                buffer_adrr = self.entry_state.regs.rbp + 0x8 * 2 
                self.entry_state = self.project.factory.entry_state(addr=self.entry_addr, add_options={angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
                pre_call_state.memory.store(buffer_adrr, cyclic_input)
                pre_call_state.regs.rdx = buffer_adrr
            self.stack_before = pre_call_state.solver.eval(pre_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)

            for _ in range(3):
                simgr.step(stash="found")
            post_call_state = simgr.found[0]

            # Save the stack after the call
            self.stack_after = post_call_state.solver.eval(post_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)

            #print(self.stack_before)
            #print(self.stack_after)
            del self.entry_state
            del simgr
        else:
            del self.entry_state
            del simgr
            raise FailedConcolicExecution

class CLibGeneric(EmulatedFunction):
    
    def __init__(self, *args, project, buffer_map, entry_addr, target_addr, stack_size, fname) -> None:
        super().__init__(fname, project, entry_addr, target_addr, stack_size, *args)
        self.buffer_map = buffer_map
        self.entry_state = None
        self.stack_pointer = None

    def execute(self):
        main_addr = self.project.loader.main_object.get_symbol("main")
        if ANGR_OPTION is not None:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, mode=ANGR_OPTION, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })
        else:
            self.entry_state = self.project.factory.blank_state(addr=main_addr.rebased_addr, add_options={angr.options.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, 
                                                                                                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                                                      angr.options.REPLACEMENT_SOLVER,
                                                                                                      angr.options.UNICORN,
                                                                                                      angr.options.UNICORN_THRESHOLD_CONCRETIZATION,
                                                                                                      })

        simgr = self.project.factory.simgr(self.entry_state)
        simgr.explore(find=self.target_addr)

        if simgr.found:
            pre_call_state = simgr.found[0]
            self.stack_pointer = pre_call_state.regs.rsp
            # Save the stack before the call
            self.stack_before = pre_call_state.solver.eval(pre_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)

            for _ in range(3):
                try:
                    simgr.step(stash="found")
                    post_call_state = simgr.found[0]
                except IndexError:
                    try:
                        post_call_state = simgr.unconstrained[0]
                    except IndexError:
                        raise FailedConcolicExecution
                    

            # Save the stack after the call
            self.stack_after = post_call_state.solver.eval(post_call_state.memory.load(self.stack_pointer, self.stack_size), cast_to=bytes)
            del self.entry_state
            del simgr
        else:
            del self.entry_state
            del simgr
            raise FailedConcolicExecution