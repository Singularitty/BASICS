# System modules
from typing import NamedTuple
from enum import IntEnum
import capstone
import angr

import os
import subprocess
import nose
import claripy

# User modules
import src.global_vars as global_vars
import src.model_checker.models.emulated_functions as simulator
from src.model_checker.models.wrappers import MemoryAddress
from src.model_checker.models.memory_transitions import MemoryOperation, OperationType
from src.model_checker.models.stack_frame import StackFrame
from src.exceptions import FailedConcolicExecution

class OperandType(IntEnum):
    """
    Represents the type of an operand.
    """
    REGISTER = 1
    IMMEDIATE = 2
    MEMORY = 3

    def __str__(self) -> str:
        return self.name

class DataType(IntEnum):
    """
    Represents the data types that can be used in C.
    """
    CHAR = 1
    INT = 2
    POINTER = 3
    SIZE_T = 4

class CType(NamedTuple):
    """
    Represents a C type

    datatype: DataType: The data type of the C type
    size: int: The size of the C type in bytes
    pointed_type: "CType" = None: The pointed type if the C type is a pointer
    """
    datatype: DataType
    size: int
    pointed_type: "CType" = None

# Compost C types
CHAR_BUFF = CType(DataType.POINTER, 8, CType(DataType.CHAR, 1))

# Floats not important for now


C_LIB_FUNCTION_DATA = {
    "strcpy": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]},
    "gets": {"safe": False, "arguments": [CHAR_BUFF]},
    "sprintf": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]}, 
    "scanf": {"safe": False, "arguments": [CHAR_BUFF]},
    "strcat": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]}
}

PARAMETER_REGISTERS = {0: "rdi", 1: "rsi",
                       2: "rdx", 3: "rcx", 
                       4: "r8",  5: "r9"}


def is_register(operand: capstone.x86.X86Op) -> bool:
    """
    Determines if the given operand is a register.
    """
    return operand.type == capstone.x86.X86_OP_REG


def is_immediate(operand: capstone.x86.X86Op) -> bool:
    """
    Determines if the given operand is an immediate value.
    """
    return operand.type == capstone.x86.X86_OP_IMM


def is_memory(operand: capstone.x86.X86Op) -> bool:
    """
    Determines if the given operand is a memory address.
    """
    return operand.type == capstone.x86.X86_OP_MEM


def get_register_name(ins: angr.block.CapstoneInsn,
                      operand: capstone.x86.X86Op) -> str:
    """
    Returns the name of the register in the given operand.
    """
    return ins.reg_name(operand.reg)


def get_operand_value(ins: angr.block.CapstoneInsn,
                      operand: capstone.x86.X86Op) -> int | str | capstone.x86.X86OpMem:
    """
    Determines the value of the given operand.
    """
    if is_register(operand):
        return get_register_name(ins, operand)
    elif is_immediate(operand):
        return operand.value.imm
    elif is_memory(operand):
        return MemoryAddress(ins, operand.value.mem)
    else:
        raise ValueError("Unknown operand type: " + str(operand.type))


def get_operand_type(operand: capstone.x86.X86Op) -> OperandType:
    """
    Determines the type of the given operand.
    """
    if is_register(operand):
        return OperandType.REGISTER
    elif is_immediate(operand):
        return OperandType.IMMEDIATE
    elif is_memory(operand):
        return OperandType.MEMORY
    else:
        raise ValueError("Unknown operand type: " + str(operand.type))


class RegisterState(NamedTuple):
    """
    Represents the state of a register.

    The register can point to a value in another register
    """
    name: str
    valuetype: OperandType
    value: int | MemoryAddress | str
    contains_arg: bool = False
    instruction_addr: int = None
    instruction: object = None

    def __str__(self) -> str:
        return f"{self.name}: {self.valuetype} -> {self.value} set on {hex(self.instruction_addr)}"


class ArgumentState(NamedTuple):
    """
    Represents the state of an argument.

    The argument can point to a value in another register
    """
    register_name: str
    order: int
    expected_type: CType 
    value: int | MemoryAddress | str
    instruction: object = None
    instruction_addr: int = None

    def __str__(self) -> str:
        return f"Argument #{self.order} {self.register_name}: {self.expected_type} -> {self.value} set on {hex(self.instruction_addr)}"

class CallEmulator:
    """
    Emulates the effects of modelled C library functions on the stack by
    using concolic execution.
    """

    def __init__(self,
                 current_stack_frame: StackFrame,
                 call_instruction: angr.block.CapstoneInsn,
                 target_node: angr.block,
                 cfg: angr.analyses.cfg,
                 project: angr.Project,
                 user_functions,
                 binary_path: str,
                 concolic_exection=True):

        self.stack_frame = current_stack_frame
        self.call_instruction = call_instruction
        self.call_addr = call_instruction.address
        self.target_node = target_node
        self.cfg = cfg
        self.user_functions = user_functions
        self.function_name = None
        self.expected_parameters = {}
        self.register_values = {}
        self.buffer_map = {}
        self.binary_path = binary_path
        self.project = project
        self.generic_call = False

        if concolic_exection:
            if self.setup():
                print(f"Function {self.function_name} detected.\nPerforming Concolic Execution...")
                self.stack_changes = self.concolic_execution()
            else:
                self.stack_changes = []
        else:
            self.setup()
            
    def save_concolic_input(self, fname, bad_input: str):
        """
        Saves the bad input that triggered the vulnerability.
        """
        if bad_input is not None:
            with open(f"{global_vars.REPORTS_DIR}/{global_vars.BINARY_NAME}/concolic_inputs.txt", 'a') as f:
                f.write(f"{fname}: {bad_input}\n")
        
    def concolic_execution(self):
        
        target_addr = self.call_instruction.address
        entry_addr = self.target_node.function_address
        
        if global_vars.DEBUG:
            print(f"Function start: {hex(entry_addr)}")
            print(f"Buffer map: {self.buffer_map}")
            print(f"Expected Parameters: {self.expected_parameters}")

        # Emulate the function call in a generic way with no guarantees
        if self.generic_call:
            emulated_call = simulator.CLibGeneric(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr,
                                                    fname = self.function_name)
        # "Manually" implemented functions
        else:
            match self.function_name:
                case "strcpy":
                    emulated_call = simulator.Strcpy(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr)
                case "gets":
                    emulated_call = simulator.Gets(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr)
                    
                case "scanf":
                    emulated_call = simulator.Scanf(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr)
                    
                case "strcat":
                    emulated_call = simulator.Strcat(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr)
                case "sprintf":
                    emulated_call = simulator.Sprintf(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr)
                case _:
                    raise NotImplementedError(f"Function {self.function_name} not implemented.")
        try:
            stack_changes = emulated_call.run()
            if self.function_name in global_vars.STDIN_FUNCTIONS:
                self.save_concolic_input(self.function_name, emulated_call.concolic_input())
        except Exception: # f it, catch it all!
            print("Failed to execute function. Skipping...")
            stack_changes = []
        return stack_changes
                
                
    def setup(self):
        
        # Determine the function name
        self.__determine_function_name()
        # Initialize the expected parameters
        try:
            for reg, _ in zip(PARAMETER_REGISTERS.values(),
                              C_LIB_FUNCTION_DATA[self.function_name]["arguments"]):
             self.expected_parameters[reg] = None
        except KeyError:
            if self.function_name in global_vars.NO_EXECUTE_FUNCTIONS:
                return False
            self.generic_call = True

        # Attempt to determine the instructions that set the arguments of the function
        self.__determine_argument_instructions()
        #for reg_name, reg_state in self.expected_parameters.items():
        #    print(f"{reg_name} -> {reg_state}")

        # Determine the buffer map
        try:
            for arg in self.expected_parameters.values():
                if self.__is_buffer_type(arg.expected_type) and arg.value.base_register == 'rbp':
                    buffer_offset, size = self.__determine_buffer_size(arg)
                    self.buffer_map[arg.register_name] = (buffer_offset, size)
        except AttributeError:
            self.buffer_map = {}


        return True
                
    def __determine_buffer_size(self, arg: ArgumentState) -> int:
        offset = arg.value.displacement
        size = self.stack_frame.get_buffer(abs(offset))
        return offset, size


    def __determine_function_name(self):

        call_addr = self.call_instruction.operands[0].imm
        for func in self.cfg.kb.functions.values():
            if func.addr == call_addr:
                self.function_name = func.name.split("_")[-1]
                return

    def __is_buffer_type(self, ctype: CType) -> bool:
        """
        Determines if the given C type is a buffer type.
        """
        # TODO: Better way to determine if a type is a buffer type
        match ctype.datatype:
            case DataType.POINTER:
                return True
            case _:
                return False

    def get_register_pointed_value(self, reg_state: RegisterState) -> int | str | capstone.x86.X86OpMem:
        """
        Returns the value that the given register points to.
        """
        if reg_state.valuetype == OperandType.REGISTER:
            return self.get_register_pointed_value(self.register_values[reg_state.value])
        return reg_state.value

    def __update_register_values(self, ins: angr.block.CapstoneInsn):
        """
        Updates the values of the registers based on the given instruction.

        Does not update the values of the registers that are already set.
        """
        match ins.mnemonic:
            case "mov":
                op1 = ins.operands[0]
                if is_register(op1):
                    reg_name = get_register_name(ins, op1)
                    if reg_name not in self.register_values:
                        op2 = ins.operands[1]
                        self.register_values[reg_name] = RegisterState(reg_name,
                                                                       get_operand_type(
                                                                           op2),
                                                                       get_operand_value(
                                                                           ins, op2),
                                                                       reg_name in self.expected_parameters,
                                                                       ins.address,
                                                                       ins)
            case "lea":
                op1 = ins.operands[0]
                reg_name = get_register_name(ins, op1)
                if reg_name not in self.register_values:
                    op2 = ins.operands[1]
                    mem = get_operand_value(ins, op2)
                    self.register_values[reg_name] = RegisterState(reg_name,
                                                                   OperandType.MEMORY,
                                                                   mem,
                                                                   reg_name in self.expected_parameters,
                                                                   ins.address,
                                                                   ins)
            case _:
                pass

    def __determine_argument_instructions(self):
        """
        Attemps to determine the instructions that set the arguments of the function.

        This uses some assumptions:
            - The call instruction is the last instruction of the block
            - The args are set in the same block as the call instruction
            - The arg registers are set using the mov instruction
        """

        instructions = self.target_node.block.capstone.insns

        for i in range(self.target_node.block.instructions-2, -1, -1):
            ins = instructions[i]
            self.__update_register_values(ins)

        for reg_state in self.register_values.values():
            if reg_state.contains_arg:
                arg_index = list(self.expected_parameters.keys()).index(reg_state.name)
                self.expected_parameters[reg_state.name] = ArgumentState(reg_state.name,
                                                                         arg_index,
                                                                         C_LIB_FUNCTION_DATA[self.function_name]["arguments"][arg_index],
                                                                         self.get_register_pointed_value(reg_state),
                                                                         reg_state.instruction,
                                                                         reg_state.instruction_addr)
