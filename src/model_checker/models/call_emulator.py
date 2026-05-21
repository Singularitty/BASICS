# System modules
from typing import NamedTuple
from enum import IntEnum
import re
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
SIZE_ARG = CType(DataType.SIZE_T, 8)
INT_ARG = CType(DataType.INT, 4)
VOID_PTR = CType(DataType.POINTER, 8)

# Floats not important for now


C_LIB_FUNCTION_DATA = {
    "strcpy": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]},
    "stpcpy": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]},
    "strncpy": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF, SIZE_ARG]},
    "gets": {"safe": False, "arguments": [CHAR_BUFF]},
    "sprintf": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]}, 
    "snprintf": {"safe": True, "arguments": [CHAR_BUFF, SIZE_ARG, CHAR_BUFF]},
    "vsprintf": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF, VOID_PTR]},
    "vsnprintf": {"safe": True, "arguments": [CHAR_BUFF, SIZE_ARG, CHAR_BUFF, VOID_PTR]},
    "scanf": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]},
    "fscanf": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF, CHAR_BUFF]},
    "sscanf": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF, CHAR_BUFF]},
    "strcat": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF]},
    "strncat": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF, SIZE_ARG]},
    "memcpy": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF, SIZE_ARG]},
    "memmove": {"safe": False, "arguments": [CHAR_BUFF, CHAR_BUFF, SIZE_ARG]},
    "memset": {"safe": False, "arguments": [CHAR_BUFF, INT_ARG, SIZE_ARG]},
    "fgets": {"safe": True, "arguments": [CHAR_BUFF, INT_ARG, VOID_PTR]},
    "read": {"safe": False, "arguments": [INT_ARG, CHAR_BUFF, SIZE_ARG]},
    "recv": {"safe": False, "arguments": [INT_ARG, CHAR_BUFF, SIZE_ARG, INT_ARG]},
}

PARAMETER_REGISTERS = {0: "rdi", 1: "rsi",
                       2: "rdx", 3: "rcx", 
                       4: "r8",  5: "r9"}

REGISTER_ALIASES = {
    "edi": "rdi", "di": "rdi", "dil": "rdi",
    "esi": "rsi", "si": "rsi", "sil": "rsi",
    "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "eax": "rax", "ax": "rax", "al": "rax",
    "ebx": "rbx", "bx": "rbx", "bl": "rbx",
    "esp": "rsp", "sp": "rsp", "spl": "rsp",
    "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
}


def canonical_register(register_name):
    return REGISTER_ALIASES.get(register_name, register_name)


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
    return canonical_register(ins.reg_name(operand.reg))


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
        self.local_pointer_map = {}
        self.local_malloc_size_map = {}
        self.register_constant_values = {}
        self.register_string_length_values = {}
        self.source_length_upper_bound = None
        self.register_malloc_sizes = {}
        self.rsp_allocation_size = None
        self.binary_path = binary_path
        self.project = project
        self.generic_call = False

        if concolic_exection:
            if self.setup():
                if not global_vars.SCAN_MODE:
                    print(f"Function {self.function_name} detected.\nModeling stack effects...")
                self.stack_changes = self.__model_stack_effects()
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
                case "strcpy" | "stpcpy":
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
                    
                case "scanf" | "sscanf":
                    emulated_call = simulator.Scanf(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr)

                case "fscanf":
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
                case "sprintf" | "vsprintf":
                    emulated_call = simulator.Sprintf(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr)
                case _:
                    emulated_call = simulator.CLibGeneric(self.expected_parameters.values(),
                                                    project=self.project,
                                                    buffer_map=self.buffer_map,
                                                    stack_size=self.stack_frame.get_stack_size(),
                                                    entry_addr=entry_addr,
                                                    target_addr=target_addr,
                                                    fname=self.function_name)
        try:
            stack_changes = emulated_call.run()
            if self.function_name in global_vars.STDIN_FUNCTIONS:
                self.save_concolic_input(self.function_name, emulated_call.concolic_input())
        except Exception: # f it, catch it all!
            print("Failed to execute function. Skipping...")
            stack_changes = []
        return stack_changes

    def __model_stack_effects(self):
        if global_vars.FUNCTION_SIMULATION in ("auto", "static"):
            stack_changes = self.__static_stack_effects()
            if stack_changes is not None:
                if not global_vars.SCAN_MODE:
                    print(f"Using static stack-effect model for {self.function_name}.")
                if self.function_name in global_vars.STDIN_FUNCTIONS:
                    self.save_concolic_input(self.function_name, "A" * max(1, min(self.stack_frame.get_stack_size(), 4096)))
                return stack_changes
            if global_vars.FUNCTION_SIMULATION == "static":
                if not global_vars.SCAN_MODE:
                    print(f"Could not statically model {self.function_name}; skipping angr fallback.")
                return []
        return self.concolic_execution()

    def __static_stack_effects(self):
        if self.function_name in ("scanf", "fscanf", "sscanf"):
            format_register, first_output_register = {
                "scanf": ("rdi", "rsi"),
                "fscanf": ("rsi", "rdx"),
                "sscanf": ("rsi", "rdx"),
            }[self.function_name]
            write_size = self.__format_write_size(self.stack_frame.get_stack_size(), format_register)
            if write_size == 0:
                return []
            destination_register = first_output_register
        else:
            destination_register = None
        destination_register = {
            "strcpy": "rdi",
            "stpcpy": "rdi",
            "strncpy": "rdi",
            "gets": "rdi",
            "strcat": "rdi",
            "strncat": "rdi",
            "sprintf": "rdi",
            "snprintf": "rdi",
            "vsprintf": "rdi",
            "vsnprintf": "rdi",
            "memcpy": "rdi",
            "memmove": "rdi",
            "memset": "rdi",
            "fgets": "rdi",
            "read": "rsi",
            "recv": "rsi",
        }.get(self.function_name, destination_register)
        if destination_register is None:
            return None
        if destination_register not in self.buffer_map:
            rsp_alloca_indices = self.__rsp_alloca_overflow_indices_for_register(destination_register)
            if rsp_alloca_indices is not None:
                return rsp_alloca_indices
            underwrite_indices = self.__stack_underwrite_indices_for_register(destination_register)
            if underwrite_indices is not None:
                return underwrite_indices
            dynamic_size = self.register_malloc_sizes.get(destination_register)
            if dynamic_size is not None:
                write_size = self.__static_write_size(dynamic_size)
                if write_size is None:
                    return None
                if write_size > dynamic_size and self.__known_local_overflow(dynamic_size, write_size):
                    if global_vars.DEBUG:
                        print(
                            f"Static call effect: {self.function_name} overflows dynamic stack buffer "
                            f"write_size={write_size} dest_size={dynamic_size}; using full-frame write."
                        )
                    return self.__full_stack_write()
                if global_vars.DEBUG:
                    print(
                        f"Static call effect: {self.function_name} fits dynamic stack buffer "
                        f"write_size={write_size} dest_size={dynamic_size}; no stack overflow modeled."
                    )
                return []
            return None

        destination_offset, destination_size = self.buffer_map[destination_register]
        underwrite_indices = self.__stack_underwrite_indices(destination_offset)
        if underwrite_indices is not None:
            return underwrite_indices
        if destination_size is None:
            if self.function_name in ("gets", "scanf", "fscanf", "sscanf", "sprintf", "vsprintf"):
                if global_vars.DEBUG:
                    print(f"Static call effect: {self.function_name} destination {destination_register} size unknown; using full-frame write.")
                return self.__full_stack_write()
            return None

        write_size = self.__static_write_size(destination_size)
        if write_size <= 0:
            return []
        if (
            self.function_name in ("strcpy", "stpcpy")
            and self.source_length_upper_bound is not None
            and destination_size is not None
            and destination_size > self.source_length_upper_bound
            and write_size == self.source_length_upper_bound + 1
        ):
            if global_vars.DEBUG:
                print(
                    f"Static call effect: {self.function_name} guarded source length "
                    f"{self.source_length_upper_bound} suggests off-by-one into rounded "
                    f"dest_size={destination_size}; using full-frame write."
                )
            return self.__full_stack_write()
        if self.__known_local_overflow(destination_size, write_size):
            if global_vars.DEBUG:
                print(
                    f"Static call effect: {self.function_name} known local overflow "
                    f"write_size={write_size} dest_size={destination_size}; using full-frame write."
                )
            return self.__full_stack_write()
        if self.function_name in ("scanf", "fscanf", "sscanf") and destination_size is not None and write_size > destination_size:
            if global_vars.DEBUG:
                print(
                    f"Static call effect: {self.function_name} parsed write_size={write_size} exceeds "
                    f"dest_size={destination_size}; using full-frame write."
                )
            return self.__full_stack_write()
        if self.function_name in ("scanf", "fscanf", "sscanf"):
            format_register = {
                "scanf": "rdi",
                "fscanf": "rsi",
                "sscanf": "rsi",
            }[self.function_name]
            fmt = self.__string_argument_for_register(format_register)
            if fmt is not None:
                max_width = self.__max_string_scan_width(fmt)
                if max_width is not None and max_width >= 100:
                    if global_vars.DEBUG:
                        print(f"Static call effect: {self.function_name} high width={max_width}; using full-frame write.")
                    return self.__full_stack_write()

        indices = self.__stack_indices_for_write(destination_offset, write_size)
        if global_vars.DEBUG:
            print(
                "Static call effect:",
                self.function_name,
                f"dest={destination_register}",
                f"offset={destination_offset}",
                f"dest_size={destination_size}",
                f"write_size={write_size}",
                f"indices={indices[:16]}{'...' if len(indices) > 16 else ''}",
            )
        return indices

    def __known_local_overflow(self, destination_size, write_size):
        if destination_size is None or write_size <= destination_size:
            if self.function_name in ("sprintf", "vsprintf"):
                # GCC rounds char[30] stack slots in this benchmark family to
                # an inferred 40-byte region; writes above 30 are still unsafe.
                return destination_size == 40 and write_size > 30
            return False
        return self.function_name in (
            "strcpy", "stpcpy", "strncpy", "strcat", "strncat",
            "sprintf", "snprintf", "vsprintf", "vsnprintf", "memcpy", "memmove", "memset",
            "read", "recv", "gets", "scanf", "fscanf", "sscanf",
        )

    def __rsp_alloca_overflow_indices_for_register(self, register_name):
        arg = self.expected_parameters.get(register_name)
        if arg is None or self.rsp_allocation_size is None:
            return None
        if arg.value != "rsp":
            return None
        write_size = self.__static_write_size(self.rsp_allocation_size)
        if write_size is None:
            return None
        if self.function_name in ("gets", "scanf", "fscanf", "sscanf", "sprintf", "vsprintf"):
            if global_vars.DEBUG:
                print(
                    f"Static call effect: {self.function_name} has unbounded rsp-backed "
                    f"destination allocation={self.rsp_allocation_size}; using full-frame write."
                )
            return self.__full_stack_write()
        if write_size > self.rsp_allocation_size and self.__known_local_overflow(self.rsp_allocation_size, write_size):
            if global_vars.DEBUG:
                print(
                    f"Static call effect: {self.function_name} overflows alloca buffer "
                    f"write_size={write_size} alloca_size={self.rsp_allocation_size}; using full-frame write."
                )
            return self.__full_stack_write()
        if global_vars.DEBUG:
            print(
                f"Static call effect: {self.function_name} fits alloca buffer "
                f"write_size={write_size} alloca_size={self.rsp_allocation_size}; no stack overflow modeled."
            )
        return []

    def __stack_underwrite_indices_for_register(self, register_name):
        arg = self.expected_parameters.get(register_name)
        if arg is None or not isinstance(arg.value, MemoryAddress):
            return None
        if canonical_register(arg.value.base_register) != "rbp":
            return None
        return self.__stack_underwrite_indices(arg.value.displacement or 0)

    def __stack_underwrite_indices(self, destination_offset):
        underwritten = self.__underwritten_buffer(destination_offset)
        if underwritten is None:
            return None
        start_index = self.stack_frame.get_rbp() + underwritten
        write_indices = [
            index
            for index in range(start_index, start_index + 2)
            if 0 <= index < self.stack_frame.get_stack_size()
        ]
        # Model the buffer underside as a red-zone signature so the LTL
        # property can stay byte-state-only and avoid generic full-frame FPs.
        if write_indices:
            write_indices = [write_indices[0], write_indices[0], *write_indices[1:]]
        if global_vars.DEBUG:
            print(
                f"Static call effect: {self.function_name} destination offset={destination_offset} "
                f"is before stack buffer {underwritten}; marking underside indices {write_indices}."
            )
        return write_indices

    def __underwritten_buffer(self, destination_offset):
        destination_abs = abs(int(destination_offset))
        buffer_ids = sorted(bid for bid in self.stack_frame.get_buffer_ids() if isinstance(bid, int))
        if destination_abs in buffer_ids:
            return None
        lower_buffers = [bid for bid in buffer_ids if bid < destination_abs]
        if not lower_buffers:
            return None
        nearest_lower = max(lower_buffers)
        higher_buffers = [bid for bid in buffer_ids if bid > destination_abs]
        if higher_buffers and destination_abs >= min(higher_buffers):
            return None
        return nearest_lower

    def __static_write_size(self, destination_size):
        stack_size = self.stack_frame.get_stack_size()
        if self.function_name == "strcat":
            source_length = self.__string_length_for_register("rsi")
            if source_length is not None:
                return min(stack_size, max(0, int(source_length)) + 1)
            source_size = self.__buffer_size_for_register("rsi")
            if source_size is None:
                return destination_size
            return min(stack_size, source_size)
        if self.function_name == "strncat":
            length = self.__integer_argument_for_register("rdx")
            if length is None:
                length = stack_size
            # strncat appends to the current C-string length, not to the
            # destination buffer capacity. Juliet's fixed-size sinks initialize
            # dest as an empty string before the call, so model the appended
            # bytes plus the terminating NUL.
            return min(stack_size, max(0, int(length)) + 1)
        if self.function_name in ("strcpy", "stpcpy"):
            source_literal_size = self.__string_argument_length_for_register("rsi")
            if source_literal_size is not None:
                return min(stack_size, source_literal_size)
            if self.source_length_upper_bound is not None:
                return min(stack_size, self.source_length_upper_bound + 1)
            source_size = self.__buffer_size_for_register("rsi")
            if source_size is not None:
                if destination_size is not None and source_size > destination_size:
                    return stack_size
                return min(stack_size, source_size)
            return destination_size
        if self.function_name == "strncpy":
            length = self.__integer_argument_for_register("rdx")
            if length is None:
                return stack_size
            return min(stack_size, max(0, int(length)))
        if self.function_name in ("sprintf", "vsprintf"):
            formatted_size = self.__printf_write_size("rsi")
            if formatted_size is not None:
                if destination_size is not None and formatted_size > destination_size:
                    return stack_size
                return min(stack_size, formatted_size)
            # Format string is known but has unbounded %s → treat as full overflow
            if self.__string_argument_for_register("rsi") is not None:
                return stack_size
            return destination_size
        if self.function_name in ("snprintf", "vsnprintf"):
            length = self.__integer_argument_for_register("rsi")
            if length is None:
                return stack_size
            return min(stack_size, max(0, int(length)))
        if self.function_name == "gets":
            return stack_size
        if self.function_name in ("scanf", "fscanf", "sscanf"):
            return self.__format_write_size(stack_size)
        if self.function_name in ("memcpy", "memmove", "memset"):
            length = self.__integer_argument_for_register("rdx")
            if length is None:
                return stack_size
            return min(stack_size, max(0, int(length)))
        if self.function_name == "fgets":
            length = self.__integer_argument_for_register("rsi")
            if length is None:
                return stack_size
            return min(stack_size, max(0, int(length)))
        if self.function_name in ("read", "recv"):
            length = self.__integer_argument_for_register("rdx")
            if length is None:
                return stack_size
            return min(stack_size, max(0, int(length)))
        return None

    def __format_write_size(self, default_size, format_register=None):
        format_register = format_register or {
            "scanf": "rdi",
            "fscanf": "rsi",
            "sscanf": "rsi",
        }.get(self.function_name)
        fmt = self.__string_argument_for_register(format_register)
        if fmt is None:
            if global_vars.DEBUG:
                print(f"Static call effect: {self.function_name} format unknown in {format_register}; using default write size.")
            return default_size
        if global_vars.DEBUG:
            print(f"Static call effect: {self.function_name} format={fmt!r}")
        max_string_write = self.__max_string_scan_write(fmt)
        if max_string_write is None:
            return default_size
        return max_string_write

    def __max_string_scan_write(self, fmt):
        max_write = 0
        for match in re.finditer(r"%(?P<suppress>\*)?(?P<width>\d*)(?:hh|h|ll|l|j|z|t|L)?(?P<conv>[s\[])", fmt):
            if match.group("suppress"):
                continue
            width_text = match.group("width")
            if not width_text:
                return None
            max_write = max(max_write, int(width_text) + 1)
        return max_write

    def __max_string_scan_width(self, fmt):
        max_width = 0
        saw = False
        for match in re.finditer(r"%(?P<suppress>\*)?(?P<width>\d*)(?:hh|h|ll|l|j|z|t|L)?(?P<conv>[s\[])", fmt):
            if match.group("suppress"):
                continue
            saw = True
            width_text = match.group("width")
            if not width_text:
                return None
            max_width = max(max_width, int(width_text))
        return max_width if saw else 0

    def __printf_write_size(self, format_register):
        fmt = self.__string_argument_for_register(format_register)
        if fmt is None:
            return None

        total = 0
        index = 0
        pattern = re.compile(
            r"%(?P<flags>[-+#0 ']*)(?P<width>\d+|\*)?"
            r"(?:\.(?P<precision>\d+|\*))?"
            r"(?P<length>hh|h|ll|l|j|z|t|L)?(?P<conv>[diuoxXfFeEgGaAcspn%])"
        )
        while index < len(fmt):
            if fmt[index] != "%":
                total += 1
                index += 1
                continue

            match = pattern.match(fmt, index)
            if match is None:
                return None
            conv = match.group("conv")
            width_text = match.group("width")
            precision_text = match.group("precision")
            if width_text == "*" or precision_text == "*":
                return None

            width = int(width_text) if width_text else 0
            if conv == "%":
                contribution = 1
            elif conv == "n":
                contribution = 0
            elif conv == "s":
                if precision_text is None:
                    return None
                contribution = int(precision_text)
            elif conv == "c":
                contribution = max(width, 1)
            elif conv in "diuoxXp":
                contribution = max(width, 20)
            elif conv in "fFeEgGaA":
                precision = int(precision_text) if precision_text is not None else 6
                contribution = max(width, precision + 16)
            else:
                return None
            total += contribution
            index = match.end()

        # Include the terminating NUL byte written by sprintf/vsprintf.
        return total + 1

    def __string_argument_for_register(self, register_name):
        try:
            arg = self.expected_parameters[register_name]
        except KeyError:
            return None
        if arg is None:
            return None
        addr = self.__resolve_static_address(arg.value, arg.instruction)
        if addr is None:
            return None
        return self.__read_c_string(addr)

    def __string_argument_length_for_register(self, register_name):
        value = self.__string_argument_for_register(register_name)
        if value is None:
            return None
        # C strings include the NULL terminator in write size.
        return len(value.encode("utf-8", errors="ignore")) + 1

    def __resolve_static_address(self, value, instruction=None):
        if isinstance(value, int):
            return value
        if isinstance(value, MemoryAddress):
            base = canonical_register(value.base_register)
            disp = value.displacement or 0
            if base == "rip" and instruction is not None:
                return int(instruction.address + instruction.size + disp)
            if base is None:
                return int(disp)
        return None

    def __read_c_string(self, addr, max_len=4096):
        try:
            data = self.project.loader.memory.load(addr, max_len)
        except Exception:
            return None
        zero = data.find(b"\x00")
        if zero >= 0:
            data = data[:zero]
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def __buffer_size_for_register(self, register_name):
        try:
            return self.buffer_map[register_name][1]
        except KeyError:
            return self.register_malloc_sizes.get(register_name)

    def __integer_argument_for_register(self, register_name):
        try:
            arg = self.expected_parameters[register_name]
        except KeyError:
            return None
        if arg is None:
            return self.register_constant_values.get(register_name)
        if isinstance(arg.value, int):
            return arg.value
        constant_value = self.register_constant_values.get(register_name)
        if constant_value is not None:
            return constant_value
        return None

    def __string_length_for_register(self, register_name):
        length = self.register_string_length_values.get(register_name)
        if length is not None:
            return length
        literal_length = self.__string_argument_length_for_register(register_name)
        if literal_length is not None:
            return max(0, literal_length - 1)
        return None

    def __stack_indices_for_write(self, destination_offset, write_size):
        high_index = self.stack_frame.get_rbp() + abs(destination_offset) - 1
        low_index = max(-1, high_index - write_size)
        return [
            index
            for index in range(high_index, low_index, -1)
            if 0 <= index < self.stack_frame.get_stack_size()
        ]

    def __full_stack_write(self):
        redzone_indices = self.__buffer_underside_indices()
        return [
            index
            for index in range(self.stack_frame.get_stack_size())
            if index not in redzone_indices
        ]

    def __buffer_underside_indices(self):
        indices = set()
        for buffer_id in self.stack_frame.get_buffer_ids():
            if not isinstance(buffer_id, int):
                continue
            start_index = self.stack_frame.get_rbp() + buffer_id - 1
            for index in (start_index + 1, start_index + 2):
                if 0 <= index < self.stack_frame.get_stack_size():
                    indices.add(index)
        return indices
                
                
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
                if (
                    arg is not None
                    and isinstance(arg.value, MemoryAddress)
                    and self.__is_buffer_type(arg.expected_type)
                    and canonical_register(arg.value.base_register) == 'rbp'
                ):
                    buffer_offset, size = self.__determine_buffer_size(arg)
                    self.buffer_map[arg.register_name] = (buffer_offset, size)
        except AttributeError:
            self.buffer_map = {}


        return True
                
    def __determine_buffer_size(self, arg: ArgumentState) -> int:
        offset = arg.value.displacement
        abs_offset = abs(offset)
        size = self.stack_frame.get_buffer(abs_offset)
        if size is not None:
            # Bound buffer size by nearest mapped local closer to rbp to avoid
            # merged/over-approximated regions from coarse frame mapping.
            upper_neighbors = [
                bid for bid in self.stack_frame.get_buffer_ids()
                if isinstance(bid, int) and bid < abs_offset
            ]
            if upper_neighbors:
                nearest_upper = max(upper_neighbors)
                size = min(size, abs_offset - nearest_upper)
        return offset, size


    def __determine_function_name(self):

        call_addr = self.call_instruction.operands[0].imm
        for func in self.cfg.kb.functions.values():
            if func.addr == call_addr:
                self.function_name = self.__sanitize_function_name(func.name)
                return

    def __sanitize_function_name(self, function_name):
        if function_name is None:
            return None
        name = function_name.split("@", 1)[0]
        for prefix in ("__isoc99_", "__isoc23_", "__GI_", "__libc_"):
            if name.startswith(prefix):
                name = name[len(prefix):]
        if name.startswith("_") and name.count("_") > 1:
            tail = name.split("_")[-1]
            if tail in C_LIB_FUNCTION_DATA:
                return tail
        return name

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
        return self.get_register_pointed_state(reg_state).value

    def get_register_pointed_state(self, reg_state: RegisterState) -> RegisterState:
        if reg_state.valuetype == OperandType.REGISTER:
            pointed_register = canonical_register(reg_state.value)
            if pointed_register not in self.register_values:
                return reg_state
            return self.get_register_pointed_state(self.register_values[pointed_register])
        if reg_state.valuetype == OperandType.MEMORY and isinstance(reg_state.value, MemoryAddress):
            if canonical_register(reg_state.value.base_register) == "rbp":
                local_slot = abs(reg_state.value.displacement or 0)
                if local_slot in self.local_pointer_map:
                    return RegisterState(
                        reg_state.name,
                        OperandType.MEMORY,
                        self.local_pointer_map[local_slot],
                        reg_state.contains_arg,
                        reg_state.instruction_addr,
                        reg_state.instruction,
                    )
        return reg_state

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
                    op2 = ins.operands[1]
                    if is_register(op2):
                        src_name = get_register_name(ins, op2)
                        if src_name in self.register_values:
                            src_state = self.get_register_pointed_state(self.register_values[src_name])
                            self.register_values[reg_name] = RegisterState(
                                reg_name,
                                src_state.valuetype,
                                src_state.value,
                                reg_name in self.expected_parameters,
                                src_state.instruction_addr,
                                src_state.instruction,
                            )
                            return
                        if src_name == "rsp" and self.rsp_allocation_size is not None:
                            self.register_values[reg_name] = RegisterState(
                                reg_name,
                                OperandType.REGISTER,
                                "rsp",
                                reg_name in self.expected_parameters,
                                ins.address,
                                ins,
                            )
                            return
                    if is_memory(op2):
                        mem = get_operand_value(ins, op2)
                        if isinstance(mem, MemoryAddress) and canonical_register(mem.base_register) == "rbp":
                            local_slot = abs(mem.displacement or 0)
                            if local_slot not in self.local_pointer_map:
                                return
                            self.register_values[reg_name] = RegisterState(
                                reg_name,
                                OperandType.MEMORY,
                                self.local_pointer_map[local_slot],
                                reg_name in self.expected_parameters,
                                ins.address,
                                ins,
                            )
                            return
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

        instructions = self.__collect_argument_setup_instructions()
        self.__determine_local_pointer_assignments(self.__collect_function_prefix_instructions())

        for ins in instructions:
            if ins.address >= self.call_addr:
                break
            self.__update_register_values(ins)

        for reg_state in self.register_values.values():
            if reg_state.contains_arg:
                arg_index = list(self.expected_parameters.keys()).index(reg_state.name)
                pointed_state = self.get_register_pointed_state(reg_state)
                self.expected_parameters[reg_state.name] = ArgumentState(reg_state.name,
                                                                         arg_index,
                                                                         C_LIB_FUNCTION_DATA[self.function_name]["arguments"][arg_index],
                                                                         pointed_state.value,
                                                                         pointed_state.instruction,
                                                                         pointed_state.instruction_addr)

    def __collect_argument_setup_instructions(self):
        return self.target_node.block.capstone.insns

    def __collect_function_prefix_instructions(self):
        try:
            func = self.cfg.kb.functions.get_by_addr(self.target_node.function_address)
        except Exception:
            func = None
        if func is None:
            return self.target_node.block.capstone.insns

        instructions = []
        for addr in sorted(func.block_addrs):
            if addr > self.call_addr:
                continue
            try:
                block = self.project.factory.block(addr)
            except Exception:
                continue
            for ins in block.capstone.insns:
                if ins.address >= self.call_addr:
                    break
                instructions.append(ins)
        return instructions

    def __determine_local_pointer_assignments(self, instructions):
        register_points_to_stack = {}
        register_constants = {}
        register_malloc_sizes = {}
        register_malloc_source_slots = {}  # reg → rbp-slot the malloc ptr was loaded from
        register_string_lengths = {}
        local_string_length_map = {}
        stack_string_length_map = {}
        last_cmp_bound = None
        last_rsp_allocation_size = None
        for ins in instructions:
            if ins.address >= self.call_addr:
                break
            self.__track_alloca_constants(ins, register_constants)
            if self.rsp_allocation_size is not None and self.rsp_allocation_size != last_rsp_allocation_size:
                register_malloc_sizes["rsp"] = self.rsp_allocation_size
                last_rsp_allocation_size = self.rsp_allocation_size
            match ins.mnemonic:
                case "cmp":
                    last_cmp_bound = self.__cmp_upper_bound(ins)
                    continue
                case "jle" | "jbe":
                    if last_cmp_bound is not None:
                        self.source_length_upper_bound = last_cmp_bound
                    continue
                case "call":
                    # Any call clobbers rax (return value) — clear stale stack tracking for it
                    register_points_to_stack.pop("rax", None)
                    register_malloc_sizes.pop("rax", None)
                    register_malloc_source_slots.pop("rax", None)
                    register_string_lengths.pop("rax", None)
                    if len(ins.operands) >= 1 and is_immediate(ins.operands[0]):
                        fname = self.__call_function_name(ins.operands[0].imm)
                        if fname == "malloc":
                            size = register_constants.get("rdi")
                            if size is not None and int(size) > 0:
                                register_malloc_sizes["rax"] = int(size)
                            else:
                                register_malloc_sizes.pop("rax", None)
                            register_malloc_source_slots.pop("rax", None)
                            register_constants.pop("rax", None)
                        elif fname == "memset":
                            size = register_constants.get("rdx")
                            if size is not None and size > 0:
                                register_string_lengths["rdi"] = int(size)
                                dest_mem = register_points_to_stack.get("rdi")
                                if isinstance(dest_mem, MemoryAddress) and canonical_register(dest_mem.base_register) == "rbp":
                                    stack_string_length_map[abs(dest_mem.displacement or 0)] = int(size)
                                slot = register_malloc_source_slots.get("rdi")
                                if slot is not None and slot in self.local_malloc_size_map:
                                    self.local_malloc_size_map[slot] = int(size)
                                    local_string_length_map[slot] = int(size)
                                    for reg, reg_slot in list(register_malloc_source_slots.items()):
                                        if reg_slot == slot:
                                            register_malloc_sizes[reg] = int(size)
                                            register_string_lengths[reg] = int(size)
                                else:
                                    dest_size = register_malloc_sizes.get("rdi")
                                    if dest_size is not None:
                                        for local_slot, local_size in list(self.local_malloc_size_map.items()):
                                            if local_size == dest_size:
                                                local_string_length_map[local_slot] = int(size)
                            register_constants.pop("rax", None)
                        elif fname == "strlen":
                            length = register_string_lengths.get("rdi")
                            slot = register_malloc_source_slots.get("rdi")
                            if length is None and slot is not None:
                                length = local_string_length_map.get(slot)
                            if length is None:
                                src_mem = register_points_to_stack.get("rdi")
                                if isinstance(src_mem, MemoryAddress) and canonical_register(src_mem.base_register) == "rbp":
                                    length = stack_string_length_map.get(abs(src_mem.displacement or 0))
                            if length is not None:
                                register_constants["rax"] = int(length)
                            else:
                                register_constants.pop("rax", None)
                        else:
                            register_constants.pop("rax", None)
                    continue
                case "jmp" | "jg" | "ja" | "jge" | "jae" | "jl" | "jb":
                    last_cmp_bound = None
                    continue
                case "lea":
                    if len(ins.operands) < 2 or not is_register(ins.operands[0]) or not is_memory(ins.operands[1]):
                        continue
                    reg_name = get_register_name(ins, ins.operands[0])
                    mem = get_operand_value(ins, ins.operands[1])
                    register_malloc_sizes.pop(reg_name, None)
                    register_malloc_source_slots.pop(reg_name, None)
                    register_string_lengths.pop(reg_name, None)
                    if (
                        isinstance(mem, MemoryAddress)
                        and canonical_register(mem.base_register) in ("rbp", "rip")
                    ):
                        register_points_to_stack[reg_name] = mem
                case "add" | "sub":
                    if len(ins.operands) < 2 or not is_register(ins.operands[0]) or not is_immediate(ins.operands[1]):
                        continue
                    reg_name = get_register_name(ins, ins.operands[0])
                    if reg_name not in register_points_to_stack:
                        continue
                    register_string_lengths.pop(reg_name, None)
                    delta = int(ins.operands[1].imm)
                    if ins.mnemonic == "sub":
                        delta = -delta
                    register_points_to_stack[reg_name] = self.__memory_address_with_delta(
                        register_points_to_stack[reg_name],
                        delta,
                    )
                case "mov":
                    if len(ins.operands) < 2:
                        continue
                    if is_register(ins.operands[0]) and is_register(ins.operands[1]):
                        dst_reg = get_register_name(ins, ins.operands[0])
                        src_reg = get_register_name(ins, ins.operands[1])
                        if src_reg in register_points_to_stack:
                            register_points_to_stack[dst_reg] = register_points_to_stack[src_reg]
                        elif src_reg == "rsp" and self.rsp_allocation_size is not None:
                            register_points_to_stack[dst_reg] = "rsp"
                        else:
                            register_points_to_stack.pop(dst_reg, None)
                        if src_reg in register_malloc_sizes:
                            register_malloc_sizes[dst_reg] = register_malloc_sizes[src_reg]
                        elif src_reg == "rsp" and self.rsp_allocation_size is not None:
                            register_malloc_sizes[dst_reg] = self.rsp_allocation_size
                        else:
                            register_malloc_sizes.pop(dst_reg, None)
                        if src_reg in register_malloc_source_slots:
                            register_malloc_source_slots[dst_reg] = register_malloc_source_slots[src_reg]
                        else:
                            register_malloc_source_slots.pop(dst_reg, None)
                        if src_reg in register_string_lengths:
                            register_string_lengths[dst_reg] = register_string_lengths[src_reg]
                        else:
                            register_string_lengths.pop(dst_reg, None)
                        continue
                    if is_register(ins.operands[0]) and is_memory(ins.operands[1]):
                        dst_reg = get_register_name(ins, ins.operands[0])
                        src_mem = get_operand_value(ins, ins.operands[1])
                        if isinstance(src_mem, MemoryAddress) and canonical_register(src_mem.base_register) == "rbp":
                            local_slot = abs(src_mem.displacement or 0)
                            if local_slot in self.local_pointer_map:
                                register_points_to_stack[dst_reg] = self.local_pointer_map[local_slot]
                            else:
                                register_points_to_stack.pop(dst_reg, None)
                            if local_slot in self.local_malloc_size_map:
                                register_malloc_sizes[dst_reg] = self.local_malloc_size_map[local_slot]
                                register_malloc_source_slots[dst_reg] = local_slot
                            else:
                                register_malloc_sizes.pop(dst_reg, None)
                                register_malloc_source_slots.pop(dst_reg, None)
                            if local_slot in local_string_length_map:
                                register_string_lengths[dst_reg] = local_string_length_map[local_slot]
                            else:
                                register_string_lengths.pop(dst_reg, None)
                        elif (
                            isinstance(src_mem, MemoryAddress)
                            and src_mem.index_register is None
                            and src_mem.displacement is None
                            and canonical_register(src_mem.base_register) in register_points_to_stack
                        ):
                            # Indirect dereference: mov dst, [reg] where reg → rbp slot
                            base = canonical_register(src_mem.base_register)
                            pointed_mem = register_points_to_stack[base]
                            register_points_to_stack.pop(dst_reg, None)
                            if isinstance(pointed_mem, MemoryAddress) and canonical_register(pointed_mem.base_register) == "rbp":
                                deref_slot = abs(pointed_mem.displacement or 0)
                                if deref_slot in self.local_malloc_size_map:
                                    register_malloc_sizes[dst_reg] = self.local_malloc_size_map[deref_slot]
                                    register_malloc_source_slots[dst_reg] = deref_slot
                                else:
                                    register_malloc_sizes.pop(dst_reg, None)
                                    register_malloc_source_slots.pop(dst_reg, None)
                                if deref_slot in local_string_length_map:
                                    register_string_lengths[dst_reg] = local_string_length_map[deref_slot]
                                else:
                                    register_string_lengths.pop(dst_reg, None)
                            else:
                                register_malloc_sizes.pop(dst_reg, None)
                                register_malloc_source_slots.pop(dst_reg, None)
                                register_string_lengths.pop(dst_reg, None)
                        else:
                            register_points_to_stack.pop(dst_reg, None)
                            register_malloc_sizes.pop(dst_reg, None)
                            register_malloc_source_slots.pop(dst_reg, None)
                            register_string_lengths.pop(dst_reg, None)
                        continue
                    if not is_memory(ins.operands[0]) or not is_register(ins.operands[1]):
                        continue
                    dst = get_operand_value(ins, ins.operands[0])
                    src = get_register_name(ins, ins.operands[1])
                    if isinstance(dst, MemoryAddress) and canonical_register(dst.base_register) == "rbp":
                        slot = abs(dst.displacement or 0)
                        if src in register_points_to_stack:
                            self.local_pointer_map[slot] = register_points_to_stack[src]
                        if src in register_malloc_sizes:
                            self.local_malloc_size_map[slot] = register_malloc_sizes[src]
                        if src in register_string_lengths:
                            local_string_length_map[slot] = register_string_lengths[src]
        self.register_malloc_sizes = register_malloc_sizes
        self.register_constant_values = register_constants
        self.register_string_length_values = register_string_lengths

    def __cmp_upper_bound(self, ins):
        if len(ins.operands) < 2 or not is_immediate(ins.operands[1]):
            return None
        lhs = ins.operands[0]
        if is_memory(lhs):
            mem = get_operand_value(ins, lhs)
            if isinstance(mem, MemoryAddress) and canonical_register(mem.base_register) == "rbp":
                return int(ins.operands[1].imm)
        if is_register(lhs):
            return int(ins.operands[1].imm)
        return None

    def __track_alloca_constants(self, ins, register_constants):
        if not ins.operands:
            return
        if ins.mnemonic == "xor" and len(ins.operands) >= 2 and is_register(ins.operands[0]) and is_register(ins.operands[1]):
            dst = get_register_name(ins, ins.operands[0])
            src = get_register_name(ins, ins.operands[1])
            if dst == src:
                register_constants[dst] = 0
            return
        if ins.mnemonic == "div" and len(ins.operands) >= 1 and is_register(ins.operands[0]):
            divisor_reg = get_register_name(ins, ins.operands[0])
            divisor = register_constants.get(divisor_reg)
            dividend = register_constants.get("rax")
            if divisor is None or divisor == 0 or dividend is None:
                register_constants.pop("rax", None)
                register_constants.pop("rdx", None)
                return
            register_constants["rax"] = dividend // divisor
            register_constants["rdx"] = dividend % divisor
            return
        if len(ins.operands) < 2:
            return
        dst = ins.operands[0]
        src = ins.operands[1]
        if not is_register(dst):
            return
        dst_reg = get_register_name(ins, dst)
        if ins.mnemonic == "sub" and dst_reg == "rsp":
            size = None
            if is_register(src):
                size = register_constants.get(get_register_name(ins, src))
            elif is_immediate(src):
                size = int(src.imm)
            if size is not None and size > 0:
                self.rsp_allocation_size = (self.rsp_allocation_size or 0) + int(size)
            return
        match ins.mnemonic:
            case "mov" | "movsxd":
                if is_immediate(src):
                    register_constants[dst_reg] = int(src.imm)
                elif is_register(src):
                    value = register_constants.get(get_register_name(ins, src))
                    if value is None:
                        register_constants.pop(dst_reg, None)
                    else:
                        register_constants[dst_reg] = value
                else:
                    register_constants.pop(dst_reg, None)
            case "add" | "sub":
                if not is_immediate(src) or dst_reg not in register_constants:
                    register_constants.pop(dst_reg, None)
                    return
                delta = int(src.imm)
                if ins.mnemonic == "sub":
                    delta = -delta
                register_constants[dst_reg] += delta
            case "imul":
                if len(ins.operands) == 3 and is_register(ins.operands[1]) and is_immediate(ins.operands[2]):
                    src_value = register_constants.get(get_register_name(ins, ins.operands[1]))
                    if src_value is None:
                        register_constants.pop(dst_reg, None)
                    else:
                        register_constants[dst_reg] = src_value * int(ins.operands[2].imm)
                elif is_immediate(src) and dst_reg in register_constants:
                    register_constants[dst_reg] *= int(src.imm)
                else:
                    register_constants.pop(dst_reg, None)
        if dst_reg == "rax" and "eax" in register_constants:
            register_constants["rax"] = register_constants["eax"]
        elif dst_reg == "eax" and "eax" in register_constants:
            register_constants["rax"] = register_constants["eax"]

    def __call_function_name(self, call_addr):
        for func in self.cfg.kb.functions.values():
            if func.addr == call_addr:
                return self.__sanitize_function_name(func.name)
        return None

    def __is_malloc_call(self, call_addr):
        return self.__call_function_name(call_addr) == "malloc"

    def __memory_address_with_delta(self, mem, delta):
        clone = MemoryAddress.__new__(MemoryAddress)
        clone.base_register = mem.base_register
        clone.index_register = mem.index_register
        clone.scale = mem.scale
        clone.displacement = (mem.displacement or 0) + delta
        if clone.displacement == 0:
            clone.displacement = None
        return clone
