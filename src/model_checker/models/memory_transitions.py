from enum import Enum
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

from src.exceptions import WriteOperationException

class TransitionType(Enum):
    """
    Enumerates the types of transitions that can be used in the memory model.

    Direct: Memory operation that directly affects the stack with one instruction.

    Indirect: Memory operation that indirectly affects the stack through a function call.
    """
    DIRECT = 1
    INDIRECT = 2


class DataType(Enum):
    """
    Enumerates the types of data that can be written to the stack.

    BYTE: 1 byte
    WORD: 2 bytes
    DWORD: 4 bytes
    QWORD: 8 bytes
    """
    BYTE = 1
    WORD = 2
    DWORD = 4
    QWORD = 8

data_type_strings = {
    "byte": DataType.BYTE,
    "word": DataType.WORD,
    "dword": DataType.DWORD,
    "qword": DataType.QWORD
}

register_size = {
    **dict.fromkeys(["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl",
                     "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"], DataType.BYTE),
    **dict.fromkeys(["ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                     "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"], DataType.WORD),
    **dict.fromkeys(["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                     "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"], DataType.DWORD),
    **dict.fromkeys(["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"], DataType.QWORD)
}

def parse_pointer_size(instruction: str) -> DataType:
    """
    Parses the data type for a mov operation of the following format
    
    mov (byte|word|dword|qword) ptr [address], reg
    """
    data_type = instruction.split()[0]
    return data_type_strings[data_type]


def is_pointer_write(instruction: str) -> bool:
    """
    Returns true if the instruction is a write to a pointer.
    """
    return "ptr" in instruction

class OperationType(Enum):
    """
    Enumerates the types of operations that can be performed on the stack.

    WRITE: Write data to the stack
    BUFFER_ALLOCATION: Allocate a buffer on the stack
    FRAME_EXTENSION: Extend the stack frame
    PUSH: Push data to the stack
    POP: Pop data from the stack
    """
    WRITE = 1
    BUFFER_ALLOCATION = 2
    FRAME_EXTENSION = 3
    PUSH = 4
    POP = 5
    INDIRECT = 6
    JUMP = 7
    NULL = 8
    CANARY = 9
    CALL = 10

class MemoryOperation:
    """
    Represents a memory operation that was performed on the stack.
    """

    def __init__(self, operation_type):
        self.operation_type = operation_type
        
class CanarySetup(MemoryOperation):
    def __init__(self):
        super().__init__(operation_type=OperationType.CANARY)

class JumpOperation(MemoryOperation):
    def __init__(self):
        super().__init__(operation_type=OperationType.JUMP)

class IndirectMemoryOperation(MemoryOperation):
    """
    Represents a memory operation that indirectly affects the stack through a function call.
    """

    def __init__(self):
        super().__init__(operation_type=OperationType.INDIRECT)

class CallOperation(IndirectMemoryOperation):
    """
    Represents a call operation that was performed on the stack.
    """

    def __init__(self, func):
        super().__init__()
        self.function = func

class WriteOperation(MemoryOperation):
    """
    Represents a write operation that was performed on the stack
    """

    def __init__(self, address, source, source_type, instruction: str) -> None:
        super().__init__(OperationType.WRITE)
        self.address = address
        if source_type == X86_OP_REG:
            self.data_size = register_size[source]
        # If the source is an immediate value, 8 bytes will be pushed to the stack
        # This might not happen if the processor is running in other modes other than 64-bit mode
        # Or if the assembly code is doing something weird
        elif source_type == X86_OP_IMM:
            if is_pointer_write(instruction):
                self.data_size = parse_pointer_size(instruction)
            else:
                self.data_size = DataType.QWORD
        elif source_type == X86_OP_MEM:
            raise WriteOperationException(
                "Source type cannot be memory\nSource: " + source)
        else:
            raise WriteOperationException(
                "Invalid source type\nSource: " + source)


class BufferAllocation(MemoryOperation):
    """
    Represents a buffer allocation operation that was performed on the stack.
    """

    def __init__(self, offset, data_type=None):
        super().__init__(OperationType.BUFFER_ALLOCATION)
        self.offset = offset
        # Not sure if the data type is every specified
        self.data_type = data_type


class FrameExtension(MemoryOperation):
    """
    Represents a frame extension operation that was performed on the stack.
    """

    def __init__(self, size):
        super().__init__(OperationType.FRAME_EXTENSION)
        self.size = size

class PushOperation(MemoryOperation):
    """
    Represents a push operation that was performed on the stack.
    """

    def __init__(self, data_size, critical):
        super().__init__(OperationType.PUSH)
        self.critical = critical
        self.data_size = data_size

class PopOperation(MemoryOperation):
    """
    Represents a pop operation that was performed on the stack.
    """

    def __init__(self, data_size: int):
        super().__init__(OperationType.POP)
        self.data_size = data_size

MemoryOperatorType = {
    **dict.fromkeys(["push"], OperationType.PUSH),
    **dict.fromkeys(["pop"], OperationType.POP),
    **dict.fromkeys(["mov", "xchg"], OperationType.WRITE),
    **dict.fromkeys(["lea"], OperationType.BUFFER_ALLOCATION),
    **dict.fromkeys(["sub"], OperationType.FRAME_EXTENSION),
    **dict.fromkeys(["call"], OperationType.INDIRECT),
    **dict.fromkeys(["jmp", 
                     "jg", "jnle", "jge", "jnl", "jl", "jnge", "jle", "jng",
                     "ja", "jnbe", "jae", "jnb", "jb", "jnae", "jbe", "jna",
                     "je", "jz", "jne", "jnz", "js", "jc", "jo"], OperationType.JUMP),
    **dict.fromkeys(["endbr64"], OperationType.CALL)
}


class MemoryTransition:
    """
    Represents a transition between two memory states in the form of a memory operation.
    """

    def __init__(self, instruction, cfg, fname=None) -> None:
        self.instruction = instruction
        self.cfg = cfg
        self.fname = fname
        self.func = None
        self.type = self.match_instruction(instruction)
        # Save the index of the transition in the state space
        self.index = None

    def match_instruction(self, instruction):
        
        mnemonic = instruction.mnemonic
        n_operands = len(instruction.operands)
        
        try:
            match MemoryOperatorType[mnemonic]:
                case OperationType.CALL:
                    return CallOperation(self.fname)
                case OperationType.PUSH:
                    critical = False
                    if instruction.reg_name(instruction.operands[0].reg) == "rbp":
                        critical = True
                    return PushOperation(register_size[instruction.reg_name(instruction.operands[0].reg)].value, critical)
                case OperationType.POP:
                    return PopOperation(register_size[instruction.reg_name(instruction.operands[0].reg)].value)
                case OperationType.WRITE:
                    if n_operands == 2:
                        # If the first operand is a memory address, a write to memory operation is performed
                        if instruction.operands[0].type == X86_OP_MEM:
                            address = instruction.operands[0].value.mem
                            if instruction.reg_name(address.base) == "rbp" and instruction.reg_name(address.index) is None:
                                if instruction.operands[1].type == X86_OP_REG:
                                    offset = address.disp
                                    source = instruction.operands[1]
                                    reg_name = instruction.reg_name(source.reg)
                                    return WriteOperation(offset, reg_name, source.type, instruction.op_str)
                                elif instruction.operands[1].type == X86_OP_IMM:
                                    offset = address.disp
                                    return WriteOperation(offset, address, X86_OP_IMM, instruction.op_str)
                            else:
                                return None
                        # If the second operand is a memory address, a read from memory operation is performed
                        # We generally do not care, but we want to know if a read from fs:[x] is performed, which is the canary
                        elif instruction.operands[1].type == X86_OP_MEM:
                            if "qword ptr fs:" in instruction.op_str.split(", ")[-1]:
                                return CanarySetup()
                            else:
                                return None
                    return None
                case OperationType.BUFFER_ALLOCATION:
                    if n_operands == 2:
                        if instruction.operands[0].type == X86_OP_REG and instruction.operands[1].type == X86_OP_MEM:
                            address = instruction.operands[1].value.mem
                            if instruction.reg_name(address.base) == "rbp":
                                offset = address.disp
                                return BufferAllocation(offset)
                    return None
                case OperationType.FRAME_EXTENSION:
                    if n_operands == 2:
                        if instruction.operands[0].type == X86_OP_REG and instruction.reg_name(instruction.operands[0].reg) == "rsp":
                            if instruction.operands[1].type == X86_OP_IMM:
                                size = abs(int(instruction.operands[1].imm))
                                return FrameExtension(size)
                        elif instruction.operands[1].type == X86_OP_REG:
                            return None
                    return None
                case OperationType.INDIRECT:
                    if mnemonic == "call":
                        self.func = self.determine_function_name(instruction)
                    return IndirectMemoryOperation()
                case OperationType.JUMP:
                    return JumpOperation()
                case OperationType.NULL:
                    return None
        except KeyError:
            # Dynamically add the mnemonic to the dictionary to avoid future KeyError
            MemoryOperatorType[mnemonic] = OperationType.NULL
            return None

    def determine_function_name(self, ins):
        call_addr = ins.operands[0].imm
        for func in self.cfg.kb.functions.values():
            if func.addr == call_addr:
                return func.name.split("_")[-1]
        return "Unknown Function"

    def __str__(self) -> str:
        if self.instruction.mnemonic == "enbr64":
            return f"call {self.fname}"
        if self.instruction.mnemonic == "call":
            return f"call {self.func}"
        if MemoryOperatorType[self.instruction.mnemonic] == OperationType.JUMP:
            return f"loop"
        return str(self.instruction.mnemonic)