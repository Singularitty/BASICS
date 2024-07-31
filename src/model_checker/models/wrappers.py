import angr
import capstone

class MemoryAddress:
    """
    Represents a indexed memory address.

    This is a wrapper for the capstone.x86.X86OpMem class.

    base_register: str: The base register of the memory address
    index_register: str: The index register of the memory address
    scale: int: The scale of the memory address
    displacement: int: The displacement of the memory address

    """
    base_register: str
    index_register: str
    scale: int
    displacement: int

    def __init__(self, ins: angr.block.CapstoneInsn, mem: capstone.x86.X86OpMem):
        self.base_register = ins.reg_name(mem.base) if mem.base != 0 else None
        self.index_register = ins.reg_name(
            mem.index) if mem.index != 0 else None
        self.scale = mem.scale if mem.scale > 1 else None
        self.displacement = mem.disp if mem.disp != 0 else None

    def __str__(self) -> str:
        string = ""
        if self.base_register is not None:
            string += f"{self.base_register}"
        if self.index_register is not None:
            string += f" + {self.index_register}"
        if self.scale is not None:
            string += f" * {self.scale}"
        if self.displacement is not None:
            if self.displacement < 0:
                string += f" - {hex(-self.displacement)}"
            else:
                string += f" + {hex(self.displacement)}"
        return string
