# System imports
import numpy as np

# User imports
from src.model_checker.models.byte_states import ByteState, byte_state_automaton, WriteType
from src.exceptions import NonExistentByte, NonExistentStackFrame

class StackFrame:
    """
    Objects of this class represent a stack frame of a model.

    A stack frame model is an array of size n, corresponding to the size of a corresponding functions
    stack frame in the binary. Each element of the array is a byte state, which can be in one of the
    following states:
        - Free: The byte is not occupied
        - Critical: The byte is occupied by criical data
        - Occupied: The byte is occupied by non-critical data
        - Modified: The byte is occupied by data that has been modified
    """

    def __init__(self, stack_frame: np.array = None, buffer_map=None, rbp: int = 0, canary = False, canary_written = None) -> None:
        if buffer_map is None:
            buffer_map = {}
        # Create numpy array of size 1 and data type uint8
        # uint8 is used to conserve memory
        if stack_frame is not None:
            self.stack_frame = stack_frame
        else:
            self.stack_frame = np.zeros(8, dtype=np.uint8) # Allocate 8 bytes for the return address
        self.buffer_map = buffer_map
        self.rbp = rbp
        self.canary = canary
        self.canary_written = canary_written

    def __copy__(self) -> "StackFrame":
        return StackFrame(self.stack_frame.copy(), self.buffer_map.copy(), self.rbp)

    def initialize(self):
        """
        Initializes the stack frame after a function call.
        """
        # First byte is always occupied by the return address which is critical
        for i in range(8):
            self.stack_frame[i] = ByteState.CRITICAL
        self.rbp += 8

    def setup_canary(self):
        self.canary = True
        self.canary_written = False
        
    def write_canary(self):
        if self.canary_written:
            return self
        if (self.rbp + 8) > len(self.stack_frame):
            new_stack_frame = np.concatenate([new_stack_frame, np.full(
                (self.rbp + 8) - len(self.stack_frame), ByteState.FREE, dtype=np.uint8)])
        else:
            new_stack_frame = self.stack_frame.copy()
        for i in range(8):
            new_stack_frame[16 + i] = ByteState.CRITICAL
        return StackFrame(new_stack_frame, self.buffer_map.copy(), self.rbp, self.canary, True)

    def extend(self, size):
        """
        Extends the stack frame by size bytes.

        Args:
            size (int): The number of bytes to extend the stack frame by.

        Returns:
            StackFrame: A new stack frame with the extended size.
        """
        new_stack_frame = np.concatenate(
            [self.stack_frame, np.full(size, ByteState.FREE, dtype=np.uint8)])
        return StackFrame(new_stack_frame, self.buffer_map.copy(), self.rbp, self.canary, self.canary_written)

    def write(self, offset, data_size: int):
        """Perms a write to the given offset.
        """
        offset = abs(offset)
        if (offset + self.rbp) > len(self.stack_frame):
            new_stack_frame = np.concatenate([self.stack_frame, np.full(
                offset - (len(self.stack_frame) - self.rbp), ByteState.FREE, dtype=np.uint8)])
        else:
            new_stack_frame = self.stack_frame.copy()
        offset = offset - 1 + self.rbp
        new_state = byte_state_automaton(
            new_stack_frame[offset], WriteType.NON_CRITICAL)
        for i in range(data_size):
            new_stack_frame[offset-i] = new_state
        return StackFrame(new_stack_frame, self.buffer_map.copy(), self.rbp)

    def write_multiple_bytes(self, indices):
        new_stack_frame = self.stack_frame.copy()
        for index in indices:
            new_state = byte_state_automaton(new_stack_frame[index], WriteType.NON_CRITICAL)
            #print(f"Index: {index}, State: {new_state}")
            new_stack_frame[index] = new_state
        return StackFrame(new_stack_frame, self.buffer_map.copy(), self.rbp, self.canary, self.canary_written)

    def push(self, critical: bool, data_size: int):
        """Pushes a new byte to the stack frame.
        """
        new_state = ByteState.CRITICAL if critical else ByteState.OCCUPIED
        new_stack_frame = np.concatenate(
            [self.stack_frame, np.full(data_size, new_state, dtype=np.uint8)])
        # if a critical push is made, the rbp register is incremented because the stack base pointer of the caller has been saved
        new_rbp = self.rbp + data_size if critical else self.rbp
        return StackFrame(new_stack_frame, self.buffer_map.copy(), new_rbp)

    def pop(self, data_size: int):
        """Pops a byte from the stack frame.
        """
        new_stack_frame = self.stack_frame[:-data_size]
        return StackFrame(new_stack_frame, self.buffer_map.copy(), self.rbp, self.canary, self.canary_written)

    def map_buffer(self, offset):
        """
        Maps a buffer to the stack frame.

        To calculate buffer size, we iterate backwards from the offset until we find a byte that is not free.
        Or until we reach the beginning of another buffer.
        """
        try:
            i = 1
            offset = abs(offset)
            if offset - i + (self.rbp-1) > len(self.stack_frame):
                self.stack_frame = np.concatenate(
                    [self.stack_frame, np.full(offset - i + (self.rbp-1) - len(self.stack_frame), ByteState.FREE, dtype=np.uint8)])
            last_state = self.stack_frame[offset - i + (self.rbp-1)]
            while offset - i >= 0:
                if self.stack_frame[offset - i + (self.rbp-1)] == last_state and \
                        (offset - i) not in self.buffer_map.keys():
                    last_state = self.stack_frame[offset - i + (self.rbp-1)]
                    i += 1
                else:
                    break
            self.buffer_map[offset] = i
            self.update_buffer_sizes()
        except IndexError:
            pass

    def get_byte_state(self, offset):
        """Returns the byte state at the given offset.
        """
        try: 
            return self.stack_frame[offset]
        except IndexError:
            raise NonExistentByte(offset)

    def get_stack_size(self):
        """Returns the size of the stack frame.
        """
        return len(self.stack_frame)

    def get_rbp(self):
        """Returns the value of the rbp register.
        """
        return self.rbp

    def get_buffer(self, offset):
        """Returns the buffer at the given offset.
        """
        return self.buffer_map.get(offset)

    def get_buffer_ids(self) -> list:
        """Returns the ids of the buffers in the stack frame.
        """
        return list(self.buffer_map.keys())

    def update_buffer(self, offset, size):
        """Updates the size of the buffer at the given offset.
        """
        self.buffer_map[offset] = size

    def update_buffer_sizes(self):
        """
        Not recommended to use this method due to potential changes in the stack frame
        after the buffer alocation which may lead to smaller buffer sizes than in reality.

        Determines the size of the buffers in the stack frame.
        """

        for offset in self.buffer_map.keys():
            offset = abs(offset)
            i = 1
            last_state = self.stack_frame[offset - i + (self.rbp-1)]
            while offset - i >= 0:
                if self.stack_frame[offset - i + (self.rbp-1)] == last_state and \
                        (offset - i) not in self.buffer_map.keys():
                    last_state = self.stack_frame[offset - i + (self.rbp-1)]
                    i += 1
                else:
                    break
            self.buffer_map[offset] = i