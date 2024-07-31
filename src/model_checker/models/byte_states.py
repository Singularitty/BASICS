from enum import IntEnum
from functools import lru_cache
import numpy as np


class ByteState(IntEnum):
    """
    Possible byte states of a stack frame.
        - Free: The byte is not occupied
        - Critical: The byte is occupied by criical data
        - Occupied: The byte is occupied by non-critical data
        - Modified: The byte is occupied by data that has been modified
    """
    FREE = np.uint8(0)
    CRITICAL = np.uint8(1)
    OCCUPIED = np.uint8(2)
    MODIFIED = np.uint8(3)

    def __str__(self):
        return self.name

class WriteType(IntEnum):
    """
    Possible write types to a stack frame.
    """
    NON_CRITICAL = 0
    CRITICAL = 1


BYTE_STATE_TRANSITIONS = {
    (WriteType.NON_CRITICAL,    ByteState.FREE):       ByteState.OCCUPIED,
    (WriteType.NON_CRITICAL,    ByteState.OCCUPIED):   ByteState.MODIFIED,
    (WriteType.NON_CRITICAL,    ByteState.CRITICAL):   ByteState.MODIFIED,
    (WriteType.NON_CRITICAL,    ByteState.MODIFIED):   ByteState.MODIFIED,
    (WriteType.CRITICAL,        ByteState.FREE):       ByteState.CRITICAL
}

@lru_cache(maxsize=None)
def byte_state_automaton(byte_state: ByteState, write_type: WriteType):
    """
    Transitions a byte state to a new state based on the write type
    and according to the byte state automaton.

    Initial: Free

          Non-Critical Write 
    Free ---------------------> Occupied

            Critical Write
    Free ---------------------> Critical

            Non-Critical Write
    Occupied -----------------> Modified

            Non-Critical Write
    Critical -----------------> Modified

            Non-Critical Write
    Modified -----------------> Modified

    """
    try:
        return BYTE_STATE_TRANSITIONS[(write_type, byte_state)]
    except Exception as e:
        raise ValueError(
            f"Error: {e}\nInvalid byte state transition.\n Byte State: {byte_state}\n Write Type: {write_type}") from e
