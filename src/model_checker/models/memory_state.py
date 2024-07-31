from PIL import Image, ImageDraw, ImageFont

from copy import deepcopy
from src.model_checker.models.stack_frame import StackFrame
from src.exceptions import NonExistentStackFrame

ByteStateRepresentation = {
    0: "FREE",
    1: "CRITICAL",
    2: "OCCUPIED",
    3: "MODIFIED"
}

class MemoryState:
    """
    A memory state is the basic block for the stack memory space.
    
    It is a collection of stack frames, each representing the memory state of a function.
    It also contains a transition, which is the memory operator that led to the current state.
    """

    def __init__(self, stack_frames_map = None, instruction = None):
        if stack_frames_map is None:
            stack_frames_map = {}
        self.stack_frames_map = stack_frames_map
        # Save the index of the state in the state space
        self.index = None
        self.instruction = instruction

    def add_stack_frame(self, function_name, stack_frame: StackFrame):
        """
        Adds a stack frame to the memory state.

        Returns:
            MemoryState: A new memory state with the added stack frame.
        """
        new_stack_frames_map = self.stack_frames_map.copy()
        new_stack_frames_map[function_name] = stack_frame
        return MemoryState(new_stack_frames_map, self.instruction)

    def add_instruction(self, instruction):
        return MemoryState(self.stack_frames_map, instruction = instruction)

    def __get_stack_frame(self, function_name):
        """
        Returns the stack frame of the given function name.
        """
        return self.stack_frames_map[function_name]
    
    def get_stack_frame(self, function_name):
        """
        Returns a copy of the stack frame of the given function name.
        """
        try:
            return deepcopy(self.stack_frames_map[function_name])
        except KeyError:
            new_frame = StackFrame()
            new_frame.initialize()
            self.stack_frames_map[function_name] = new_frame
            return deepcopy(new_frame)
        except Exception as e:
            raise NonExistentStackFrame(f"Error {e} for stack frame {function_name}")
    
    def get_stack_frames(self):
        return self.stack_frames_map.values()
    
    def get_stack_frame_names(self):
        return self.stack_frames_map.keys()

    def contains_stack_frame(self, function_name):
        """
        Returns true if the memory state contains a stack frame for the given function name.
        """
        return function_name in self.stack_frames_map
    
    def draw(self):
        """
        Create an ASCII representation of multiple stacks with titles.
        """

        ascii_representation = ""

        # Determine the maximum height of the stacks for formatting
        max_stack_height = max(len(stack.stack_frame) for stack in self.stack_frames_map.values())

        # Create ASCII representation for each stack
        for title, stack_frame in self.stack_frames_map.items():
            ascii_representation += f"-- {title} --|"
            stack = stack_frame.stack_frame

            # For debugging
            # print(stack_frame.buffer_map)
            
            # Add each element of the stack
            for index, byte in enumerate(stack):
                ascii_representation += f"{index}: {ByteStateRepresentation[byte]}"
                if index == 7:
                    ascii_representation += " - rip"
                elif index - stack_frame.rbp + 1 in stack_frame.buffer_map:
                    ascii_representation += " - buffer"
                elif index == stack_frame.rbp - 1:
                    ascii_representation += " - rbp"

                elif stack_frame.canary_written and index == 15 + 8:
                    ascii_representation += " - canary"
                ascii_representation += "|"
            # Add padding for stacks shorter than the tallest one
            for _ in range(max_stack_height - len(stack)):
                ascii_representation += ""

            ascii_representation += ""

        return ascii_representation[:-1]
    
