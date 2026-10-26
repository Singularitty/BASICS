import os
import sys
import tempfile
import unittest

try:
    import rustworkx as rx
except ImportError as e:
    raise unittest.SkipTest("rustworkx is required for model checker tests") from e

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.model_checker.ltl_model_checker import LogicalCondition, ModelChecker
from src.model_checker.models.memory_state import MemoryState
from src.model_checker.models.stack_frame import StackFrame
from src.model_checker.models.state_space import StateSpace
from src.model_checker.models.byte_states import ByteState


class FakeInsn:
    def __init__(self, address=0x401000, mnemonic="nop", op_str=""):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str


class FakeInstruction:
    def __init__(self, address=0x401000, mnemonic="nop", op_str=""):
        self.insn = FakeInsn(address, mnemonic, op_str)
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str

    def __str__(self):
        return f"{self.mnemonic} {self.op_str}".strip()


def build_state_space(memory_state):
    temp_dir = tempfile.mkdtemp()
    state_space = StateSpace(temp_dir, "unit_test_binary")
    state_space.add_state(memory_state)
    return state_space


def build_memory_state(stack_frame, address=0x401000):
    instruction = FakeInstruction(address)
    return MemoryState({"main": stack_frame}, instruction=instruction)


def initialized_frame():
    frame = StackFrame()
    frame.initialize()
    return frame


def automaton_for_condition(condition_ast, accepting_target=True):
    automaton = rx.PyDiGraph(multigraph=False)
    automaton.add_node({"name": "init", "is_accepting": False})
    automaton.add_node({"name": "accept", "is_accepting": accepting_target})
    automaton.add_edge(0, 1, LogicalCondition(condition_ast, str(condition_ast)))
    return automaton


class ModelCheckerTests(unittest.TestCase):
    def test_accepting_property_has_no_violations(self):
        frame = initialized_frame()
        memory_state = build_memory_state(frame)
        state_space = build_state_space(memory_state)
        automata = {"always_true": automaton_for_condition(True)}

        checker = ModelChecker("unit_test_binary", state_space, automata, {0x401000: "main"})
        checker.state_space_transversal()
        report = checker.create_report()

        self.assertEqual(report.violations, {})

    def test_false_transition_records_violation(self):
        frame = initialized_frame()
        memory_state = build_memory_state(frame)
        state_space = build_state_space(memory_state)
        automata = {"always_false": automaton_for_condition(False)}

        checker = ModelChecker("unit_test_binary", state_space, automata, {0x401000: "main"})
        checker.state_space_transversal()
        report = checker.create_report()

        self.assertIn("always_false", report.violations)
        self.assertGreaterEqual(len(report.violations["always_false"]), 1)

    def test_stack_byte_predicate_can_be_checked(self):
        frame = initialized_frame()
        memory_state = build_memory_state(frame)
        state_space = build_state_space(memory_state)
        condition = {
            "COMPARISON": {
                "left": {
                    "FUNCTION": {
                        "name": "byte",
                        "args": [[
                            {
                                "FUNCTION": {
                                    "name": "stack",
                                    "args": [["main"]],
                                }
                            },
                            0,
                        ]],
                    }
                },
                "comparator": "==",
                "right": ByteState.CRITICAL,
            }
        }
        automata = {"return_address_is_critical": automaton_for_condition(condition)}

        checker = ModelChecker("unit_test_binary", state_space, automata, {0x401000: "main"})
        checker.state_space_transversal()
        report = checker.create_report()

        self.assertEqual(report.violations, {})

    def test_stack_byte_predicate_violation_is_reported(self):
        frame = initialized_frame()
        memory_state = build_memory_state(frame)
        state_space = build_state_space(memory_state)
        condition = {
            "COMPARISON": {
                "left": {
                    "FUNCTION": {
                        "name": "byte",
                        "args": [[
                            {
                                "FUNCTION": {
                                    "name": "stack",
                                    "args": [["main"]],
                                }
                            },
                            0,
                        ]],
                    }
                },
                "comparator": "==",
                "right": ByteState.FREE,
            }
        }
        automata = {"return_address_is_free": automaton_for_condition(condition)}

        checker = ModelChecker("unit_test_binary", state_space, automata, {0x401000: "main"})
        checker.state_space_transversal()
        report = checker.create_report()

        self.assertIn("return_address_is_free", report.violations)


class LoopOutOfBoundsWriteTests(unittest.TestCase):
    """Per-instruction rule used by the loop emulator to prove an overflow."""

    @staticmethod
    def leaves(objects, address, length, previous=None):
        from src.model_checker.state_space_constructor import StateSpaceConstructor
        return StateSpaceConstructor._StateSpaceConstructor__loop_write_leaves_object(objects, address, length, previous)

    def walk(self, objects, writes):
        previous = None
        for address, length in writes:
            violation = self.leaves(objects, address, length, previous)
            if violation is not None:
                return violation
            stride = address - previous[0] if previous is not None else None
            previous = (address, length, stride)
        return None

    def test_byte_walk_one_past_the_end_is_out_of_bounds(self):
        buffer = ("f", 100, 110)
        self.assertEqual(self.walk([buffer], [(100 + i, 1) for i in range(11)]), buffer)

    def test_walk_that_stays_inside_is_not_out_of_bounds(self):
        objects = [("f", 100, 110), ("f", 110, 121)]
        self.assertIsNone(self.walk(objects, [(110 + i, 1) for i in range(11)]))
        self.assertIsNone(self.walk(objects, [(100 + i, 1) for i in range(10)]))

    def test_walk_below_the_start_is_out_of_bounds(self):
        buffer = ("f", 100, 110)
        self.assertEqual(self.walk([buffer], [(109 - i, 1) for i in range(11)]), buffer)

    def test_store_straddling_a_boundary_is_out_of_bounds(self):
        buffer = ("f", 100, 110)
        self.assertEqual(self.leaves([buffer], 106, 8), buffer)

    def test_same_instruction_writing_unrelated_locals_is_not_out_of_bounds(self):
        # e.g. a helper called for buf[0..9] and for a separate counter
        buffer = ("f", 100, 110)
        writes = [(100 + i, 1) for i in range(10)] + [(140, 4), (100, 1), (140, 4)]
        self.assertIsNone(self.walk([buffer], writes))

    def test_constant_stride_walk_off_the_end_is_out_of_bounds(self):
        # first 4-byte field of each 8-byte struct of a 4-element array
        array = ("f", 0, 32)
        self.assertEqual(self.walk([array], [(8 * i, 4) for i in range(5)]), array)
        self.assertIsNone(self.walk([array], [(8 * i, 4) for i in range(4)]))


if __name__ == "__main__":
    unittest.main()
