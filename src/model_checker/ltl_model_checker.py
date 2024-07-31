import lark.reconstruct
import rustworkx as rx
import lark

from typing import Dict, Set, List

from src import global_vars
from src.exceptions import InvalidLTLFormulaException, NonExistentByte, NonExistentStackFrame, NonExistentBufferMap
from src.model_checker.models.state_space import StateSpace
from src.model_checker.models.memory_state import MemoryState
from src.model_checker.models.stack_frame import StackFrame
from src.model_checker.models.memory_transitions import MemoryTransition
from src.security_property_converter.ltl_translator import LogicalCondition

class Evaluator:
    
    def __init__(self, state_space_pointer: StateSpace):
        self.state_space = state_space_pointer
        self.memory_state = None
        self.violated_properties = {}  # Dictionary to track violated properties per stack frame
        self.functions = {
            "stack": self.stack,
            "byte": self.byte,
            "previous_transition": self.previous_transition,
            "buffer": self.buffer,
            "get_buffer_map": self.get_buffer_map,
            "start": self.start,
            "end": self.end,
            "has_canary": self.has_canary
        }
        
    def set_state_pointer(self, state_pointer: MemoryState):
        self.memory_state = state_pointer

    def remove_state_pointer(self):
        self.memory_state = None

    def eval(self, ast, context):
        if isinstance(ast, lark.Tree):
            return self.eval(ast.children[0], context)
        elif isinstance(ast, bool):
            return ast
        elif isinstance(ast, (int, float)):
            return int(ast)
        elif isinstance(ast, str):
            if ast in context:
                return context[ast]
            return ast
        elif isinstance(ast, dict):
            if "OR" in ast:
                results = [self.eval(sub_ast, context) for sub_ast in ast["OR"]]
                if any(result is None for result in results):
                    return None
                return any(results)
            elif "AND" in ast:
                results = [self.eval(sub_ast, context) for sub_ast in ast["AND"]]
                if any(result is None for result in results):
                    return None
                return all(results)
            elif "NOT" in ast:
                result = self.eval(ast["NOT"], context)
               # print(result)
                return not result
            elif "COMPARISON" in ast:
                left = self.eval(ast["COMPARISON"]["left"], context)
                comparator = ast["COMPARISON"]["comparator"]
                right = self.eval(ast["COMPARISON"]["right"], context)
                #print(left, comparator, right)
                if left is None or right is None:
                    return None
                elif comparator == "==":
                    return left == right
                elif comparator == "!=":
                    return left != right
                elif comparator == "<":
                    return left < right
                elif comparator == "<=":
                    return left <= right
                elif comparator == ">":
                    return left > right
                elif comparator == ">=":
                    return left >= right
                elif comparator == "-":
                    return left - right
                elif comparator == "+":
                    return left + right
                elif comparator == "*":
                    return left * right
                elif comparator == "/":
                    return left / right
            elif "FUNCTION" in ast:
                func_name = ast["FUNCTION"]["name"]
                args = [self.eval(arg, context) for arg in ast["FUNCTION"]["args"][0]]
                #print(args)
                if any(arg is None for arg in args):
                    #print("None argument in function call")
                    return None
                try:
                    result = self.functions[func_name](*args)
                    #print(result)
                    return result
                except NonExistentByte:
                    return None
                except NonExistentStackFrame:
                    #print("Non existent stack frame")
                    return None
                except NonExistentBufferMap:
                    return None
            elif "FORALL_STACK" in ast:
                variable = ast["FORALL_STACK"]["variable"]
                expression = ast["FORALL_STACK"]["expression"]
                if self.memory_state:
                    stack_frames = self.memory_state.get_stack_frame_names()
                    results = []
                    for stack in stack_frames:
                        if not(stack in self.violated_properties and context['property_key'] in self.violated_properties[stack]):
                            results.append(self.eval(expression, {**context, variable: stack, "stack_frame": stack}))
                    if len(results) == 0:
                        return None
                    if any(result is None for result in results):
                        return None
                    return all(results)
            elif "EXISTS_STACK" in ast:
                variable = ast["EXISTS_STACK"]["variable"]
                expression = ast["EXISTS_STACK"]["expression"]
                if self.memory_state:
                    stack_frames = self.memory_state.get_stack_frame_names()
                    results = []
                    for stack in stack_frames:
                        if not(stack in self.violated_properties and context['property_key'] in self.violated_properties[stack]):
                            results.append(self.eval(expression, {**context, variable: stack, "stack_frame": stack}))
                    if len(results) == 0:
                        return None
                    if any(result is None for result in results):
                        return None
                    return any(results)
            elif "FORALL_BUFFER" in ast:
                stack_frame_variable = ast["FORALL_BUFFER"]["stack"]
                buffer_variable = ast["FORALL_BUFFER"]["buffer"]
                expression = ast["FORALL_BUFFER"]["expression"]
                if stack_frame_variable in context:
                    stack_frame_id = context[stack_frame_variable]
                    stack_frame = self.memory_state.get_stack_frame(stack_frame_id)
                    if isinstance(stack_frame, StackFrame):
                        buffer_ids = stack_frame.get_buffer_ids()
                        if len(buffer_ids) == 0:
                            return None
                        results = []
                        for buffer_id in buffer_ids:
                            if not(stack_frame in self.violated_properties and context['property_key'] in self.violated_properties[stack_frame]):
                                results.append(self.eval(expression, {**context, buffer_variable: buffer_id}))
                        if len(results) == 0:
                            return None
                        if any(result is None for result in results):
                            return None
                        return all(results)
            elif "EXISTS_BUFFER" in ast:
                stack_frame_variable = ast["FORALL_BUFFER"]["stack"]
                buffer_variable = ast["FORALL_BUFFER"]["buffer"]
                expression = ast["FORALL_BUFFER"]["expression"]
                if stack_frame_variable in context:
                    stack_frame_id = context[stack_frame_variable]
                    stack_frame = self.memory_state.get_stack_frame(stack_frame_id)
                    if isinstance(stack_frame, StackFrame):
                        buffer_ids = stack_frame.get_buffer_ids()
                        if len(buffer_ids) == 0:
                            return None
                        results = []
                        for buffer_id in buffer_ids:
                            if stack_frame in self.violated_properties and context['property_key'] in self.violated_properties[stack_frame]:
                                continue
                            results.append(self.eval(expression, {**context, buffer_variable: buffer_id}))
                        if len(results) == 0:
                            return None
                        if any(result is None for result in results):
                            return None
                        return any(results)
        return None

    # Functions to reason about the state space

    def stack(self, stack_id: str) -> StackFrame:
        """
        Returns the stack frame of the given stack id.
        """
        #print(stack_id)
        if not isinstance(stack_id, str):
            raise InvalidLTLFormulaException("Invalid stack idenfifier used in the Stack() function.")
        return self.memory_state.get_stack_frame(stack_id)

    def byte(self, stack_frame: StackFrame, offset: int) -> int:
        """
        Returns the byte at the given offset in the stack frame.
        """
        if not isinstance(offset, int):
            raise InvalidLTLFormulaException(f"Invalid offset ({offset}) used in the Byte() function.")
        if not isinstance(stack_frame, StackFrame):
            if not isinstance(stack_frame, str):
                raise InvalidLTLFormulaException("Invalid stack frame identifier used in the Byte() function.")
            else:
                stack_frame = self.memory_state.get_stack_frame(stack_frame)
        return stack_frame.get_byte_state(offset)

    def previous_transition(self) -> MemoryTransition:
        """
        Returns the previous transition of the state.
        """
        edge_data = self.state_space.graph.in_edges(self.memory_state.index) # List[Tuple(parent_index, node_index, edge_data)]
        if len(edge_data) == 0:
            return None
        return edge_data[0][2].__str__().replace(" ", "_")
    
    def buffer(self, stack_frame, buffer_id: str) -> List[int]:
        """
        Returns the buffer of the given buffer id.
        
        buffer_id is the offset of the buffer on the stack, what this returns is the size of the buffer in the stack
        """
        if not isinstance(buffer_id, int):
            raise InvalidLTLFormulaException("Invalid buffer idenfifier used in the Buffer() function.")
        stack_frame = self.memory_state.get_stack_frame(stack_frame)
        if not isinstance(stack_frame, StackFrame):
            raise InvalidLTLFormulaException("Invalid stack frame used in the Buffer() function.")
        return stack_frame.get_buffer(buffer_id), buffer_id
    
    def start(self, buffer) -> int:
        """
        Returns the start offset of the buffer.
        """
        return abs(buffer[1]) + 15
    
    def end(self, buffer) -> int:
        """
        Returns the end offset of the buffer.
        """
        return buffer[1] + 16 - buffer[0]
    
    def get_buffer_map(self, stack_frame: StackFrame) -> Dict[str, List[int]]:
        """
        Returns a map of buffer names to their contents for the given stack frame.
        """
        buffer_map = {}
        buffer_map = stack_frame.buffer_map
        if not buffer_map:
            raise NonExistentBufferMap("No buffer map found in the stack frame.")
        buffer_ids = stack_frame.buffer_map.keys()
        for buffer_id in buffer_ids:
            buffer_map[buffer_id] = self.buffer(stack_frame, buffer_id)
        return buffer_map
    
    def has_canary(self, stack_frame: StackFrame) -> bool:
        """
        Returns True if the stack frame has a canary.
        """
        s = self.memory_state.get_stack_frame(stack_frame)
        result = False if s.canary_written is None else s.canary_written
        return result

class ExecutionTrace:

    def __init__(self, properties: List[str]) -> None:
        self.trace = []
        self.properties = properties
        self.buchi_states = {}

    def add_transition(self, instruction, memory_state):
        """
        Adds a transition to the execution trace.
        """
        self.trace.append((instruction, memory_state))

    def transition_buchi_state(self, key: str, next_buchi_state: int):
        """
        Transitions the Büchi automaton state.
        """
        self.buchi_states[key] = next_buchi_state

    def copy(self):
        new_trace = ExecutionTrace(self.properties)
        new_trace.trace = self.trace.copy()
        new_trace.buchi_states = self.buchi_states.copy()
        return new_trace
        
    def __str__(self):
        trace_str = ""
        trace_str += "\n".join([f"{instr[0]}" for instr in self.trace])
        #trace_str += "\n\nBüchi States:\n"
        #trace_str += "\n".join([f"{key}: {state}" for key, state in self.buchi_states.items()])
        return trace_str

class PropertyViolation:
    
    def __init__(self, property_key: str, trace: ExecutionTrace):
        self.counter_example_trace = trace
        self.property = property_key

class ModelCheckingReport:
    
    def __init__(self, binary_name, security_properties, violations):
        self.binary_name = binary_name
        self.security_properties = security_properties
        self.violations = violations
        self.execution_time = None
        
    def set_execution_time(self, time: float):
        self.execution_time = time
        
    def emit(self):
        """
        Emits the report of the model checking.
        """
        report = "------ Model Checking Report ------\n\n"
        report += f"File: {self.binary_name}\n\n"

        report += "Verified Security Properties:\n"
        for prop in self.security_properties.keys():
            if prop not in self.violations.keys():
                report += f"  - {prop}\n"
        report += "\n"

        if not self.violations:
            report += "No security property violations found.\n"
        else:
            report += "Found security property violations:\n\n"
            for prop, violations in self.violations.items():
                report += f"Property: {prop}\n\n"
                for violation in violations:
                    report += "Counterexample Trace:\n"
                    report += f"{str(violation.counter_example_trace)}\n"
                    report += "\n"
            report += f"{sum(len(v) for v in self.violations.values())} security property violations found.\n"

        report += f"\nExecution Time: {self.execution_time} seconds\n"
        report_path = global_vars.REPORTS_DIR + "/" + self.binary_name + "/" + self.binary_name + "_report.txt"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
            
        report += "\n------ End of Report ------\n"
        report += f"\nWrote report to {report_path}\n"
        
        print(report)


class ModelChecker:

    def __init__(self, binary_name: str, state_space: StateSpace, security_properties: Dict[str, rx.PyDiGraph], address_map): # pylint: disable=no-member
        self.binary_name = binary_name
        self.state_space = state_space
        self.security_properties = security_properties

        self.split_points = {}
        self.final_traces = []
        self.violations = {}
        
        self.evaluator = Evaluator(state_space)
        self.violation_frames = {prop: set() for prop in security_properties.keys()}

        self.default_context = {"Free" : 0, "Critical" : 1, "Occupied" : 2, "Modified" : 3}
        
        self.address_map = address_map

    def check_security_properties(self, state: MemoryState, trace: ExecutionTrace) -> bool:
        """
        Checks the security properties against the state space.
        """
        violation_found = False
        for property_key in self.security_properties.keys():
            self.evaluator.set_state_pointer(state)
            result = self.__update_buchi_state(trace, property_key, state)
            current_stack_frame = self.address_map[trace.trace[-1][0].insn.address] # determine which stack frame the current instruction belongs to
            if result is not None and not result:
                violation_trace = trace.copy()
                if property_key in self.violations:
                    self.violations[property_key].append(PropertyViolation(property_key, violation_trace))
                else:
                    self.violations[property_key] = [PropertyViolation(property_key, violation_trace)]
                # Don't add the same violation twice for the same stack frame
                if current_stack_frame not in self.evaluator.violated_properties:
                        self.evaluator.violated_properties[current_stack_frame] = set()
                self.evaluator.violated_properties[current_stack_frame].add(property_key)
                violation_found = True
        return violation_found
                    

    def state_space_transversal(self, method: str = "dfs"):
        """
        Transverses the state space.
        """
        source_state = self.__find_source_state()
        if method == "dfs":
            visited = set()
            self.__dfs_traversal(source_state, visited, ExecutionTrace(self.security_properties.keys()))
        elif method == "bfs":
            raise NotImplementedError("BFS traversal not implemented yet.")
        else:
            raise ValueError("Invalid search method please use 'dfs' or 'bfs'")
        return self.final_traces

    def __update_buchi_state(self, trace: ExecutionTrace, property_key: str, state: MemoryState):
        """
        Updates the Büchi automaton state of the property.
        """
        if property_key not in trace.buchi_states:
            trace.buchi_states[property_key] = 0
        buchi_state = trace.buchi_states[property_key]

        # Get the Büchi automaton of the property
        buchi_automaton = self.security_properties[property_key]
        transitions = buchi_automaton.out_edges(buchi_state)
        # Evaluate the transitions
        for transition in transitions:
            #print(transition)
            condition = transition[2].ast
            context = {**self.default_context, "property_key": property_key}
            result = self.evaluator.eval(condition, context)
            #print(property_key, result, '\n', condition)
            if result:  # Check for None before evaluating to True
                trace.transition_buchi_state(property_key, transition[1])
                return True
            if result is None:
                return None
        return False


    def __find_buchi_entry(self, property_key: str):
        """
        Finds the entry state of the Büchi automaton.
        """
        buchi_automaton = self.security_properties[property_key]
        for node in buchi_automaton.nodes():
            if "init" in node:
                return node
        raise ValueError("Entry point not found in the Büchi automaton")

    def __dfs_traversal(self, current_state_index, visited: Set, trace: ExecutionTrace):
        """
        Performs DFS traversal from the current state.
        """
        if current_state_index in visited:
            return

        # Process the current state
        current_state = self.state_space.graph[current_state_index]
        trace.add_transition(current_state.instruction, current_state)
        violation_found = self.check_security_properties(current_state, trace)
        visited.add(current_state_index)

        neighbors = list(self.state_space.graph.neighbors(current_state_index))

        if not neighbors:
            accepting, key = self.__is_accepting_state(trace)
            self.final_traces.append(trace.copy())
            if not accepting:
                violation_trace = trace.copy()
                violation_trace.add_transition(current_state.instruction, current_state)
                if key in self.violations:
                    self.violations[key].append(PropertyViolation(key, violation_trace))
                else:
                    self.violations[key] = [PropertyViolation(key, violation_trace)]

        for neighbor in neighbors:
            if neighbor not in visited:
                new_trace = trace.copy()
                self.__dfs_traversal(neighbor, visited, new_trace)

    def __is_accepting_state(self, trace: ExecutionTrace):
        """
        Checks if the end of the trace is at an accepting state for all properties.
        """
        for property_key in self.security_properties.keys():
            buchi_automaton = self.security_properties[property_key]
            buchi_state = trace.buchi_states[property_key]
            return (buchi_automaton[buchi_state]["is_accepting"], property_key)

    def __find_source_state(self):
        """
        Finds the source state in the state space.
        """
        source_node = None
        for node in self.state_space.graph.nodes():
            if len(self.state_space.graph.in_edges(node.index)) == 0:
                source_node = node.index
                break
        assert source_node is not None, "Entry point not found in the state space"

        return source_node
        
    def create_report(self) -> ModelCheckingReport:
        return ModelCheckingReport(self.binary_name, self.security_properties, self.violations)
