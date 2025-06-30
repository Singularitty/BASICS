import src.global_vars as global_vars
import os
import re
import subprocess
import lark
import pickle
import rustworkx as rx

from lark import Transformer
from abc import ABC
from typing import List
from rustworkx.visualization import graphviz_draw

class Node(ABC):
    ...
        
class ConditionNode(Node):
    def __init__(self,condition: str):
        self.condition = condition
        
class TransitionNode(Node):
    def __init__(self, condition: ConditionNode, target: str):
        self.condition = condition
        self.target = target
        
class StateNode(Node):
    def __init__(self, name: str, transitions: List[TransitionNode]):
        self.name = name
        self.transitions = transitions

class NeverClaimNode(Node):
    def __init__(self, states: List[StateNode]):
        self.states = states
        
        
class AstTransformer(Transformer):
    
    def state_label(self, item) -> str:
        label = item[0].value
        return label
    
    def target_state(self, item) -> str:
        return item[0].value
    
    def condition(self, item) -> ConditionNode:
        return ConditionNode(item[0].value)
    
    def transition(self, items) -> TransitionNode:
        condition = items[:-1]
        target = items[-1]
        return TransitionNode(condition, target)
    
    def state(self, items) -> StateNode:
        name = items[0]
        transitions = items[1:]
        return StateNode(name, transitions)
    
    def start(self, items) -> NeverClaimNode:
        return NeverClaimNode(items)

class LogicTransformer(lark.Transformer):
    def or_expr(self, args):
        return {"OR": args}
    
    def and_expr(self, args):
        return {"AND": args}
    
    def not_expr(self, args):
        return {"NOT": args[0]}
    
    def true(self, _):
        return True
    
    def false(self, _):
        return False
    
    def NAME(self, name):
        return str(name)
    
    def NUMBER(self, number):
        return float(number)
    
    def function_call(self, args):
        name = args[0]
        arguments = args[1:] if len(args) > 1 else []
        return {"FUNCTION": {"name": name, "args": arguments}}
    
    def args(self, args):
        return list(args)
    
    def comparison_expr(self, args):
        left = args[0]
        comparator = args[1]
        right = args[2]
        return {"COMPARISON": {"left": left, "comparator": comparator, "right": right}}
    
    def forall_stack_expr(self, args):
        variable = args[0]
        expression = args[1]
        return {"FORALL_STACK": {"variable": variable, "expression": expression}}
    
    def exists_stack_expr(self, args):
        variable = args[0]
        expression = args[1]
        return {"EXISTS_STACK": {"variable": variable, "expression": expression}}
    
    def forall_buffer_expr(self, args):
        variable_stack = args[0]
        variable_buffer = args[1]
        expression = args[2]
        return {"FORALL_BUFFER": {"stack": variable_stack, "buffer": variable_buffer, "expression": expression}}
    
    def exists_buffer_expr(self, args):
        variable_stack = args[0]
        variable_buffer = args[1]
        expression = args[2]
        return {"EXISTS_BUFFER": {"stack": variable_stack, "buffer": variable_buffer, "expression": expression}}
    
    def eq(self, _):
        return "=="
    
    def neq(self, _):
        return "!="
    
    def lt(self, _):
        return "<"
    
    def let(self, _):
        return "<="
    
    def gt(self, _):
        return ">"
    
    def get(self, _):
        return ">="
    
    def plus(self, _):
        return "+"
    
    def minus(self, _):
        return "-"
    
    def times(self, _):
        return "*"
    
    def div(self, _):
        return "/"

class LogicalCondition:
    
    def __init__(self, ast, string: str):
        self.ast = ast
        self.string = string

class LinearTemporalLogicTranslator:
    proposition_pattern = r'\$([^$]+)\$'
    
    
    def __init__(self) -> None:
        self.directory = global_vars.SECURITY_PROPERTIES_DIR
        self.formulas = {}
        self.parsed_formulas = {}
        self.proposition_map = {}
        self.never_claims = {}
        self.compiled_formulas = {}
        self.automata = {}
        never_claim_lark = os.path.join(global_vars.LTL_MODULES_DIR, "never_claim.lark")
        propositions_lark = os.path.join(global_vars.LTL_MODULES_DIR, "propositions.lark")
        self.never_claim_parser = lark.Lark.open(never_claim_lark, start="start")
        self.propositions_parser = lark.Lark.open(propositions_lark, start="start")
        
    def find_formulas(self):
        for file in os.listdir(self.directory + "/ltl"):
            if file.endswith(".ltl"):
                with open (self.directory + "/ltl/" + file, "r") as f:
                    self.formulas[file[:-4]] = f.read().strip("\n")
        if os.path.isdir(self.directory + "/buchi_automata") and global_vars.RECOMPILE_LTL is False:
            for file in os.listdir(self.directory + "/buchi_automata"):
                if file.endswith(".pickle"):
                    key = os.path.basename(file).split(".")[0]
                    self.compiled_formulas[key] = self.load_automata(key)
    
    def map_propositions(self):
        for key, formula in self.formulas.items():
            if key not in self.compiled_formulas:
                matches = re.findall(self.proposition_pattern, formula)
                unique_propositions = list(dict.fromkeys(matches))
                if len(unique_propositions) > 0:
                    self.proposition_map[key] = {}
                    ltl_formula = formula
                    for i, prop in enumerate(unique_propositions):
                        new_prop = f'p_{i}'
                        ltl_formula = ltl_formula.replace(f'${prop}$', new_prop)
                        self.proposition_map[key][new_prop] = prop
                    self.parsed_formulas[key] = ltl_formula
                else:
                    assert False, "No propositions found in the formula, please enclose the propositions in $ $"
    
    def ltl2ba(self):
        buchi_dir = os.path.join(self.directory, "buchi_automata")
        os.makedirs(buchi_dir, exist_ok=True)
        for key, formula in self.parsed_formulas.items():
            if key not in self.compiled_formulas:
                # Execute ltl2ba command and capture its output
                result = subprocess.run(
                    ['ltl2ba', '-f', f'"{formula}"'],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self.never_claims[key] = result.stdout
                    # Save the output to a file
                    with open(os.path.join(buchi_dir, f"{key}.pml"), 'w', encoding='utf-8') as f:
                        f.write(result.stdout)
                else:
                    print(f"Error processing formula {key}: {result.stderr}")
                    self.never_claims[key] = f"Error: {result.stderr}"
                
    def convert_never_claims_to_automata(self):
        for key, never_claim in self.never_claims.items():
            if key not in self.compiled_formulas:
                if 'Error' in never_claim:
                    continue  # Skip if there was an error in ltl2ba output
                
                tree = self.never_claim_parser.parse(never_claim)
                ast = AstTransformer().transform(tree)
                automata = self.__create_automata(ast, key)
                self.automata[key] = automata
                self.save_automata(key, automata)
                graphviz_draw(automata, node_attr_fn=self.__node_attr_fn, edge_attr_fn=self.__edge_attr_fn, image_type="pdf", filename=os.path.join(self.directory + "/buchi_automata/", f"{key}.pdf"))
            else:
                self.automata[key] = self.compiled_formulas[key]
                
    def save_automata(self, key: str, automata: rx.PyDiGraph): # pylint: disable=no-member
        with open(os.path.join(self.directory + "/buchi_automata/", f"{key}.pickle"), 'wb') as f:
            pickle.dump(automata, f)
        
        
    def load_automata(self, key: str):
        with open(os.path.join(self.directory + "/buchi_automata/", f"{key}.pickle"), 'rb') as f:
            automata = pickle.load(f)
        return automata
    
    def load_all_automata(self):
        for key in self.formulas.keys():
            self.automata[key] = self.load_automata(key)
            
    def __create_automata(self, ast: NeverClaimNode, key: str):
        automata = rx.PyDiGraph(multigraph=False)  # pylint: disable=no-member
        state_indices = {}  # Mapping of state names to their node indices

        for state in ast.states:
            if state.name in state_indices:
                index = state_indices[state.name]
            else:
                index = automata.add_node({"name": state.name, "is_accepting": "accept" in state.name})
                state_indices[state.name] = index
                #print(f"Adding state {state.name} to the automata")

            for transition in state.transitions:
                if transition.target in state_indices:
                    target = state_indices[transition.target]
                    #print(f"State {transition.target} already exists in the automata")
                else:
                    target = automata.add_node({"name": transition.target, "is_accepting": "accept" in transition.target})
                    state_indices[transition.target] = target
                    #print(f"Adding state {transition.target} to the automata")

                condition = transition.condition[0].condition
                condition = self.__replace_propositions(condition, key)
                tree = self.propositions_parser.parse(condition)
                condition_ast = LogicTransformer().transform(tree)
                # Save the AST and the string, in order to draw the automata for debugging
                automata.add_edge(index, target, LogicalCondition(condition_ast, condition))

        return automata
    
    def __replace_propositions(self, formula: str, key: str):
        for prop, new_prop in self.proposition_map[key].items():
            formula = formula.replace(prop, "(" + new_prop + ")")
        return formula
    
    def __node_attr_fn(self, node):
        representation = node["name"]
        if node["is_accepting"]:
            return {
                "shape": 'doublecircle',
                "label": representation,
                "fontname" : "Courier"
            }
        return {
            "shape": 'circle',
            "label": representation,
            "fontname" : "Courier"
        }
        
    def __edge_attr_fn(self, edge: LogicalCondition):
        return {
            "label": edge.string,
            "fontname" : "Courier"
            }