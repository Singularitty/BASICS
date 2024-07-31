import sys, os
import argparse
import json
from timeit import default_timer as timer
# User modules
# Fixes import errors
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import src.global_vars as global_vars
from src.binary_data_extractor.core import BinaryDataExtractor
from src.model_checker.state_space_constructor import StateSpaceConstructor
from src.security_property_converter.ltl_translator import LinearTemporalLogicTranslator
from src.model_checker.ltl_model_checker import ModelChecker
from src.vulnerability_identifier_removal.identifier import Identifier
from src.vulnerability_identifier_removal.patcher import Patcher
from src.vulnerability_identifier_removal.validator import Validator


def get_arguments():
    
    parser = argparse.ArgumentParser(description='Model Check Security properties of a binary programs stack memory.')

    parser.add_argument('--debug', action='store_true', help='Enable debugging messages')

    parser.add_argument('--no-recompilation-ltl', action='store_true', help='Do not recompile any found LTL formulas')

    parser.add_argument('--draw-cfg', action='store_true', help='Draw a control flow graph (CFG) of the binary program')

    parser.add_argument('--draw-state-space', action='store_true', help='Draw the state space of the binary program')

    parser.add_argument('--static', action='store_true', help='Do no build emulated cfg (NOT RECOMENDED)')
    
    parser.add_argument('--no-patching', action='store_true', help='Do not patch the binary')

    parser.add_argument('--max-iterations', type=int, help='Maximum number of iterations for the model checker', default=20)
    
    parser.add_argument('--angr-option', type=str, help='Option for angr simulation, static/fastpath are faster but worse', default=None)

    # Regular required argument for the binary path
    parser.add_argument('binary_path', type=str, help='Path to the binary file')

    return parser.parse_args()

def setup_workspace(binary_path: str):
    current_directory = global_vars.DIRECTORY
    os.makedirs(current_directory + "/security_properties", exist_ok=True)
    os.makedirs(current_directory + "/security_properties/ltl", exist_ok=True)
    os.makedirs(current_directory + "/security_properties/buchi_automata", exist_ok=True)
    os.makedirs(current_directory + "/reports", exist_ok=True)

    binary_name = os.path.basename(binary_path)
    
    os.makedirs(current_directory + "/reports/" + binary_name, exist_ok=True)

    try:
        os.remove(current_directory + "/reports/" + binary_name + "/concolic_inputs.txt")
    except FileNotFoundError:
        pass

    return current_directory, binary_name

def main():
    
    args: argparse.ArgumentParser = get_arguments()
    current_dir, binary_name = setup_workspace(args.binary_path)
    
    global_vars.BINARY_NAME = binary_name
    
    if args.debug:
        print("Debugging enabled\n")
        global_vars.DEBUG = True
        
    if args.angr_option is not None:
        global_vars.ANGR_OPTION = args.angr_option
    
    # Security Property Converter Module
    
    if not args.no_recompilation_ltl:
        print("Compiling LTL formulas\n")
        global_vars.RECOMPILE_LTL = True
    ltl = LinearTemporalLogicTranslator()
    ltl.find_formulas()
    ltl.map_propositions()
    ltl.ltl2ba()
    ltl.convert_never_claims_to_automata()

    
    security_properties = ltl.automata
    
    emulated_cfg = True
    if args.static:
        emulated_cfg = False
    
    start = timer()
    
    # Binary Data Extractor Module
    print("Extracting binary data\n")
    binary_data = BinaryDataExtractor(args.binary_path, emulated_cfg)
    
    if args.draw_cfg:
        binary_data.draw_binary_cfg()
    
    # Model Checker Module
    
    # Construct the state space
    print("Constructing state space\n")
    constructor = StateSpaceConstructor(binary_data, binary_name, current_dir, args.binary_path, args.max_iterations)
    constructor.construct_state_space()
    
    if args.draw_state_space:
        constructor.state_space.draw()
    
    # Model check the state space
    print("Performing model checking\n")
    model_checker = ModelChecker(binary_name, constructor.state_space, security_properties, binary_data.address_to_function)
    model_checker.state_space_transversal()
    
    report = model_checker.create_report()
    
    end = timer()
    report.set_execution_time(end - start)
    report.emit()

    
    
    
    
    # Identify Vulnerabilities
    vuln_identifier = Identifier(report, binary_data.cfg)
    
    sinks = vuln_identifier.find_vulnerability()
    
    # Patch the binary
    if args.no_patching:
        return
    patcher = Patcher(binary_data, sinks)
    patched_binary = patcher.patch()

    if patched_binary is not None:
        validator = Validator(args.binary_path)
        validator.validate()
    
    # Check if the patched binary is vulnerable
    #patched_binary_data = BinaryDataExtractor(patched_binary)
    #patched_constructor = StateSpaceConstructor(patched_binary_data, binary_name, current_dir, patched_binary)
    #patched_constructor.construct_state_space()
    #patched_binary_model_checker = ModelChecker(binary_name, patched_constructor.state_space, security_properties)
    #patched_binary_model_checker.state_space_transversal()
    #patched_report = patched_binary_model_checker.create_report()
    #patched_report.emit()
    
if __name__ == "__main__":
    main()