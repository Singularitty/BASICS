import sys, os
import argparse
import json
import shutil
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

    parser.add_argument('--cfg-mode', choices=['auto', 'emulated', 'fast'], default='auto',
                        help='CFG construction mode. auto uses CFGFast for large binaries.')
    
    parser.add_argument('--no-patching', action='store_true', help='Do not patch the binary')

    parser.add_argument('--no-check-patched', action='store_true', help='Do not model check the E9-patched binary')

    parser.add_argument('--inspect-patch-only', type=str, default=None,
                        help='Inspect an existing patched binary against binary_path and exit.')

    parser.add_argument('--max-iterations', type=int, help='Maximum number of iterations for the model checker', default=20)

    parser.add_argument('--max-states', type=int, help='Maximum number of memory states to construct before stopping', default=None)
    
    parser.add_argument('--angr-option', type=str, help='Option for angr simulation, static/fastpath are faster but worse', default=None)

    parser.add_argument('--function-simulation', choices=['auto', 'static', 'angr'], default='auto',
                        help='How to model supported C library calls. auto uses static effects first and falls back to angr.')
    parser.add_argument('--patched-function-simulation', choices=['auto', 'static', 'angr'], default='angr',
                        help='How to model C library calls when re-checking the patched binary.')

    parser.add_argument('--concolic-step-limit', type=int, default=10000,
                        help='Maximum angr steps when searching for a loop or call site.')

    parser.add_argument('--concolic-active-limit', type=int, default=64,
                        help='Maximum active angr states kept during concolic exploration.')

    parser.add_argument('--ltl-backend', choices=['spot', 'ltl2ba', 'auto'], default='auto',
                        help='LTL-to-Buchi backend. spot uses Spot Python bindings; auto falls back to ltl2ba.')

    parser.add_argument('--analysis-entry', choices=['main', 'loader'], default='main',
                        help='Start model checking at main or at the ELF loader entry point.')

    parser.add_argument('--patched-analysis-entry', choices=['main', 'loader'], default='main',
                        help='Start patched-binary model checking at main or at the ELF loader entry point. '
                             'loader follows E9 entry trampolines.')

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

def emit_binary_load_summary(binary_data, label):
    summary = binary_data.loader_summary()
    fingerprint = binary_data.fingerprint
    print(f"{label.capitalize()} binary fingerprint:")
    print(f"  path: {fingerprint['path']}")
    print(f"  size: {fingerprint['size']}")
    print(f"  sha256: {fingerprint['sha256']}")
    print(f"{label.capitalize()} angr loader summary:")
    print(f"  mapped_base: {hex(summary['mapped_base'])}")
    print(f"  min_addr: {hex(summary['min_addr'])}")
    print(f"  max_addr: {hex(summary['max_addr'])}")
    print(f"  entry: {hex(summary['entry'])}")
    print(f"  analysis_entry: {summary['analysis_entry']} ({hex(summary['analysis_entry_addr'])})")
    print(f"  sections: {summary['sections']}")
    print(f"  segments: {summary['segments']}")
    print(f"  functions: {summary['functions']}\n")

def compare_binary_loads(original_data, patched_data):
    same_hash = original_data.fingerprint["sha256"] == patched_data.fingerprint["sha256"]
    if same_hash:
        print("WARNING: Original and patched binaries have the same SHA-256. E9 may not have changed the output file.\n")
    else:
        print("Original and patched binary hashes differ; angr loaded a distinct patched artifact.\n")

def executable_segments(binary_data):
    segments = []
    main_object = binary_data.project.loader.main_object
    for segment in main_object.segments:
        if not getattr(segment, "is_executable", False):
            continue
        segments.append({
            "min_addr": int(segment.min_addr),
            "max_addr": int(segment.max_addr),
            "offset": int(getattr(segment, "offset", 0) or 0),
            "filesize": int(getattr(segment, "filesize", 0) or 0),
            "memsize": int(getattr(segment, "memsize", 0) or 0),
        })
    return segments

def ranges_overlap(left, right):
    return left["min_addr"] <= right["max_addr"] and right["min_addr"] <= left["max_addr"]

def segment_contains(segment, address):
    return segment["min_addr"] <= address <= segment["max_addr"]

def inspect_patch_mappings(original_data, patched_data):
    original_exec = executable_segments(original_data)
    patched_exec = executable_segments(patched_data)
    added_exec = [
        segment for segment in patched_exec
        if not any(ranges_overlap(segment, original) for original in original_exec)
    ]

    print("Patch mapping inspection:")
    if original_data.project.entry != patched_data.project.entry:
        print(f"  entry changed: {hex(original_data.project.entry)} -> {hex(patched_data.project.entry)}")
    else:
        print(f"  entry unchanged: {hex(patched_data.project.entry)}")

    if not added_exec:
        print("  no added executable mappings detected by angr\n")
        return

    print(f"  added executable mappings: {len(added_exec)}")
    for segment in added_exec:
        entry_marker = " contains patched entry" if segment_contains(segment, patched_data.project.entry) else ""
        print(
            "  candidate trampoline/mapping:"
            f" vaddr={hex(segment['min_addr'])}-{hex(segment['max_addr'])}"
            f" file_offset={hex(segment['offset'])}"
            f" file_size={segment['filesize']}"
            f" mem_size={segment['memsize']}"
            f"{entry_marker}"
        )
    print()

def compare_binary_bytes(original_path, patched_path, max_regions=16):
    with open(original_path, "rb") as f:
        original = f.read()
    with open(patched_path, "rb") as f:
        patched = f.read()

    print("Raw file comparison:")
    print(f"  original size: {len(original)}")
    print(f"  patched size: {len(patched)}")
    regions = []
    index = 0
    shared_size = min(len(original), len(patched))
    while index < shared_size and len(regions) < max_regions:
        if original[index] == patched[index]:
            index += 1
            continue
        start = index
        while index < shared_size and original[index] != patched[index]:
            index += 1
        regions.append(("replace", start, index, start, index))
    if len(original) != len(patched) and len(regions) < max_regions:
        regions.append(("resize", shared_size, len(original), shared_size, len(patched)))
    if not regions:
        print("  no raw byte differences found\n")
        return

    print(f"  first differing regions: {len(regions)}")
    for tag, i1, i2, j1, j2 in regions[:max_regions]:
        print(f"  {tag}: original[{i1}:{i2}] -> patched[{j1}:{j2}]")
    if len(regions) > max_regions:
        print(f"  ... {len(regions) - max_regions} more differing regions omitted")
    print()

def inspect_patched_sites(sinks, patched_data):
    print("Patched-site inspection:")
    for sink in sinks:
        try:
            block = patched_data.project.factory.block(sink.address, num_inst=1)
            insns = block.capstone.insns
        except Exception as e:
            print(f"  {hex(sink.address)}: angr could not disassemble patched site ({e})")
            continue
        if not insns:
            print(f"  {hex(sink.address)}: no instruction decoded")
            continue
        patched_ins = insns[0]
        original = f"{sink.instruction.mnemonic} {sink.instruction.op_str}".strip()
        patched = f"{patched_ins.mnemonic} {patched_ins.op_str}".strip()
        if patched_ins.mnemonic == sink.instruction.mnemonic and patched_ins.op_str == sink.instruction.op_str:
            print(f"  {hex(sink.address)}: unchanged ({patched})")
        else:
            print(f"  {hex(sink.address)}: {original} -> {patched}")
    print()

def inspect_existing_patch(original_path, patched_path, args):
    original_data = BinaryDataExtractor(original_path, args.cfg_mode == "emulated", args.cfg_mode, args.analysis_entry)
    patched_data = BinaryDataExtractor(patched_path, args.cfg_mode == "emulated", args.cfg_mode, args.patched_analysis_entry)
    emit_binary_load_summary(original_data, "original")
    emit_binary_load_summary(patched_data, "patched")
    compare_binary_loads(original_data, patched_data)
    inspect_patch_mappings(original_data, patched_data)
    compare_binary_bytes(original_data.binary, patched_data.binary)

def analyze_binary(binary_path, security_properties, args, label=None, analysis_entry=None):
    current_dir, binary_name = setup_workspace(binary_path)
    global_vars.BINARY_NAME = binary_name
    if label:
        print(f"Analyzing {label} binary: {binary_path}\n")

    emulated_cfg = args.cfg_mode == "emulated"
    if args.static:
        emulated_cfg = False
        cfg_mode = "fast"
    else:
        cfg_mode = args.cfg_mode
    analysis_entry = analysis_entry or args.analysis_entry

    start = timer()

    # Binary Data Extractor Module
    print("Extracting binary data\n")
    binary_data = BinaryDataExtractor(binary_path, emulated_cfg, cfg_mode, analysis_entry)
    previous_analysis_start = global_vars.ANALYSIS_START_ADDR
    global_vars.ANALYSIS_START_ADDR = binary_data.analysis_entry_addr
    emit_binary_load_summary(binary_data, label or "target")

    try:
        if args.draw_cfg:
            binary_data.draw_binary_cfg()

        # Model Checker Module

        # Construct the state space
        print("Constructing state space\n")
        constructor = StateSpaceConstructor(binary_data, binary_name, current_dir, binary_path, args.max_iterations, args.max_states)
        constructor.construct_state_space()

        if args.draw_state_space:
            constructor.state_space.draw()

        # Model check the state space
        print("Performing model checking\n")
        model_checker = ModelChecker(binary_name, constructor.state_space, security_properties, binary_data.address_to_function)
        model_checker.state_space_transversal()

        report = model_checker.create_report()
    finally:
        global_vars.ANALYSIS_START_ADDR = previous_analysis_start

    end = timer()
    report.set_execution_time(end - start)
    report.emit()
    return binary_data, report

def main():
    
    args: argparse.ArgumentParser = get_arguments()
    current_dir, binary_name = setup_workspace(args.binary_path)
    
    global_vars.BINARY_NAME = binary_name
    
    if args.debug:
        print("Debugging enabled\n")
        global_vars.DEBUG = True
        
    if args.angr_option is not None:
        global_vars.ANGR_OPTION = args.angr_option

    global_vars.FUNCTION_SIMULATION = args.function_simulation
    global_vars.CONCOLIC_STEP_LIMIT = args.concolic_step_limit
    global_vars.CONCOLIC_ACTIVE_LIMIT = args.concolic_active_limit
    global_vars.LTL_BACKEND = args.ltl_backend

    if args.inspect_patch_only is not None:
        inspect_existing_patch(args.binary_path, args.inspect_patch_only, args)
        return

    if not args.no_patching and shutil.which("e9tool") is None:
        raise RuntimeError(
            "Patching is enabled but e9tool is not available in PATH. "
            "Install E9Patch (./install_arch.sh) and rerun with ./run_basics.sh, "
            "or pass --no-patching."
        )
    
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
    
    binary_data, report = analyze_binary(args.binary_path, security_properties, args, "original", args.analysis_entry)
    
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

        if not args.no_check_patched:
            print("Model checking patched binary\n")
            original_simulation = global_vars.FUNCTION_SIMULATION
            try:
                global_vars.FUNCTION_SIMULATION = args.patched_function_simulation
                print(f"Patched binary function simulation mode: {global_vars.FUNCTION_SIMULATION}\n")
                patched_data, patched_report = analyze_binary(
                    patched_binary,
                    security_properties,
                    args,
                    "patched",
                    args.patched_analysis_entry,
                )
            finally:
                global_vars.FUNCTION_SIMULATION = original_simulation
            compare_binary_loads(binary_data, patched_data)
            inspect_patch_mappings(binary_data, patched_data)
            compare_binary_bytes(binary_data.binary, patched_data.binary)
            inspect_patched_sites(sinks, patched_data)
            if patched_report.violations:
                print("Patched binary still has security property violations.\n")
            else:
                print("Patched binary passed model checking.\n")
    
if __name__ == "__main__":
    main()
