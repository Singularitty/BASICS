import argparse
import json
import logging
import os
import shutil
import sys
from timeit import default_timer as timer

# Suppress angr's "unconstrained exit state" spam — these states are pruned in
# reaching_state before they accumulate, so the warning is just noise.
logging.getLogger("angr.engines.successors").setLevel(logging.ERROR)

# User modules
# Fixes import errors
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import src.global_vars as global_vars
from src.binary_data_extractor.core import BinaryDataExtractor
from src.model_checker.ltl_model_checker import ModelChecker
from src.model_checker.state_space_constructor import StateSpaceConstructor
from src.security_property_converter.ltl_translator import LinearTemporalLogicTranslator
from src.vulnerability_identifier_removal.identifier import Identifier
from src.vulnerability_identifier_removal.patcher import Patcher
from src.vulnerability_identifier_removal.validator import Validator
from src.model_checker.models.concolic_executor import ConcolicExecutor


def get_arguments():

    parser = argparse.ArgumentParser(
        description="Model Check Security properties of a binary programs stack memory."
    )

    parser.add_argument(
        "--debug", action="store_true", help="Enable debugging messages"
    )

    parser.add_argument(
        "--no-recompilation-ltl",
        action="store_true",
        help="Do not recompile any found LTL formulas",
    )

    parser.add_argument(
        "--draw-cfg",
        action="store_true",
        help="Draw a control flow graph (CFG) of the binary program",
    )

    parser.add_argument(
        "--draw-state-space",
        action="store_true",
        help="Draw the state space of the binary program",
    )

    parser.add_argument(
        "--static",
        action="store_true",
        help="Do no build emulated cfg (NOT RECOMENDED)",
    )

    parser.add_argument(
        "--cfg-mode",
        choices=["auto", "emulated", "fast"],
        default="auto",
        help="CFG construction mode. auto uses CFGFast for large binaries.",
    )
    parser.add_argument(
        "--large-binary-mode",
        action="store_true",
        help="Enable aggressive angr settings for large binaries.",
    )
    parser.add_argument(
        "--scan-all-functions",
        action="store_true",
        help="Analyze every user function in the binary as a separate entry point. "
             "Builds the CFG once and iterates. Implies --large-binary-mode and --no-patching.",
    )
    parser.add_argument(
        "--cfg-fast-complete-scan",
        action="store_true",
        help="Enable CFGFast complete scan (slower, broader coverage).",
    )
    parser.add_argument(
        "--cfg-fast-no-indirect-jumps",
        action="store_true",
        help="Disable CFGFast indirect jump resolution for speed.",
    )
    parser.add_argument(
        "--cfg-fast-no-normalize",
        action="store_true",
        help="Disable CFGFast normalization for speed.",
    )
    parser.add_argument(
        "--cfg-fast-function-starts-only",
        action="store_true",
        help="Seed CFGFast only from the selected analysis entry.",
    )
    parser.add_argument(
        "--patch-aware",
        action="store_true",
        help="Patch-aware analysis: seed CFG with changed and trampoline addresses in patched binaries.",
    )

    parser.add_argument(
        "--no-patching", action="store_true", help="Do not patch the binary"
    )

    parser.add_argument(
        "--no-check-patched",
        action="store_true",
        help="Do not model check the E9-patched binary",
    )

    parser.add_argument(
        "--inspect-patch-only",
        type=str,
        default=None,
        help="Inspect an existing patched binary against binary_path and exit.",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        help="Maximum number of iterations for the model checker",
        default=20,
    )

    parser.add_argument(
        "--max-recursion-depth",
        type=int,
        help="Maximum recursion depth to summarize before skipping recursive calls (0 = always skip)",
        default=1,
    )

    parser.add_argument(
        "--max-states",
        type=int,
        help="Maximum number of memory states to construct before stopping",
        default=None,
    )

    parser.add_argument(
        "--angr-option",
        type=str,
        help="Option for angr simulation, static/fastpath are faster but worse",
        default=None,
    )

    parser.add_argument(
        "--function-simulation",
        choices=["auto", "static", "angr"],
        default="auto",
        help="How to model supported C library calls. auto uses static effects first and falls back to angr.",
    )
    parser.add_argument(
        "--patched-function-simulation",
        choices=["auto", "static", "angr"],
        default="angr",
        help="How to model C library calls when re-checking the patched binary.",
    )

    parser.add_argument(
        "--concolic-step-limit",
        type=int,
        default=10000,
        help="Maximum angr steps when searching for a loop or call site.",
    )

    parser.add_argument(
        "--concolic-active-limit",
        type=int,
        default=64,
        help="Maximum active angr states kept during concolic exploration.",
    )

    parser.add_argument(
        "--scan-memory-limit-mb",
        type=int,
        default=None,
        metavar="MB",
        help="Alias for --memory-limit-mb kept for older scan scripts.",
    )

    parser.add_argument(
        "--memory-limit-mb",
        type=int,
        default=None,
        metavar="MB",
        help="RSS memory ceiling (MB). Whole-binary analysis stops before OOM; "
             "--scan-all-functions skips functions over this limit.",
    )

    parser.add_argument(
        "--validation-inputs",
        type=str,
        default=None,
        metavar="PATH",
        help="Optional JSON file with malicious, benign, and boundary validation inputs.",
    )

    parser.add_argument(
        "--no-gdb-validation",
        action="store_true",
        help="Disable GDB patch-site contract validation.",
    )

    parser.add_argument(
        "--no-regression-validation",
        action="store_true",
        help="Disable original-vs-patched bounded regression checks.",
    )

    parser.add_argument(
        "--validation-timeout",
        type=float,
        default=10,
        metavar="SECONDS",
        help="Timeout for each validation process/GDB run.",
    )

    parser.add_argument(
        "--strict-stderr-validation",
        action="store_true",
        help="Require stderr to match during benign/boundary regression validation.",
    )

    parser.add_argument(
        "--ltl-backend",
        choices=["spot", "ltl2ba", "auto"],
        default="auto",
        help="LTL-to-Buchi backend. spot uses Spot Python bindings; auto falls back to ltl2ba.",
    )

    parser.add_argument(
        "--include-experimental-properties",
        action="store_true",
        help="Include experimental LTL properties. Disabled by default because "
             "they are research probes and can increase false positives.",
    )

    parser.add_argument(
        "--analysis-entry",
        default="main",
        help="Start model checking at this function name (or 'loader' for ELF entry point).",
    )

    parser.add_argument(
        "--patched-analysis-entry",
        default="main",
        help="Start patched-binary model checking at this function name (or 'loader' for ELF entry).",
    )

    # Regular required argument for the binary path
    parser.add_argument("binary_path", type=str, help="Path to the binary file")

    return parser.parse_args()


def setup_workspace(binary_path: str):
    current_directory = global_vars.DIRECTORY
    os.makedirs(current_directory + "/security_properties", exist_ok=True)
    os.makedirs(current_directory + "/security_properties/ltl", exist_ok=True)
    os.makedirs(
        current_directory + "/security_properties/buchi_automata", exist_ok=True
    )
    os.makedirs(current_directory + "/reports", exist_ok=True)

    binary_name = os.path.basename(binary_path)

    os.makedirs(current_directory + "/reports/" + binary_name, exist_ok=True)

    try:
        os.remove(
            current_directory + "/reports/" + binary_name + "/concolic_inputs.txt"
        )
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
    print(
        f"  analysis_entry: {summary['analysis_entry']} ({hex(summary['analysis_entry_addr'])})"
    )
    print(f"  sections: {summary['sections']}")
    print(f"  segments: {summary['segments']}")
    print(f"  functions: {summary['functions']}\n")


def compare_binary_loads(original_data, patched_data):
    same_hash = (
        original_data.fingerprint["sha256"] == patched_data.fingerprint["sha256"]
    )
    if same_hash:
        print(
            "WARNING: Original and patched binaries have the same SHA-256. E9 may not have changed the output file.\n"
        )
    else:
        print(
            "Original and patched binary hashes differ; angr loaded a distinct patched artifact.\n"
        )


def executable_segments(binary_data):
    segments = []
    main_object = binary_data.project.loader.main_object
    for segment in main_object.segments:
        if not getattr(segment, "is_executable", False):
            continue
        segments.append(
            {
                "min_addr": int(segment.min_addr),
                "max_addr": int(segment.max_addr),
                "offset": int(getattr(segment, "offset", 0) or 0),
                "filesize": int(getattr(segment, "filesize", 0) or 0),
                "memsize": int(getattr(segment, "memsize", 0) or 0),
            }
        )
    return segments


def ranges_overlap(left, right):
    return (
        left["min_addr"] <= right["max_addr"] and right["min_addr"] <= left["max_addr"]
    )


def segment_contains(segment, address):
    return segment["min_addr"] <= address <= segment["max_addr"]


def inspect_patch_mappings(original_data, patched_data):
    original_exec = executable_segments(original_data)
    patched_exec = executable_segments(patched_data)
    added_exec = [
        segment
        for segment in patched_exec
        if not any(ranges_overlap(segment, original) for original in original_exec)
    ]

    print("Patch mapping inspection:")
    if original_data.project.entry != patched_data.project.entry:
        print(
            f"  entry changed: {hex(original_data.project.entry)} -> {hex(patched_data.project.entry)}"
        )
    else:
        print(f"  entry unchanged: {hex(patched_data.project.entry)}")

    if not added_exec:
        print("  no added executable mappings detected by angr\n")
        return

    print(f"  added executable mappings: {len(added_exec)}")
    for segment in added_exec:
        entry_marker = (
            " contains patched entry"
            if segment_contains(segment, patched_data.project.entry)
            else ""
        )
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
        regions.append(
            ("resize", shared_size, len(original), shared_size, len(patched))
        )
    if not regions:
        print("  no raw byte differences found\n")
        return

    print(f"  first differing regions: {len(regions)}")
    for tag, i1, i2, j1, j2 in regions[:max_regions]:
        print(f"  {tag}: original[{i1}:{i2}] -> patched[{j1}:{j2}]")
    if len(regions) > max_regions:
        print(f"  ... {len(regions) - max_regions} more differing regions omitted")
    print()


def _load_exec_segments(binary_path):
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
    import angr

    project = angr.Project(binary_path, load_options={"auto_load_libs": False})
    segments = []
    for segment in project.loader.main_object.segments:
        if not getattr(segment, "is_executable", False):
            continue
        segments.append(
            {
                "min_addr": int(segment.min_addr),
                "max_addr": int(segment.max_addr),
                "offset": int(getattr(segment, "offset", 0) or 0),
                "filesize": int(getattr(segment, "filesize", 0) or 0),
            }
        )
    return int(project.entry), segments


def _changed_file_regions(original_path, patched_path, max_regions=128):
    with open(original_path, "rb") as f:
        original = f.read()
    with open(patched_path, "rb") as f:
        patched = f.read()
    shared = min(len(original), len(patched))
    regions = []
    i = 0
    while i < shared and len(regions) < max_regions:
        if original[i] == patched[i]:
            i += 1
            continue
        start = i
        while i < shared and original[i] != patched[i]:
            i += 1
        regions.append((start, i))
    if len(patched) > shared and len(regions) < max_regions:
        regions.append((shared, len(patched)))
    return regions


def patch_aware_cfg_starts(original_path, patched_path):
    patched_entry, patched_exec = _load_exec_segments(patched_path)
    _, original_exec = _load_exec_segments(original_path)
    changed_regions = _changed_file_regions(original_path, patched_path)
    starts = {patched_entry}

    # Seed from one or two anchors per changed region (start + midpoint) to avoid OOM.
    for region_start, region_end in changed_regions:
        anchors = [region_start]
        if region_end - region_start > 64:
            anchors.append(region_start + (region_end - region_start) // 2)
        for off in anchors:
            for seg in patched_exec:
                seg_start = seg["offset"]
                seg_end = seg["offset"] + seg["filesize"]
                if seg_start <= off < seg_end:
                    starts.add(seg["min_addr"] + (off - seg_start))
                    break

    for seg in patched_exec:
        if not any(ranges_overlap(seg, old) for old in original_exec):
            starts.add(seg["min_addr"])

    # Hard cap to keep memory bounded on heavily rewritten binaries.
    return sorted(starts)[:96]


def inspect_patched_sites(sinks, patched_data):
    print("Patched-site inspection:")
    for sink in sinks:
        try:
            block = patched_data.project.factory.block(sink.address, num_inst=1)
            insns = block.capstone.insns
        except Exception as e:
            print(
                f"  {hex(sink.address)}: angr could not disassemble patched site ({e})"
            )
            continue
        if not insns:
            print(f"  {hex(sink.address)}: no instruction decoded")
            continue
        patched_ins = insns[0]
        original = f"{sink.instruction.mnemonic} {sink.instruction.op_str}".strip()
        patched = f"{patched_ins.mnemonic} {patched_ins.op_str}".strip()
        if (
            patched_ins.mnemonic == sink.instruction.mnemonic
            and patched_ins.op_str == sink.instruction.op_str
        ):
            print(f"  {hex(sink.address)}: unchanged ({patched})")
        else:
            print(f"  {hex(sink.address)}: {original} -> {patched}")
    print()


def inspect_existing_patch(original_path, patched_path, args):
    patched_starts = None
    if args.patch_aware:
        patched_starts = patch_aware_cfg_starts(original_path, patched_path)
        print(f"Patch-aware CFG starts for patched binary: {len(patched_starts)}")
    original_data = BinaryDataExtractor(
        original_path,
        args.cfg_mode == "emulated",
        args.cfg_mode,
        args.analysis_entry,
        cfg_fast_complete_scan=args.cfg_fast_complete_scan,
        cfg_fast_resolve_indirect_jumps=not args.cfg_fast_no_indirect_jumps,
        cfg_fast_normalize=not args.cfg_fast_no_normalize,
        cfg_fast_function_starts_only=args.cfg_fast_function_starts_only,
        cfg_extra_starts=None,
    )
    patched_data = BinaryDataExtractor(
        patched_path,
        args.cfg_mode == "emulated",
        args.cfg_mode,
        args.patched_analysis_entry,
        cfg_fast_complete_scan=args.cfg_fast_complete_scan,
        cfg_fast_resolve_indirect_jumps=not args.cfg_fast_no_indirect_jumps,
        cfg_fast_normalize=not args.cfg_fast_no_normalize,
        cfg_fast_function_starts_only=args.cfg_fast_function_starts_only,
        cfg_extra_starts=patched_starts,
    )
    emit_binary_load_summary(original_data, "original")
    emit_binary_load_summary(patched_data, "patched")
    compare_binary_loads(original_data, patched_data)
    inspect_patch_mappings(original_data, patched_data)
    compare_binary_bytes(original_data.binary, patched_data.binary)


def analyze_binary(
    binary_path,
    security_properties,
    args,
    label=None,
    analysis_entry=None,
    baseline_path=None,
):
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
    cfg_extra_starts = None
    if baseline_path is not None:
        cfg_extra_starts = patch_aware_cfg_starts(baseline_path, binary_path)
        print(
            f"Patch-aware CFG starts for {label or 'target'} binary: {len(cfg_extra_starts)}"
        )

    binary_data = BinaryDataExtractor(
        binary_path,
        emulated_cfg,
        cfg_mode,
        analysis_entry,
        cfg_fast_complete_scan=args.cfg_fast_complete_scan,
        cfg_fast_resolve_indirect_jumps=not args.cfg_fast_no_indirect_jumps,
        cfg_fast_normalize=not args.cfg_fast_no_normalize,
        cfg_fast_function_starts_only=args.cfg_fast_function_starts_only,
        cfg_extra_starts=cfg_extra_starts,
    )
    previous_analysis_start = global_vars.ANALYSIS_START_ADDR
    global_vars.ANALYSIS_START_ADDR = binary_data.analysis_entry_addr
    emit_binary_load_summary(binary_data, label or "target")

    try:
        if args.draw_cfg:
            binary_data.draw_binary_cfg()

        # Model Checker Module

        # Construct the state space
        print("Constructing state space\n")
        constructor = StateSpaceConstructor(
            binary_data,
            binary_name,
            current_dir,
            binary_path,
            args.max_iterations,
            args.max_states,
            args.max_recursion_depth,
        )
        constructor.construct_state_space()

        if args.draw_state_space:
            constructor.state_space.draw()

        # Model check the state space
        print("Performing model checking\n")
        model_checker = ModelChecker(
            binary_name,
            constructor.state_space,
            security_properties,
            binary_data.address_to_function,
        )
        model_checker.state_space_transversal()

        report = model_checker.create_report()
    finally:
        global_vars.ANALYSIS_START_ADDR = previous_analysis_start

    end = timer()
    report.set_execution_time(end - start)
    report.emit()
    return binary_data, report


def _has_stack_frame(func, cfg):
    """Return True if the function allocates local stack space (has sub rsp / enter)."""
    get_node = cfg.get_any_node if hasattr(cfg, "get_any_node") else cfg.model.get_any_node
    node = get_node(func.addr)
    if node is None or node.is_simprocedure or node.block is None:
        return False
    try:
        insns = node.block.capstone.insns
    except Exception:
        return False
    if not insns:
        return False
    for ins in insns:
        if ins.mnemonic in ("sub", "enter") and "rsp" in ins.op_str:
            return True
    return False


def scan_all_functions(binary_path, security_properties, args):
    """Build the CFG once, then analyse every user function as a separate entry point."""
    import gc
    from src.global_vars import GLOBAL_HOOKS

    current_dir, binary_name = setup_workspace(binary_path)
    global_vars.BINARY_NAME = binary_name

    print(f"Analyzing binary: {binary_path}\n")
    print("Extracting binary data (CFG built once for all functions)\n")

    binary_data = BinaryDataExtractor(
        binary_path,
        cfg_emulated=False,
        cfg_mode="fast",
        analysis_entry=args.analysis_entry or "main",
        cfg_fast_complete_scan=args.cfg_fast_complete_scan,
        cfg_fast_resolve_indirect_jumps=not args.cfg_fast_no_indirect_jumps,
        cfg_fast_normalize=not args.cfg_fast_no_normalize,
        cfg_fast_function_starts_only=False,
    )
    emit_binary_load_summary(binary_data, "target")

    # Only analyse functions that actually allocate local stack space —
    # leaf/thunk/wrapper functions with no local variables can't have
    # stack buffer overflows and account for the majority of the function list.
    all_funcs = binary_data.functions
    candidates = [f for f in all_funcs if _has_stack_frame(f, binary_data.cfg)]
    print(f"\n{len(all_funcs)} user functions found; {len(candidates)} have local stack frames — scanning those.\n")

    from src.model_checker.models.concolic_executor import _rss_mb

    all_violations = {}
    skipped = []        # (fname, reason)  — analysis errors
    oom_skipped = []    # (fname, rss_mb)  — memory-limit skips
    total_start = timer()

    global_vars.SCAN_MODE = True

    # Lower the concolic active-state limit for scan mode to reduce memory pressure.
    # The default (64) creates too many symbolic state snapshots when scanning a
    # large library with complex control flow.
    saved_active_limit = global_vars.CONCOLIC_ACTIVE_LIMIT
    global_vars.CONCOLIC_ACTIVE_LIMIT = min(saved_active_limit, 16)

    # Pre-hook all clib PLT entries once for the shared project.  The constructor
    # normally does this per-function, but for scan mode we do it upfront and keep
    # the hooks for the entire scan — avoids the O(n_functions × n_plt) unhook/rehook
    # churn and the memory spikes it causes.
    StateSpaceConstructor.hook_clib_plt(binary_data.project)

    mem_limit = global_vars.SCAN_MEMORY_LIMIT_MB

    for i, func in enumerate(candidates, 1):
        fname = func.name
        faddr = func.addr

        # Pre-flight RSS check — skip immediately if we're already over budget.
        if mem_limit is not None:
            rss = _rss_mb()
            if rss > mem_limit:
                oom_skipped.append((fname, rss))
                print(f"[{i}/{len(candidates)}] {fname} @ {hex(faddr)}  SKIPPED (RSS {rss:.0f} MB > limit {mem_limit} MB)", flush=True)
                continue

        print(f"[{i}/{len(candidates)}] {fname} @ {hex(faddr)}", flush=True)

        # Only clear the state cache between functions — PLT hooks stay in place.
        ConcolicExecutor._state_cache.clear()
        gc.collect()

        binary_data.analysis_entry_addr = faddr
        binary_data.analysis_entry = fname
        global_vars.ANALYSIS_START_ADDR = faddr

        try:
            constructor = StateSpaceConstructor(
                binary_data,
                binary_name,
                current_dir,
                binary_path,
                args.max_iterations,
                args.max_states,
                args.max_recursion_depth,
            )
            constructor.construct_state_space()

            model_checker = ModelChecker(
                binary_name,
                constructor.state_space,
                security_properties,
                binary_data.address_to_function,
            )
            model_checker.state_space_transversal()
            report = model_checker.create_report()

            violations = list(report.violations.keys())
            if violations:
                all_violations[fname] = violations
                print(f"  !! {', '.join(violations)}")
            else:
                print(f"  OK")
        except MemoryError:
            rss = _rss_mb()
            oom_skipped.append((fname, rss))
            print(f"  SKIPPED (MemoryError, RSS {rss:.0f} MB)")
            gc.collect()
        except Exception as e:
            # Surface OOM that came wrapped in FailedConcolicExecution
            reason = str(e)
            if "Memory limit" in reason and "exceeded" in reason:
                rss = _rss_mb()
                oom_skipped.append((fname, rss))
                print(f"  SKIPPED ({reason})")
                gc.collect()
            else:
                skipped.append((fname, reason))
                print(f"  SKIPPED: {reason}")

    global_vars.SCAN_MODE = False
    global_vars.CONCOLIC_ACTIVE_LIMIT = saved_active_limit

    total_elapsed = timer() - total_start

    n_clean = len(candidates) - len(all_violations) - len(skipped) - len(oom_skipped)

    print("\n" + "=" * 60)
    print(f"Scan complete: {len(candidates)} functions in {total_elapsed:.1f}s")
    print(f"  Vulnerable:   {len(all_violations)}")
    print(f"  Clean:        {n_clean}")
    print(f"  Skipped (OOM): {len(oom_skipped)}")
    print(f"  Skipped (err): {len(skipped)}")

    if all_violations:
        print("\n-- Vulnerable functions --")
        for fname, viols in all_violations.items():
            print(f"  {fname}: {', '.join(viols)}")

    if oom_skipped:
        print("\n-- Skipped (memory limit) --")
        for fname, rss in oom_skipped:
            print(f"  {fname}  (RSS {rss:.0f} MB at skip)")

    if skipped:
        print("\n-- Skipped (analysis error) --")
        for fname, reason in skipped:
            print(f"  {fname}: {reason}")

    report_path = os.path.join(current_dir, f"{binary_name}_scan_report.txt")
    with open(report_path, "w") as f:
        f.write(f"BASICS function scan: {binary_path}\n")
        f.write(f"Functions total: {len(all_funcs)} | with stack frames: {len(candidates)}\n")
        f.write(f"Elapsed: {total_elapsed:.1f}s\n\n")
        f.write("== Vulnerable ==\n")
        for fname, viols in all_violations.items():
            f.write(f"  {fname}: {', '.join(viols)}\n")
        f.write("\n== Skipped (memory limit) ==\n")
        for fname, rss in oom_skipped:
            f.write(f"  {fname}  (RSS {rss:.0f} MB)\n")
        f.write("\n== Skipped (analysis error) ==\n")
        for fname, reason in skipped:
            f.write(f"  {fname}: {reason}\n")
    print(f"\nReport written to {report_path}")


def main():

    args: argparse.ArgumentParser = get_arguments()
    current_dir, binary_name = setup_workspace(args.binary_path)

    global_vars.BINARY_NAME = binary_name

    if args.debug:
        print("Debugging enabled\n")
        global_vars.DEBUG = True

    if args.angr_option is not None:
        global_vars.ANGR_OPTION = args.angr_option

    if args.scan_all_functions:
        args.large_binary_mode = True
        args.no_patching = True

    if args.large_binary_mode:
        args.cfg_mode = "fast"
        args.function_simulation = "static"
        args.patched_function_simulation = "static"
        if args.analysis_entry is None:
            args.analysis_entry = "main"
        if args.patched_analysis_entry is None:
            args.patched_analysis_entry = "main"
        args.cfg_fast_no_indirect_jumps = True
        args.cfg_fast_function_starts_only = True

    global_vars.FUNCTION_SIMULATION = args.function_simulation
    global_vars.CONCOLIC_STEP_LIMIT = args.concolic_step_limit
    global_vars.CONCOLIC_ACTIVE_LIMIT = args.concolic_active_limit
    global_vars.LTL_BACKEND = args.ltl_backend
    if args.memory_limit_mb is None and args.scan_memory_limit_mb is not None:
        args.memory_limit_mb = args.scan_memory_limit_mb
    global_vars.SCAN_MEMORY_LIMIT_MB = args.memory_limit_mb
    global_vars.MEMORY_LIMIT_MB = args.memory_limit_mb
    global_vars.INCLUDE_EXPERIMENTAL_PROPERTIES = args.include_experimental_properties

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

    if args.scan_all_functions:
        scan_all_functions(args.binary_path, security_properties, args)
        return

    binary_data, report = analyze_binary(
        args.binary_path, security_properties, args, "original", args.analysis_entry
    )

    # Identify Vulnerabilities
    vuln_identifier = Identifier(report, binary_data.cfg)

    sinks = vuln_identifier.find_vulnerability()

    # Patch the binary
    if args.no_patching:
        return
    patcher = Patcher(binary_data, sinks)
    patched_binary = patcher.patch()

    if patched_binary is not None:
        validator = Validator(
            args.binary_path,
            patched_binary_path=patched_binary,
            sinks=sinks,
            sink_addresses=[s.address for s in sinks],
            manifest_path=patcher.manifest_path,
            validation_inputs=args.validation_inputs,
            timeout=args.validation_timeout,
            enable_gdb=not args.no_gdb_validation,
            enable_regression=not args.no_regression_validation,
            strict_stderr=args.strict_stderr_validation,
        )
        validator.validate()


if __name__ == "__main__":
    main()
