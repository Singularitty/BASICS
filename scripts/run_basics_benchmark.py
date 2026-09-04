#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT / "reports"
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "stack_benchmark" / "stack_cases_combined.json"
RESULTS_DIR = ROOT / "Benchmarks" / "stack_benchmark" / "results"
ACTIVE_PROCS = set()
ACTIVE_PROCS_LOCK = threading.Lock()
BO_CWE_IDS = {
    # BO-only scoring for BASICS-vs-external comparisons. Exclude underflow
    # classes such as CWE-124 so no_underflow_* properties do not count as
    # stack buffer-overflow detections.
    "119", "120", "121", "122", "123", "125", "126", "127",
    "129", "130", "131", "193", "680", "787", "788", "805", "806",
}


def is_stack_bo_property(name: str) -> bool:
    """Return whether an LTL violation is graded as stack-buffer overflow."""
    normalized = name.strip().lower()
    return bool(normalized) and "underflow" not in normalized and "underwrite" not in normalized


def parse_property_violations(text: str) -> list[str]:
    return sorted(set(re.findall(r"^Property:\s*(\S+)", text, re.MULTILINE)))


def load_cases(path: Path):
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, list):
        return obj
    if "datasets" in obj:
        cases = []
        for data in obj["datasets"].values():
            cases.extend(data.get("cases", []))
        return cases
    if "cases" in obj:
        return obj["cases"]
    raise ValueError(f"Unsupported manifest format: {path}")


def parse_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "y"}


def ensure_binary(case):
    compile_info = case.get("compile", {})
    binary_path = case.get("binary_path")
    if not binary_path:
        return None, "missing_binary_path"
    abs_bin = ROOT / binary_path
    source_path = case.get("source_path")
    abs_source = ROOT / source_path if source_path else None
    should_compile = parse_bool(compile_info.get("required", False))
    source_is_newer = (
        abs_bin.exists()
        and abs_source is not None
        and abs_source.exists()
        and abs_source.stat().st_mtime > abs_bin.stat().st_mtime
    )
    if abs_bin.exists() and not source_is_newer:
        return abs_bin, None
    if not should_compile:
        return None, f"binary_missing:{abs_bin}"
    cmd = compile_info.get("command", [])
    if not cmd:
        return None, "compile_command_missing"
    abs_bin.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    if proc.returncode != 0:
        return None, f"compile_failed: {proc.stdout[-800:]}"
    if abs_bin.exists():
        return abs_bin, None
    alt = resolve_juliet_individual_binary(abs_bin)
    if alt is not None:
        return alt, None
    return None, "compile_finished_binary_missing"


def resolve_juliet_individual_binary(path: Path):
    # Juliet's "make individuals" emits ..._<variant>.out, collapsing _bad/_good* suffixes.
    name = path.name
    if not name.endswith(".out"):
        return None
    stem = path.stem
    m = re.match(r"^(.*)_(\d+?)_(bad|goodB2G|goodG2B|good)$", stem, re.IGNORECASE)
    if not m:
        return None
    collapsed = f"{m.group(1)}_{m.group(2)}.out"
    candidate = path.with_name(collapsed)
    if candidate.exists():
        return candidate
    return None


def parse_report(report_text: str):
    cwes = sorted(
        cwe
        for cwe in set(re.findall(r"\bCWE-\d+\b", report_text))
        if cwe.rsplit("-", 1)[-1] in BO_CWE_IDS
    )
    violations = 0
    m = re.search(r"(\d+)\s+security property violations found\.", report_text)
    if m:
        violations = int(m.group(1))
    properties = parse_property_violations(report_text)
    return {
        "reported_vuln": bool(cwes) or any(is_stack_bo_property(p) for p in properties),
        "reported_cwes": cwes,
        "reported_properties": properties,
        "report_violation_count": violations,
    }


def parse_stdout(stdout: str):
    cwes = sorted(
        cwe
        for cwe in set(re.findall(r"Potential vulnerability(?: due to loop)?\s+(CWE-\d+)", stdout))
        if cwe.rsplit("-", 1)[-1] in BO_CWE_IDS
    )
    properties = parse_property_violations(stdout)
    patch_lines = [line for line in stdout.splitlines() if line.startswith("patched: ")]
    patch_pass = [line for line in patch_lines if " PASS " in line]
    remediation_match = re.search(r"^Patch remediation:\s+(PASS|FAIL|INCONCLUSIVE)\s*$", stdout, re.MULTILINE)
    preservation_match = re.search(r"^Bounded functional preservation:\s+(PASS|FAIL|INCONCLUSIVE)\s*$", stdout, re.MULTILINE)
    structured_validated = False
    if remediation_match or preservation_match:
        remediation = remediation_match.group(1) if remediation_match else "INCONCLUSIVE"
        preservation = preservation_match.group(1) if preservation_match else "INCONCLUSIVE"
        if remediation == "PASS" and preservation in {"PASS", "INCONCLUSIVE"}:
            validation_status = "passed" if preservation == "PASS" else "remediation_passed_preservation_inconclusive"
            structured_validated = preservation == "PASS"
        elif remediation == "FAIL" or preservation == "FAIL":
            validation_status = "failed"
        else:
            validation_status = "inconclusive"
    elif patch_lines:
        validation_status = "passed" if len(patch_pass) == len(patch_lines) else "failed"
    elif "ptrace: Operation not permitted" in stdout or "Could not trace the inferior process" in stdout:
        validation_status = "blocked_ptrace"
    elif "GDB ptrace unavailable" in stdout:
        validation_status = "blocked_ptrace"
    elif "GDB contract validation did not produce a usable debugger run" in stdout:
        validation_status = "no_debugger_run"
    elif "gdb is not installed" in stdout:
        validation_status = "gdb_missing"
    elif "Patch manifest has no patch entries" in stdout or "No patch manifest available" in stdout:
        validation_status = "not_applicable"
    else:
        validation_status = "not_run"
    timing = {}
    for match in re.finditer(r"^@@BASICS_TIMING\s+(\{.*\})\s*$", stdout, re.MULTILINE):
        try:
            candidate = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            timing = candidate
    return {
        "stdout_cwes": cwes,
        "stdout_properties": properties,
        "reported_vuln": bool(cwes) or any(is_stack_bo_property(p) for p in properties),
        "patch_validated": (
            structured_validated
            or (bool(patch_lines) and len(patch_pass) == len(patch_lines))
        ),
        "patch_validation_status": validation_status,
        "patch_validation_lines": patch_lines,
        "timing": timing,
    }


def parse_patch_manifest(path: Path):
    if not path.exists():
        return False, 0
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        entries = obj.get("patches", [])
        return True, len(entries)
    except Exception:
        return True, 0


def case_analysis_entry(case):
    """Resolve both manifest spellings used by BASICS benchmark datasets."""
    return case.get("analysis_entry") or case.get("entry_function") or ""


def empty_result_row(case):
    return {
        "case_id": case["case_id"],
        "dataset": case.get("dataset"),
        "true_present_vuln": case.get("true_present_vuln"),
        "label_confidence": case.get("label_confidence"),
        "label_rule": case.get("label_rule"),
        "analysis_entry": case_analysis_entry(case),
        "source_path": case.get("source_path", ""),
        "binary_path": case.get("binary_path", ""),
        "status": "ok",
        "error": "",
        "elapsed_sec": 0.0,
        "analysis_exec_time_sec": "",
        "disassembly_cfg_sec": "",
        "memstace_sec": "",
        "ltl_model_checking_sec": "",
        "patch_generation_sec": "",
        "patch_validation_sec": "",
        "pipeline_end_to_end_sec": "",
        "timing_overhead_unattributed_sec": "",
        "reported_vuln": False,
        "reported_cwes": "",
        "report_violation_count": 0,
        "patched": False,
        "patch_manifest_entries": 0,
        "patch_validated": False,
        "patch_validation_status": "not_run",
        "stdout_log_path": "",
        "report_path": "",
        "manifest_path": "",
    }


def run_interruptible(cmd: list[str], timeout_sec: int | None):
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    with ACTIVE_PROCS_LOCK:
        ACTIVE_PROCS.add(proc)
    try:
        output, _ = proc.communicate(timeout=timeout_sec)
        return proc.returncode, output or "", None
    except KeyboardInterrupt:
        terminate_process_group(proc)
        output, _ = proc.communicate(timeout=5)
        raise KeyboardInterrupt(output or "")
    except subprocess.TimeoutExpired:
        terminate_process_group(proc)
        output, _ = proc.communicate(timeout=5)
        return proc.returncode, output or "", "timeout"
    finally:
        with ACTIVE_PROCS_LOCK:
            ACTIVE_PROCS.discard(proc)


def terminate_process_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def terminate_active_processes():
    with ACTIVE_PROCS_LOCK:
        procs = list(ACTIVE_PROCS)
    for proc in procs:
        if proc.poll() is None:
            terminate_process_group(proc)


def run_case(case, basics_args: list[str], out_logs_dir: Path, timeout_sec: int | None):
    case_id = case["case_id"]
    binary, err = ensure_binary(case)
    row = empty_result_row(case)
    if err is not None:
        row["status"] = "compile_error"
        row["error"] = err
        return row

    log_path = out_logs_dir / f"{case_id}.log"
    binary_name = binary.name
    report_path = REPORTS_DIR / binary_name / f"{binary_name}_report.txt"
    manifest_path = REPORTS_DIR / binary_name / "patch_manifest.json"
    patched_binary_path = Path(str(binary) + "_patched")
    manifest_path.unlink(missing_ok=True)
    patched_binary_path.unlink(missing_ok=True)

    cmd = ["./run_basics.sh"] + basics_args
    analysis_entry = case_analysis_entry(case)
    if analysis_entry:
        cmd += ["--analysis-entry", str(analysis_entry)]
        if case.get("patched_analysis_entry"):
            cmd += ["--patched-analysis-entry", str(case["patched_analysis_entry"])]
        else:
            cmd += ["--patched-analysis-entry", str(analysis_entry)]
    cmd += [str(binary)]
    start = time.perf_counter()
    try:
        returncode, output, run_error = run_interruptible(cmd, timeout_sec)
    except KeyboardInterrupt as exc:
        elapsed = time.perf_counter() - start
        output = exc.args[0] if exc.args else ""
        log_path.write_text(output, encoding="utf-8")
        row["stdout_log_path"] = str(log_path.relative_to(ROOT))
        row["elapsed_sec"] = round(elapsed, 4)
        row["status"] = "interrupted"
        row["error"] = "keyboard_interrupt"
        return row, True
    elapsed = time.perf_counter() - start
    if run_error == "timeout":
        log_path.write_text(output, encoding="utf-8")
        row["stdout_log_path"] = str(log_path.relative_to(ROOT))
        row["elapsed_sec"] = round(elapsed, 4)
        row["status"] = "timeout"
        row["error"] = f"timeout={timeout_sec}s"
        return row
    log_path.write_text(output, encoding="utf-8")
    row["stdout_log_path"] = str(log_path.relative_to(ROOT))
    row["elapsed_sec"] = round(elapsed, 4)
    if returncode != 0:
        if "Memory limit" in output and "RSS" in output:
            row["status"] = "memory_limit"
            mt = re.search(r"Memory limit[^\\n]+", output)
            row["error"] = mt.group(0) if mt else f"exit={returncode}"
        elif report_path.exists() and "further analysis not implemented" in output:
            row["status"] = "ok"
            row["error"] = ""
        else:
            row["status"] = "run_error"
            row["error"] = f"exit={returncode}"

    row["report_path"] = str(report_path.relative_to(ROOT)) if report_path.exists() else ""
    row["manifest_path"] = str(manifest_path.relative_to(ROOT)) if manifest_path.exists() else ""

    parsed_stdout = parse_stdout(output)
    timing = parsed_stdout["timing"]
    timing_columns = {
        "disassembly_cfg_sec": "disassembly_cfg_seconds",
        "memstace_sec": "memstace_seconds",
        "ltl_model_checking_sec": "ltl_model_checking_seconds",
        "patch_generation_sec": "patch_generation_seconds",
        "patch_validation_sec": "patch_validation_seconds",
        "pipeline_end_to_end_sec": "end_to_end_seconds",
        "timing_overhead_unattributed_sec": "timing_overhead_unattributed_seconds",
    }
    for column, timing_key in timing_columns.items():
        value = timing.get(timing_key)
        if value is not None:
            row[column] = value

    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8", errors="replace")
        parsed_report = parse_report(report_text)
        cwes = sorted(set(parsed_report["reported_cwes"]) | set(parsed_stdout["stdout_cwes"]))
        row["reported_vuln"] = parsed_report["reported_vuln"] or parsed_stdout["reported_vuln"]
        row["reported_cwes"] = ";".join(cwes)
        row["report_violation_count"] = parsed_report["report_violation_count"]
        mt = re.search(r"Execution Time:\s*([0-9.]+)\s*seconds", report_text)
        if mt:
            row["analysis_exec_time_sec"] = mt.group(1)
    else:
        row["reported_vuln"] = parsed_stdout["reported_vuln"]
        row["reported_cwes"] = ";".join(parsed_stdout["stdout_cwes"])

    patched, entries = parse_patch_manifest(manifest_path)
    row["patched"] = patched
    row["patch_manifest_entries"] = entries
    row["patch_validated"] = parsed_stdout["patch_validated"]
    row["patch_validation_status"] = parsed_stdout["patch_validation_status"]
    return row


def slugify(value: str, fallback: str = "run") -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")
    return slug or fallback


def infer_dataset_name(cases, manifest: Path, override: str | None = None) -> str:
    if override:
        return slugify(override, "dataset")
    datasets = sorted({str(c.get("dataset", "")).strip() for c in cases if c.get("dataset")})
    if len(datasets) == 1:
        return slugify(datasets[0], "dataset")
    manifest_name = manifest.stem.lower()
    if "juliet" in manifest_name:
        return "juliet"
    if "sard" in manifest_name or "stack_cases" in manifest_name:
        return "sard"
    return "mixed"


def unique_run_dir(stem: str) -> Path:
    candidate = RESULTS_DIR / stem
    if not candidate.exists():
        return candidate
    for idx in range(2, 1000):
        candidate = RESULTS_DIR / f"{stem}_{idx:02d}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate unique result directory for {stem}")


def write_results(out_dir: Path, rows, run_stem: str | None = None):
    csv_path = out_dir / "results.csv"
    json_path = out_dir / "results.json"

    fieldnames = [
        "case_id",
        "dataset",
        "true_present_vuln",
        "label_confidence",
        "label_rule",
        "analysis_entry",
        "source_path",
        "binary_path",
        "status",
        "error",
        "elapsed_sec",
        "analysis_exec_time_sec",
        "disassembly_cfg_sec",
        "memstace_sec",
        "ltl_model_checking_sec",
        "patch_generation_sec",
        "patch_validation_sec",
        "pipeline_end_to_end_sec",
        "timing_overhead_unattributed_sec",
        "reported_vuln",
        "reported_cwes",
        "report_violation_count",
        "patched",
        "patch_manifest_entries",
        "patch_validated",
        "patch_validation_status",
        "stdout_log_path",
        "report_path",
        "manifest_path",
    ]
    csv_paths = [csv_path]
    json_paths = [json_path]
    if run_stem:
        csv_paths.append(out_dir / f"{run_stem}_results.csv")
        json_paths.append(out_dir / f"{run_stem}_results.json")

    for path in csv_paths:
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    json_payload = json.dumps(rows, indent=2)
    for path in json_paths:
        path.write_text(json_payload, encoding="utf-8")
    return csv_path, json_path, csv_paths, json_paths


def write_stats(out_dir: Path, csv_path: Path, run_stem: str | None = None):
    stats_txt_path = out_dir / "stats.txt"
    stats_json_path = out_dir / "stats.json"

    txt_proc = subprocess.run(
        ["python3", "scripts/calc_metrics.py", str(csv_path), "--by-dataset"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    stats_txt_path.write_text(txt_proc.stdout, encoding="utf-8")

    json_proc = subprocess.run(
        ["python3", "scripts/calc_metrics.py", str(csv_path), "--by-dataset", "--json"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    stats_json_path.write_text(json_proc.stdout, encoding="utf-8")

    txt_paths = [stats_txt_path]
    json_paths = [stats_json_path]
    if run_stem:
        named_txt = out_dir / f"{run_stem}_stats.txt"
        named_json = out_dir / f"{run_stem}_stats.json"
        named_txt.write_text(stats_txt_path.read_text(encoding="utf-8"), encoding="utf-8")
        named_json.write_text(stats_json_path.read_text(encoding="utf-8"), encoding="utf-8")
        txt_paths.append(named_txt)
        json_paths.append(named_json)
    return txt_paths, json_paths, txt_proc.returncode, json_proc.returncode


def read_meminfo_mb() -> tuple[int | None, int | None]:
    values = {}
    try:
        with Path("/proc/meminfo").open(encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    values[parts[0].rstrip(":")] = int(parts[1]) // 1024
    except OSError:
        return None, None
    return values.get("MemTotal"), values.get("MemAvailable")


def default_reserve_memory_mb(total_mb: int | None) -> int:
    if total_mb is None:
        return 2048
    return max(2048, int(total_mb * 0.10))


def auto_worker_count(
    requested: str,
    case_count: int,
    memory_limit_mb: int | None,
    mem_per_worker_mb: int | None,
    reserve_memory_mb: int | None,
) -> tuple[int, str]:
    if case_count <= 0:
        return 1, "no cases"
    cpu_count = os.cpu_count() or 1
    if requested != "auto":
        workers = int(requested)
        if workers < 1:
            raise SystemExit("--jobs must be 'auto' or a positive integer")
        return min(workers, case_count), f"requested={workers}"

    total_mb, available_mb = read_meminfo_mb()
    reserve_mb = reserve_memory_mb if reserve_memory_mb is not None else default_reserve_memory_mb(total_mb)
    per_worker_mb = mem_per_worker_mb or memory_limit_mb or int(os.environ.get("BASICS_BENCH_MB_PER_WORKER", "2500"))
    memory_budget_mb = max(0, (available_mb or total_mb or per_worker_mb) - reserve_mb)
    memory_workers = max(1, memory_budget_mb // max(1, per_worker_mb))
    workers = max(1, min(case_count, cpu_count, memory_workers))
    reason = (
        f"auto: cpus={cpu_count}, mem_available_mb={available_mb or 'unknown'}, "
        f"reserve_mb={reserve_mb}, per_worker_mb={per_worker_mb}"
    )
    return workers, reason


def main():
    parser = argparse.ArgumentParser(description="Run BASICS stack-vulnerability benchmarks and log results.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="Path to dataset manifest JSON.")
    parser.add_argument("--dataset", action="append", default=[], help="Filter dataset names (repeatable).")
    parser.add_argument("--case-id", action="append", default=[], help="Filter by case id (repeatable substring match).")
    parser.add_argument("--include-label-rule", action="append", default=[],
                        help="Only run cases with this label_rule (repeatable).")
    parser.add_argument("--exclude-label-rule", action="append", default=[],
                        help="Skip cases with this label_rule (repeatable).")
    parser.add_argument("--limit", type=int, default=None, help="Run at most N cases after filtering.")
    parser.add_argument("--no-patching", action="store_true", help="Run BASICS with --no-patching.")
    parser.add_argument("--include-experimental-properties", action="store_true",
                        help="Pass --include-experimental-properties to BASICS.")
    parser.add_argument("--timeout-sec", type=int, default=None, help="Per-case timeout for BASICS execution.")
    parser.add_argument(
        "--jobs",
        default="1",
        help="Number of benchmark cases to run concurrently, or 'auto'. Default: 1.",
    )
    parser.add_argument(
        "--mem-per-worker-mb",
        type=int,
        default=None,
        help="Memory estimate used by --jobs auto. Defaults to --memory-limit-mb or 2500 MB.",
    )
    parser.add_argument(
        "--reserve-memory-mb",
        type=int,
        default=None,
        help="Memory kept free by --jobs auto. Defaults to max(2048 MB, 10%% of RAM).",
    )
    parser.add_argument("--tool-name", default="basics",
                        help="Tool component used in result directory/file names.")
    parser.add_argument("--run-dataset-name", default=None,
                        help="Dataset component used in result directory/file names.")
    parser.add_argument("--no-stats", action="store_true",
                        help="Do not write stats.txt/stats.json alongside results.")
    parser.add_argument("--cfg-mode", choices=["auto", "emulated", "fast"], default="auto")
    parser.add_argument(
        "--cfg-fast-function-starts-only",
        action="store_true",
        help="Seed CFGFast from the selected analysis entry instead of scanning all code.",
    )
    parser.add_argument("--function-simulation", choices=["auto", "static", "angr"], default="static")
    parser.add_argument(
        "--loop-simulation",
        choices=["concolic", "concolic-static", "static"],
        default="concolic-static",
    )
    parser.add_argument(
        "--user-call-simulation",
        choices=["concolic", "structural"],
        default="concolic",
    )
    parser.add_argument("--patched-function-simulation", choices=["auto", "static", "angr"], default="static")
    parser.add_argument("--concolic-step-limit", type=int, default=None,
                        help="Maximum angr steps per concolic reachability query.")
    parser.add_argument("--max-iterations", type=int, default=None,
                        help="Maximum loop iterations executed by BASICS.")
    parser.add_argument("--memory-limit-mb", type=int, default=None, help="RSS ceiling passed to BASICS.")
    parser.add_argument("--validation-timeout", type=float, default=None,
                        help="Timeout passed to BASICS patch validation runs.")
    parser.add_argument("--no-gdb-validation", action="store_true",
                        help="Disable BASICS GDB validation during patch validation.")
    parser.add_argument("--no-regression-validation", action="store_true",
                        help="Disable BASICS benign/boundary regression validation.")
    parser.add_argument("--strict-stderr-validation", action="store_true",
                        help="Require stderr equality in BASICS regression validation.")
    args = parser.parse_args()

    cases = load_cases(args.manifest)
    if args.dataset:
        allow = set(args.dataset)
        cases = [c for c in cases if c.get("dataset") in allow]
    if args.case_id:
        needles = [n.lower() for n in args.case_id]
        cases = [c for c in cases if any(n in c["case_id"].lower() for n in needles)]
    if args.include_label_rule:
        allow_rules = set(args.include_label_rule)
        cases = [c for c in cases if c.get("label_rule") in allow_rules]
    if args.exclude_label_rule:
        skip_rules = set(args.exclude_label_rule)
        cases = [c for c in cases if c.get("label_rule") not in skip_rules]
    if args.limit is not None:
        cases = cases[: args.limit]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tool_name = slugify(args.tool_name, "tool")
    dataset_name = infer_dataset_name(cases, args.manifest, args.run_dataset_name)
    run_stem = f"{tool_name}_{dataset_name}_{timestamp}"
    out_dir = unique_run_dir(run_stem)
    run_stem = out_dir.name
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    basics_args = [
        "--cfg-mode",
        args.cfg_mode,
        "--function-simulation",
        args.function_simulation,
        "--loop-simulation",
        args.loop_simulation,
        "--user-call-simulation",
        args.user_call_simulation,
        "--patched-function-simulation",
        args.patched_function_simulation,
    ]
    if args.cfg_fast_function_starts_only:
        basics_args.append("--cfg-fast-function-starts-only")
    if args.no_patching:
        basics_args.append("--no-patching")
    if args.include_experimental_properties:
        basics_args.append("--include-experimental-properties")
    if args.concolic_step_limit is not None:
        basics_args += ["--concolic-step-limit", str(args.concolic_step_limit)]
    if args.max_iterations is not None:
        basics_args += ["--max-iterations", str(args.max_iterations)]
    if args.memory_limit_mb is not None:
        basics_args += ["--memory-limit-mb", str(args.memory_limit_mb)]
    if args.validation_timeout is not None:
        basics_args += ["--validation-timeout", str(args.validation_timeout)]
    if args.no_gdb_validation:
        basics_args.append("--no-gdb-validation")
    if args.no_regression_validation:
        basics_args.append("--no-regression-validation")
    if args.strict_stderr_validation:
        basics_args.append("--strict-stderr-validation")

    jobs, jobs_reason = auto_worker_count(
        args.jobs,
        len(cases),
        args.memory_limit_mb,
        args.mem_per_worker_mb,
        args.reserve_memory_mb,
    )
    print(f"Running {len(cases)} case(s) with {jobs} worker(s) ({jobs_reason}).", flush=True)

    rows = [None] * len(cases)
    interrupted = False
    completed = 0
    if jobs == 1:
        for idx, case in enumerate(cases):
            result = run_case(case, basics_args, logs_dir, args.timeout_sec)
            if isinstance(result, tuple):
                row, interrupted = result
            else:
                row = result
            rows[idx] = row
            completed += 1
            print(f"[{completed}/{len(cases)}] {case['case_id']}: {row['status']} reported={row['reported_vuln']} patched={row['patched']} validated={row['patch_validated']}", flush=True)
            if interrupted:
                print("Interrupted. Wrote partial results and stopped.", flush=True)
                break
    else:
        executor = ThreadPoolExecutor(max_workers=jobs)
        try:
            future_to_case = {
                executor.submit(run_case, case, basics_args, logs_dir, args.timeout_sec): (idx, case)
                for idx, case in enumerate(cases)
            }
            for future in as_completed(future_to_case):
                idx, case = future_to_case[future]
                result = future.result()
                if isinstance(result, tuple):
                    row, interrupted = result
                else:
                    row = result
                rows[idx] = row
                completed += 1
                print(f"[{completed}/{len(cases)}] {case['case_id']}: {row['status']} reported={row['reported_vuln']} patched={row['patched']} validated={row['patch_validated']}", flush=True)
                if interrupted:
                    print("Interrupted. Wrote partial results and stopped.", flush=True)
                    terminate_active_processes()
                    break
        except KeyboardInterrupt:
            interrupted = True
            terminate_active_processes()
            print("Interrupted. Wrote partial results and stopped.", flush=True)
        finally:
            executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    completed_rows = [row for row in rows if row is not None]
    csv_path, json_path, csv_paths, json_paths = write_results(out_dir, completed_rows, run_stem)

    print("Wrote benchmark results:")
    print(f"  Directory: {out_dir}")
    print(f"  CSV: {csv_path}")
    print(f"  JSON: {json_path}")
    if len(csv_paths) > 1:
        print(f"  Named CSV: {csv_paths[-1]}")
        print(f"  Named JSON: {json_paths[-1]}")

    if not args.no_stats:
        txt_paths, stats_json_paths, txt_rc, json_rc = write_stats(out_dir, csv_path, run_stem)
        print("Wrote benchmark statistics:")
        print(f"  Stats text: {txt_paths[0]}")
        print(f"  Stats JSON: {stats_json_paths[0]}")
        if len(txt_paths) > 1:
            print(f"  Named stats text: {txt_paths[-1]}")
            print(f"  Named stats JSON: {stats_json_paths[-1]}")
        if txt_rc != 0 or json_rc != 0:
            print("Warning: metrics generation reported an error; see stats files for details.")


if __name__ == "__main__":
    main()
