#!/usr/bin/env python3
"""Run function-entry BASICS cases one process at a time with incremental results."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "opensource" / "opensource_function_cases_all.json"
RESULTS_DIR = ROOT / "Benchmarks" / "stack_benchmark" / "results"
SCRATCH_ROOT = ROOT / "Benchmarks" / "opensource" / "function_run_bins"
WRITE_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()


def load_benchmark_module():
    path = ROOT / "scripts" / "run_basics_benchmark.py"
    spec = importlib.util.spec_from_file_location("basics_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")[:180]


def unique_binary_case(case: dict, out_dir: Path) -> dict:
    """Give a parallel function-entry run a unique binary basename.

    BASICS writes reports under reports/<binary-name>. Parallel entries from the
    same binary would otherwise race on the same report directory. Hard-linking
    keeps this cheap while giving each subprocess a distinct report namespace.
    """
    source = ROOT / case["binary_path"]
    if not source.exists():
        return case
    run_bin_dir = SCRATCH_ROOT / out_dir.name / safe_id(case["case_id"])
    run_bin_dir.mkdir(parents=True, exist_ok=True)
    target = run_bin_dir / f"{safe_id(case['case_id'])}__{source.name}"
    if not target.exists():
        try:
            os.link(source, target)
        except OSError:
            shutil.copy2(source, target)
    next_case = dict(case)
    next_case["binary_path"] = str(target.relative_to(ROOT))
    return next_case


def summarize(rows: list[dict], manifest_cases: list[dict]) -> dict:
    projects = sorted({case.get("project") for case in manifest_cases if case.get("project")})
    binaries = sorted({case.get("binary_path") for case in manifest_cases if case.get("binary_path")})
    statuses: dict[str, int] = {}
    cwes: dict[str, int] = {}
    vulnerable_functions = []
    for row in rows:
        status = row.get("status", "")
        statuses[status] = statuses.get(status, 0) + 1
        if row.get("reported_vuln") in {True, "True", "true", "1", 1}:
            vulnerable_functions.append(row.get("case_id", ""))
            for cwe in str(row.get("reported_cwes", "")).split(";"):
                if cwe:
                    cwes[cwe] = cwes.get(cwe, 0) + 1
    return {
        "projects": len(projects),
        "project_names": projects,
        "binaries": len(binaries),
        "functions_selected": len(manifest_cases),
        "functions_completed": len(rows),
        "functions_reported_vulnerable": len(vulnerable_functions),
        "statuses": statuses,
        "reported_cwes": dict(sorted(cwes.items())),
        "vulnerable_case_ids": vulnerable_functions,
    }


def write_incremental(bench, out_dir: Path, rows: list[dict], manifest_cases: list[dict]) -> None:
    bench.write_results(out_dir, rows)
    summary = summarize(rows, manifest_cases)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "summary.md").write_text(
        "\n".join(
            [
                "| Metric | Value |",
                "|---|---:|",
                f"| Projects | {summary['projects']} |",
                f"| Binaries | {summary['binaries']} |",
                f"| Functions selected | {summary['functions_selected']} |",
                f"| Functions completed | {summary['functions_completed']} |",
                f"| Functions reported vulnerable | {summary['functions_reported_vulnerable']} |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def run_one(bench, case: dict, basics_args: list[str], logs_dir: Path, timeout_sec: int | None, out_dir: Path) -> dict:
    isolated = unique_binary_case(case, out_dir)
    row = bench.run_case(isolated, basics_args, logs_dir, timeout_sec)
    if isinstance(row, tuple):
        row = row[0]
    # Preserve the original binary in the result; the isolated hardlink path is
    # only an implementation detail to avoid report-directory collisions.
    row["binary_path"] = case.get("binary_path", row.get("binary_path", ""))
    return row


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Low-memory open-source function sweep. Each function is analyzed in a fresh BASICS subprocess."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--project", action="append", default=[], help="Project name without opensource/ prefix.")
    parser.add_argument("--case-id", action="append", default=[], help="Case id substring filter.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--timeout-sec", type=int, default=300)
    parser.add_argument("--workers", type=int, default=1, help="Parallel BASICS subprocesses.")
    parser.add_argument("--cfg-mode", choices=["auto", "emulated", "fast"], default="fast")
    parser.add_argument("--function-simulation", choices=["auto", "static", "angr"], default="static")
    parser.add_argument("--memory-limit-mb", type=int, default=2500, help="Per-function BASICS RSS ceiling.")
    parser.add_argument("--hard-memory-limit-mb", type=int, default=None, help="Hard per-function BASICS address-space ceiling.")
    parser.add_argument("--concolic-step-limit", type=int, default=100, help="Per-function concolic reachability bound.")
    parser.add_argument("--concolic-active-limit", type=int, default=16, help="Per-function active-state cap.")
    parser.add_argument("--max-states", type=int, default=5000, help="Per-function abstract state cap.")
    parser.add_argument("--cfg-skip-loopfinder", action="store_true", help="Skip angr LoopFinder in per-function workers.")
    parser.add_argument("--patching", action="store_true", help="Enable patching. Default is detection-only.")
    parser.add_argument("--out-dir", type=Path, default=None, help="Resume/write into an existing result directory.")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    bench = load_benchmark_module()
    cases = bench.load_cases(args.manifest)
    cases = [case for case in cases if case.get("analysis_entry")]
    if args.project:
        allowed = {f"opensource/{name}" for name in args.project}
        cases = [case for case in cases if case.get("dataset") in allowed]
    if args.case_id:
        needles = [needle.lower() for needle in args.case_id]
        cases = [case for case in cases if any(needle in case["case_id"].lower() for needle in needles)]
    if args.limit is not None:
        cases = cases[: args.limit]

    if args.out_dir is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = RESULTS_DIR / stamp
    else:
        out_dir = args.out_dir
        if not out_dir.is_absolute():
            out_dir = ROOT / out_dir
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    existing_json = out_dir / "results.json"
    if existing_json.exists():
        import json

        rows = json.loads(existing_json.read_text(encoding="utf-8"))
    done = {row["case_id"] for row in rows}

    basics_args = [
        "--cfg-mode",
        args.cfg_mode,
        "--function-simulation",
        args.function_simulation,
        "--patched-function-simulation",
        args.function_simulation,
        "--memory-limit-mb",
        str(args.memory_limit_mb),
        "--concolic-step-limit",
        str(args.concolic_step_limit),
        "--concolic-active-limit",
        str(args.concolic_active_limit),
        "--max-states",
        str(args.max_states),
    ]
    if args.hard_memory_limit_mb is not None:
        basics_args += ["--hard-memory-limit-mb", str(args.hard_memory_limit_mb)]
    if args.cfg_skip_loopfinder:
        basics_args.append("--cfg-skip-loopfinder")
    if not args.patching:
        basics_args.append("--no-patching")

    remaining = [case for case in cases if case["case_id"] not in done]
    print(
        f"Cases: {len(cases)} total, {len(done)} already done, {len(remaining)} remaining; "
        f"workers={min(args.workers, max(1, len(remaining)))}"
    )
    write_incremental(bench, out_dir, rows, cases)
    if args.workers == 1:
        for index, case in enumerate(remaining, start=1):
            row = run_one(bench, case, basics_args, logs_dir, args.timeout_sec, out_dir)
            rows.append(row)
            write_incremental(bench, out_dir, rows, cases)
            print(
                f"[{index}/{len(remaining)}] {case['case_id']}: {row['status']} "
                f"reported={row['reported_vuln']} patched={row['patched']}",
                flush=True,
            )
    elif remaining:
        futures = {}
        with ThreadPoolExecutor(max_workers=min(args.workers, len(remaining))) as executor:
            for index, case in enumerate(remaining, start=1):
                future = executor.submit(run_one, bench, case, basics_args, logs_dir, args.timeout_sec, out_dir)
                futures[future] = (index, case)
            pending = set(futures)
            while pending:
                done_futures, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done_futures:
                    index, case = futures[future]
                    row = future.result()
                    with WRITE_LOCK:
                        rows.append(row)
                        write_incremental(bench, out_dir, rows, cases)
                    with PRINT_LOCK:
                        print(
                            f"[{len(rows)}/{len(cases)} done; job {index}/{len(remaining)}] "
                            f"{case['case_id']}: {row['status']} "
                            f"reported={row['reported_vuln']} patched={row['patched']}",
                            flush=True,
                        )

    csv_path, json_path = bench.write_results(out_dir, rows)
    write_incremental(bench, out_dir, rows, cases)
    print(f"Wrote low-memory sweep results:\n  CSV: {csv_path}\n  JSON: {json_path}")
    print(f"  Summary: {out_dir / 'summary.md'}")


if __name__ == "__main__":
    main()
