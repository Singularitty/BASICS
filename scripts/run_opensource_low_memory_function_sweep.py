#!/usr/bin/env python3
"""Run function-entry BASICS cases one process at a time with incremental results."""

from __future__ import annotations

import argparse
import importlib.util
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "opensource" / "opensource_function_cases_all.json"
RESULTS_DIR = ROOT / "Benchmarks" / "stack_benchmark" / "results"


def load_benchmark_module():
    path = ROOT / "scripts" / "run_basics_benchmark.py"
    spec = importlib.util.spec_from_file_location("basics_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Low-memory open-source function sweep. Each function is analyzed in a fresh BASICS subprocess."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--project", action="append", default=[], help="Project name without opensource/ prefix.")
    parser.add_argument("--case-id", action="append", default=[], help="Case id substring filter.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--timeout-sec", type=int, default=300)
    parser.add_argument("--cfg-mode", choices=["auto", "emulated", "fast"], default="fast")
    parser.add_argument("--function-simulation", choices=["auto", "static", "angr"], default="static")
    parser.add_argument("--patching", action="store_true", help="Enable patching. Default is detection-only.")
    parser.add_argument("--out-dir", type=Path, default=None, help="Resume/write into an existing result directory.")
    args = parser.parse_args()

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
    ]
    if not args.patching:
        basics_args.append("--no-patching")

    remaining = [case for case in cases if case["case_id"] not in done]
    print(f"Cases: {len(cases)} total, {len(done)} already done, {len(remaining)} remaining")
    for index, case in enumerate(remaining, start=1):
        row = bench.run_case(case, basics_args, logs_dir, args.timeout_sec)
        if isinstance(row, tuple):
            row = row[0]
        rows.append(row)
        bench.write_results(out_dir, rows)
        print(
            f"[{index}/{len(remaining)}] {case['case_id']}: {row['status']} "
            f"reported={row['reported_vuln']} patched={row['patched']}",
            flush=True,
        )

    csv_path, json_path = bench.write_results(out_dir, rows)
    print(f"Wrote low-memory sweep results:\n  CSV: {csv_path}\n  JSON: {json_path}")


if __name__ == "__main__":
    main()
