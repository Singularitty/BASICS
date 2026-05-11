#!/usr/bin/env python3
"""Run BASICS --scan-all-functions over open-source benchmark binaries."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "opensource" / "opensource_cases.json"
RESULTS_ROOT = ROOT / "Benchmarks" / "opensource" / "scan_results"


def load_cases(path: Path) -> list[dict]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, list):
        return obj
    if "cases" in obj:
        return obj["cases"]
    if "datasets" in obj:
        cases = []
        for data in obj["datasets"].values():
            cases.extend(data.get("cases", []))
        return cases
    raise ValueError(f"Unsupported manifest format: {path}")


def terminate_process_group(proc: subprocess.Popen) -> None:
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue


def run_interruptible(cmd: list[str], timeout_sec: int | None) -> tuple[int | None, str, str]:
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = proc.communicate(timeout=timeout_sec)
        return proc.returncode, output or "", ""
    except subprocess.TimeoutExpired:
        terminate_process_group(proc)
        output, _ = proc.communicate(timeout=5)
        return proc.returncode, output or "", "timeout"


def parse_scan_output(output: str) -> dict:
    row = {
        "functions_scanned": "",
        "scan_elapsed_sec": "",
        "vulnerable_functions": "",
        "clean_functions": "",
        "skipped_oom": "",
        "skipped_error": "",
        "reported_vuln": False,
        "vulnerable_function_names": "",
    }
    m = re.search(r"Scan complete:\s*(\d+)\s+functions\s+in\s+([0-9.]+)s", output)
    if m:
        row["functions_scanned"] = m.group(1)
        row["scan_elapsed_sec"] = m.group(2)
    for key, pattern in [
        ("vulnerable_functions", r"Vulnerable:\s*(\d+)"),
        ("clean_functions", r"Clean:\s*(\d+)"),
        ("skipped_oom", r"Skipped \(OOM\):\s*(\d+)"),
        ("skipped_error", r"Skipped \(err\):\s*(\d+)"),
    ]:
        m = re.search(pattern, output)
        if m:
            row[key] = m.group(1)
    row["reported_vuln"] = int(row["vulnerable_functions"] or 0) > 0

    names = []
    in_section = False
    for line in output.splitlines():
        if line.strip() == "-- Vulnerable functions --":
            in_section = True
            continue
        if in_section and line.startswith("-- "):
            break
        if in_section:
            m = re.match(r"\s*([^:]+):\s*(.+)", line)
            if m:
                names.append(m.group(1).strip())
    row["vulnerable_function_names"] = ";".join(names)
    return row


def run_case(case: dict, args, logs_dir: Path) -> dict:
    binary = ROOT / case["binary_path"]
    row = {
        "case_id": case["case_id"],
        "dataset": case.get("dataset", ""),
        "project": case.get("project", ""),
        "binary_path": case.get("binary_path", ""),
        "status": "ok",
        "error": "",
        "elapsed_sec": 0.0,
        "stdout_log_path": "",
        "functions_scanned": "",
        "scan_elapsed_sec": "",
        "vulnerable_functions": "",
        "clean_functions": "",
        "skipped_oom": "",
        "skipped_error": "",
        "reported_vuln": False,
        "vulnerable_function_names": "",
    }
    if not binary.exists():
        row["status"] = "missing_binary"
        row["error"] = str(binary)
        return row

    cmd = [
        "./run_basics.sh",
        "--scan-all-functions",
        "--scan-memory-limit-mb",
        str(args.scan_memory_limit_mb),
        "--concolic-step-limit",
        str(args.concolic_step_limit),
        str(binary),
    ]
    log_path = logs_dir / f"{case['case_id']}.log"
    start = time.perf_counter()
    returncode, output, run_error = run_interruptible(cmd, args.timeout_sec)
    row["elapsed_sec"] = round(time.perf_counter() - start, 4)
    log_path.write_text(output, encoding="utf-8")
    row["stdout_log_path"] = str(log_path.relative_to(ROOT))

    if run_error == "timeout":
        row["status"] = "timeout"
        row["error"] = f"timeout={args.timeout_sec}s"
        return row
    if returncode != 0:
        row["status"] = "run_error"
        row["error"] = f"exit={returncode}"

    row.update(parse_scan_output(output))
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description="Run BASICS --scan-all-functions on open-source benchmark binaries.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--project", action="append", default=[], help="Project name without opensource/ prefix.")
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument("--scan-memory-limit-mb", type=int, default=2500)
    parser.add_argument("--concolic-step-limit", type=int, default=100)
    args = parser.parse_args()

    cases = load_cases(args.manifest)
    if args.project:
        allowed = {f"opensource/{name}" for name in args.project}
        cases = [case for case in cases if case.get("dataset") in allowed]
    if args.case_id:
        needles = [needle.lower() for needle in args.case_id]
        cases = [case for case in cases if any(needle in case["case_id"].lower() for needle in needles)]
    if args.limit is not None:
        cases = cases[: args.limit]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = RESULTS_ROOT / stamp
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for index, case in enumerate(cases, start=1):
        row = run_case(case, args, logs_dir)
        rows.append(row)
        print(
            f"[{index}/{len(cases)}] {case['case_id']}: {row['status']} "
            f"functions={row['functions_scanned']} vulnerable={row['vulnerable_functions']}",
            flush=True,
        )

    csv_path = out_dir / "results.csv"
    json_path = out_dir / "results.json"
    fieldnames = list(rows[0].keys()) if rows else []
    if fieldnames:
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"Wrote scan results:\n  CSV: {csv_path}\n  JSON: {json_path}")


if __name__ == "__main__":
    main()
