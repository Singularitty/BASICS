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
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "opensource" / "opensource_cases.json"
RESULTS_ROOT = ROOT / "Benchmarks" / "opensource" / "scan_results"
WRITE_LOCK = threading.Lock()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


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
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()
        return proc.returncode, output or "", "timeout"


def parse_scan_output(output: str) -> dict:
    row = {
        "functions_scanned": "",
        "scan_elapsed_sec": "",
        "candidate_functions": "",
        "confirmed_functions": "",
        "vulnerable_functions": "",
        "unconfirmed_functions": "",
        "context_unknown_functions": "",
        "low_confidence_functions": "",
        "clean_functions": "",
        "skipped_oom": "",
        "skipped_error": "",
        "reported_vuln": False,
        "vulnerable_function_names": "",
        "unconfirmed_function_names": "",
        "context_unknown_function_names": "",
    }
    m = re.search(r"Scan complete:\s*(\d+)\s+functions\s+in\s+([0-9.]+)s", output)
    if m:
        row["functions_scanned"] = m.group(1)
        row["scan_elapsed_sec"] = m.group(2)
    for key, pattern in [
        ("candidate_functions", r"Candidates:\s*(\d+)"),
        ("confirmed_functions", r"Confirmed:\s*(\d+)"),
        ("vulnerable_functions", r"Vulnerable:\s*(\d+)"),
        ("unconfirmed_functions", r"Unconfirmed:\s*(\d+)"),
        ("context_unknown_functions", r"Context unknown:\s*(\d+)"),
        ("low_confidence_functions", r"Low-confidence:\s*(\d+)"),
        ("clean_functions", r"Clean:\s*(\d+)"),
        ("skipped_oom", r"Skipped \(OOM\):\s*(\d+)"),
        ("skipped_error", r"Skipped \(err\):\s*(\d+)"),
    ]:
        m = re.search(pattern, output)
        if m:
            row[key] = m.group(1)
    row["reported_vuln"] = int(row["vulnerable_functions"] or 0) > 0

    names = []
    unconfirmed_names = []
    unknown_names = []
    in_section = False
    section = None
    for line in output.splitlines():
        if line.strip() == "-- Vulnerable functions --":
            in_section = True
            section = "vulnerable"
            continue
        if line.strip() == "-- Unconfirmed functions --":
            in_section = True
            section = "unconfirmed"
            continue
        if line.strip() == "-- Caller-context unknown functions --":
            in_section = True
            section = "unknown"
            continue
        if in_section and line.startswith("-- "):
            section = None
            break
        if in_section:
            m = re.match(r"\s*([^:]+):\s*(.+)", line)
            if m:
                if section == "vulnerable":
                    names.append(m.group(1).strip())
                elif section == "unconfirmed":
                    unconfirmed_names.append(m.group(1).strip())
                elif section == "unknown":
                    unknown_names.append(m.group(1).strip())
    row["vulnerable_function_names"] = ";".join(names)
    row["unconfirmed_function_names"] = ";".join(unconfirmed_names)
    row["context_unknown_function_names"] = ";".join(unknown_names)
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
        "started_at": "",
        "finished_at": "",
        "elapsed_sec": 0.0,
        "stdout_log_path": "",
        "functions_scanned": "",
        "scan_elapsed_sec": "",
        "candidate_functions": "",
        "confirmed_functions": "",
        "vulnerable_functions": "",
        "unconfirmed_functions": "",
        "context_unknown_functions": "",
        "low_confidence_functions": "",
        "clean_functions": "",
        "skipped_oom": "",
        "skipped_error": "",
        "reported_vuln": False,
        "vulnerable_function_names": "",
        "unconfirmed_function_names": "",
        "context_unknown_function_names": "",
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
    if args.scan_constrain_arg_regs:
        cmd.insert(-1, "--scan-constrain-arg-regs")
        cmd.insert(-1, "--scan-arg-stack-guard-bytes")
        cmd.insert(-1, str(args.scan_arg_stack_guard_bytes))
    if not args.include_rbp_only_findings:
        cmd.insert(-1, "--scan-suppress-rbp-only")
    if args.scan_include_runtime_symbols:
        cmd.insert(-1, "--scan-include-runtime-symbols")
    if args.scan_confirm_callers:
        cmd.insert(-1, "--scan-confirm-callers")
        cmd.insert(-1, "--scan-confirm-max-callers")
        cmd.insert(-1, str(args.scan_confirm_max_callers))
        if args.scan_confirm_max_states is not None:
            cmd.insert(-1, "--scan-confirm-max-states")
            cmd.insert(-1, str(args.scan_confirm_max_states))
    if args.scan_skip_loopfinder:
        cmd.insert(-1, "--scan-skip-loopfinder")
    if args.hard_memory_limit_mb is not None:
        cmd.insert(-1, "--hard-memory-limit-mb")
        cmd.insert(-1, str(args.hard_memory_limit_mb))
    log_path = logs_dir / f"{case['case_id']}.log"
    row["started_at"] = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    returncode, output, run_error = run_interruptible(cmd, args.timeout_sec)
    row["elapsed_sec"] = round(time.perf_counter() - start, 4)
    row["finished_at"] = datetime.now(timezone.utc).isoformat()
    log_path.write_text(output, encoding="utf-8")
    row["stdout_log_path"] = display_path(log_path)

    if run_error == "timeout":
        row["status"] = "timeout"
        row["error"] = f"timeout={args.timeout_sec}s"
        return row
    if returncode != 0:
        row["status"] = "run_error"
        row["error"] = f"exit={returncode}"

    row.update(parse_scan_output(output))
    return row


def summarize(rows: list[dict], cases: list[dict]) -> dict:
    projects = sorted({case.get("project") for case in cases if case.get("project")})
    packages = sorted({case.get("package") for case in cases if case.get("package")})
    statuses: dict[str, int] = {}
    total_functions = 0
    vulnerable_functions = 0
    candidate_functions = 0
    confirmed_functions = 0
    unconfirmed_functions = 0
    context_unknown_functions = 0
    low_confidence_functions = 0
    clean_functions = 0
    skipped_oom = 0
    skipped_error = 0
    reported_binaries = []
    elapsed_values = []
    scan_elapsed_values = []
    for row in rows:
        statuses[row.get("status", "")] = statuses.get(row.get("status", ""), 0) + 1
        total_functions += int(row.get("functions_scanned") or 0)
        candidate_functions += int(row.get("candidate_functions") or 0)
        confirmed_functions += int(row.get("confirmed_functions") or 0)
        vulnerable_functions += int(row.get("vulnerable_functions") or 0)
        unconfirmed_functions += int(row.get("unconfirmed_functions") or 0)
        context_unknown_functions += int(row.get("context_unknown_functions") or 0)
        low_confidence_functions += int(row.get("low_confidence_functions") or 0)
        clean_functions += int(row.get("clean_functions") or 0)
        skipped_oom += int(row.get("skipped_oom") or 0)
        skipped_error += int(row.get("skipped_error") or 0)
        if row.get("elapsed_sec") not in {"", None}:
            elapsed_values.append(float(row["elapsed_sec"]))
        if row.get("scan_elapsed_sec") not in {"", None}:
            scan_elapsed_values.append(float(row["scan_elapsed_sec"]))
        if row.get("reported_vuln") in {True, "True", "true", "1", 1}:
            reported_binaries.append(row.get("case_id", ""))
    total_elapsed = sum(elapsed_values)
    avg_elapsed = total_elapsed / len(elapsed_values) if elapsed_values else 0.0
    max_elapsed = max(elapsed_values) if elapsed_values else 0.0
    avg_scan_elapsed = sum(scan_elapsed_values) / len(scan_elapsed_values) if scan_elapsed_values else 0.0
    return {
        "projects": len(projects),
        "project_names": projects,
        "packages": len(packages),
        "package_names": packages,
        "binaries_selected": len(cases),
        "binaries_completed": len(rows),
        "binaries_reported_vulnerable": len(reported_binaries),
        "functions_scanned": total_functions,
        "candidate_functions": candidate_functions,
        "confirmed_functions": confirmed_functions,
        "vulnerable_functions": vulnerable_functions,
        "unconfirmed_functions": unconfirmed_functions,
        "context_unknown_functions": context_unknown_functions,
        "low_confidence_functions": low_confidence_functions,
        "clean_functions": clean_functions,
        "skipped_oom": skipped_oom,
        "skipped_error": skipped_error,
        "total_binary_elapsed_sec": round(total_elapsed, 4),
        "avg_binary_elapsed_sec": round(avg_elapsed, 4),
        "max_binary_elapsed_sec": round(max_elapsed, 4),
        "avg_basics_scan_elapsed_sec": round(avg_scan_elapsed, 4),
        "statuses": statuses,
        "reported_binary_case_ids": reported_binaries,
    }


def write_results(out_dir: Path, rows: list[dict], cases: list[dict]) -> tuple[Path, Path]:
    csv_path = out_dir / "results.csv"
    json_path = out_dir / "results.json"
    fieldnames = list(rows[0].keys()) if rows else []
    if fieldnames:
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    summary = summarize(rows, cases)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "summary.md").write_text(
        "\n".join(
            [
                "| Metric | Value |",
                "|---|---:|",
                f"| Projects | {summary['projects']} |",
                f"| Packages | {summary['packages']} |",
                f"| Binaries selected | {summary['binaries_selected']} |",
                f"| Binaries completed | {summary['binaries_completed']} |",
                f"| Binaries reported vulnerable | {summary['binaries_reported_vulnerable']} |",
                f"| Functions scanned | {summary['functions_scanned']} |",
                f"| Candidate functions | {summary['candidate_functions']} |",
                f"| Confirmed functions | {summary['confirmed_functions']} |",
                f"| Vulnerable functions | {summary['vulnerable_functions']} |",
                f"| Unconfirmed functions | {summary['unconfirmed_functions']} |",
                f"| Context unknown functions | {summary['context_unknown_functions']} |",
                f"| Low-confidence functions | {summary['low_confidence_functions']} |",
                f"| Skipped OOM | {summary['skipped_oom']} |",
                f"| Skipped error | {summary['skipped_error']} |",
                f"| Total binary elapsed sec | {summary['total_binary_elapsed_sec']} |",
                f"| Avg binary elapsed sec | {summary['avg_binary_elapsed_sec']} |",
                f"| Max binary elapsed sec | {summary['max_binary_elapsed_sec']} |",
                f"| Avg BASICS scan elapsed sec | {summary['avg_basics_scan_elapsed_sec']} |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return csv_path, json_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run BASICS --scan-all-functions on open-source benchmark binaries.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--project", action="append", default=[], help="Project name without opensource/ prefix.")
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--out-dir", type=Path, default=None, help="Resume/write into an existing result directory.")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument("--scan-memory-limit-mb", type=int, default=2500)
    parser.add_argument("--concolic-step-limit", type=int, default=100)
    parser.add_argument("--scan-arg-stack-guard-bytes", default="0x200000")
    parser.add_argument("--scan-constrain-arg-regs", action="store_true")
    parser.add_argument("--include-rbp-only-findings", action="store_true")
    parser.add_argument("--scan-include-runtime-symbols", action="store_true")
    parser.add_argument("--scan-confirm-callers", action="store_true")
    parser.add_argument("--scan-confirm-max-callers", type=int, default=4)
    parser.add_argument("--scan-confirm-max-states", type=int, default=None)
    parser.add_argument("--scan-skip-loopfinder", action="store_true")
    parser.add_argument("--hard-memory-limit-mb", type=int, default=None)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    cases = load_cases(args.manifest)
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
        out_dir = RESULTS_ROOT / stamp
    else:
        out_dir = args.out_dir
        if not out_dir.is_absolute():
            out_dir = ROOT / out_dir
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    existing_json = out_dir / "results.json"
    if existing_json.exists():
        rows = json.loads(existing_json.read_text(encoding="utf-8"))
    done_case_ids = {row.get("case_id") for row in rows}
    remaining_cases = [case for case in cases if case.get("case_id") not in done_case_ids]
    write_results(out_dir, rows, cases)
    if args.workers == 1:
        for index, case in enumerate(remaining_cases, start=1):
            row = run_case(case, args, logs_dir)
            rows.append(row)
            write_results(out_dir, rows, cases)
            print(
                f"[{len(rows)}/{len(cases)} done; job {index}/{len(remaining_cases)}] {case['case_id']}: {row['status']} "
                f"functions={row['functions_scanned']} vulnerable={row['vulnerable_functions']}",
                flush=True,
            )
    elif remaining_cases:
        futures = {}
        with ThreadPoolExecutor(max_workers=min(args.workers, len(remaining_cases))) as executor:
            for index, case in enumerate(remaining_cases, start=1):
                futures[executor.submit(run_case, case, args, logs_dir)] = (index, case)
            pending = set(futures)
            while pending:
                done_futures, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done_futures:
                    index, case = futures[future]
                    row = future.result()
                    with WRITE_LOCK:
                        rows.append(row)
                        write_results(out_dir, rows, cases)
                    print(
                        f"[{len(rows)}/{len(cases)} done; job {index}] {case['case_id']}: {row['status']} "
                        f"functions={row['functions_scanned']} vulnerable={row['vulnerable_functions']}",
                        flush=True,
                    )

    csv_path, json_path = write_results(out_dir, rows, cases)
    print(f"Wrote scan results:\n  CSV: {csv_path}\n  JSON: {json_path}")
    print(f"  Summary: {out_dir / 'summary.md'}")


if __name__ == "__main__":
    main()
