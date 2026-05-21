#!/usr/bin/env python3
import argparse
import os
import re
import signal
import subprocess
import sys
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from benchmark import DATASETS, ROOT


CSV_RE = re.compile(r"^\s*CSV:\s*(.+results\.csv)\s*$")
PRINT_LOCK = threading.Lock()
ACTIVE_PROCS: set[subprocess.Popen] = set()
ACTIVE_PROCS_LOCK = threading.Lock()
STOP_EVENT = threading.Event()

DEFAULT_TOOLS = ("cwe_checker", "binabsinspector", "codeql", "flawfinder", "manticore")
DEFAULT_DATASETS = ("sard", "juliet")
EXCLUDED_TOOLS = {"arbiter", "valgrind", "rex"}
CASE_WORKER_DEFAULTS = {
    "cwe_checker": 4,
    "binabsinspector": 2,
    "codeql": 2,
    "flawfinder": min(16, os.cpu_count() or 1),
    "manticore": 1,
}


def parse_tool_workers(spec: str) -> tuple[str, int]:
    if "=" not in spec:
        raise argparse.ArgumentTypeError("expected TOOL=N")
    tool, raw_workers = spec.split("=", 1)
    if tool not in DEFAULT_TOOLS:
        raise argparse.ArgumentTypeError(f"unknown tool {tool!r}; choices: {', '.join(DEFAULT_TOOLS)}")
    try:
        workers = int(raw_workers)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid worker count {raw_workers!r}") from exc
    if workers < 1:
        raise argparse.ArgumentTypeError("worker count must be at least 1")
    return tool, workers


def print_line(prefix: str, line: str):
    with PRINT_LOCK:
        try:
            print(f"{prefix} {line}", flush=True)
        except BrokenPipeError:
            STOP_EVENT.set()


def terminate_process_group(proc: subprocess.Popen):
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


def terminate_active_processes():
    with ACTIVE_PROCS_LOCK:
        procs = list(ACTIVE_PROCS)
    for proc in procs:
        if proc.poll() is None:
            terminate_process_group(proc)


def run_streaming(cmd: list[str], prefix: str) -> tuple[int, list[Path]]:
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
        env=os.environ.copy(),
    )
    with ACTIVE_PROCS_LOCK:
        ACTIVE_PROCS.add(proc)
    csv_paths: list[Path] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if STOP_EVENT.is_set():
                terminate_process_group(proc)
                break
            line = line.rstrip("\n")
            match = CSV_RE.match(line)
            if match:
                csv_paths.append(Path(match.group(1)))
            print_line(prefix, line)
        return proc.wait(), csv_paths
    finally:
        with ACTIVE_PROCS_LOCK:
            ACTIVE_PROCS.discard(proc)


def write_stats(csv_path: Path, prefix: str) -> int:
    out_dir = csv_path.parent
    txt_path = out_dir / "stats.txt"
    json_path = out_dir / "stats.json"

    txt_cmd = ["python3", "scripts/calc_metrics.py", str(csv_path), "--by-dataset"]
    txt = subprocess.run(txt_cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    txt_path.write_text(txt.stdout, encoding="utf-8")
    for line in txt.stdout.rstrip().splitlines():
        print_line(prefix, line)
    if txt.returncode != 0:
        return txt.returncode

    json_cmd = ["python3", "scripts/calc_metrics.py", str(csv_path), "--by-dataset", "--json"]
    js = subprocess.run(json_cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    json_path.write_text(js.stdout, encoding="utf-8")
    if js.returncode != 0:
        print_line(prefix, js.stdout.rstrip())
        return js.returncode

    print_line(prefix, f"wrote stats: {txt_path}")
    print_line(prefix, f"wrote stats: {json_path}")
    return 0


def benchmark_command(args, tool: str, dataset: str, case_workers: int) -> list[str]:
    cmd = [
        "python3",
        "scripts/benchmark.py",
        tool,
        dataset,
        str(args.timeout),
        "--workers",
        str(case_workers),
        "--no-metrics",
    ]
    if args.limit is not None:
        cmd.extend(["--limit", str(args.limit)])
    for case_id in args.case_id:
        cmd.extend(["--case-id", case_id])
    return cmd


def run_job(args, index: int, total: int, tool: str, dataset: str, case_workers: int) -> dict:
    prefix = f"[{index}/{total} {tool}:{dataset}]"
    if STOP_EVENT.is_set():
        return {"tool": tool, "dataset": dataset, "returncode": 130}
    print_line(prefix, f"starting with {case_workers} case worker(s)")
    rc, csv_paths = run_streaming(benchmark_command(args, tool, dataset, case_workers), prefix)
    if rc == 0:
        for csv_path in csv_paths:
            stats_rc = write_stats(csv_path, prefix)
            if stats_rc != 0:
                rc = stats_rc
                break
    print_line(prefix, "finished ok" if rc == 0 else f"finished failed:{rc}")
    return {"tool": tool, "dataset": dataset, "returncode": rc}


def selected_jobs(args) -> list[tuple[str, str]]:
    tools = args.tool or list(DEFAULT_TOOLS)
    datasets = args.dataset or list(DEFAULT_DATASETS)
    jobs = [(tool, dataset) for tool in tools for dataset in datasets]
    seen = set()
    unique = []
    for job in jobs:
        if job in seen:
            continue
        seen.add(job)
        unique.append(job)
    return unique


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Schedule external tool benchmarks for SARD and Juliet, excluding "
            "arbiter, valgrind, and unsupported REX, and write stats next to results."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--tool", action="append", choices=DEFAULT_TOOLS, default=[], help="Tool to run; repeatable.")
    parser.add_argument("--dataset", action="append", choices=DEFAULT_DATASETS, default=[], help="Dataset to run; repeatable.")
    parser.add_argument("--jobs", type=int, default=2, help="Concurrent tool/dataset jobs.")
    parser.add_argument("--timeout", type=int, default=300, help="Per-case timeout in seconds.")
    parser.add_argument("--case-workers", type=int, default=None, help="Override per-tool case workers for every tool.")
    parser.add_argument(
        "--tool-workers",
        action="append",
        type=parse_tool_workers,
        default=[],
        help="Override case workers for one tool, for example flawfinder=32. Repeatable.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Optional quick-test case limit per tool/dataset.")
    parser.add_argument("--case-id", action="append", default=[], help="Optional substring filter; repeatable.")
    args = parser.parse_args()

    if args.jobs < 1:
        parser.error("--jobs must be at least 1")
    if args.case_workers is not None and args.case_workers < 1:
        parser.error("--case-workers must be at least 1")

    tool_workers = dict(CASE_WORKER_DEFAULTS)
    tool_workers.update(dict(args.tool_workers))
    if args.case_workers is not None:
        tool_workers = {tool: args.case_workers for tool in tool_workers}

    jobs = selected_jobs(args)
    if not jobs:
        parser.error("no benchmark jobs selected")

    total = len(jobs)
    workers = min(args.jobs, total)
    print(f"Scheduling {total} benchmark job(s) with {workers} concurrent job(s).", flush=True)
    print(f"Excluded tools: {', '.join(sorted(EXCLUDED_TOOLS))}.", flush=True)

    failures = []
    executor = ThreadPoolExecutor(max_workers=workers)
    pending = list(enumerate(jobs, start=1))
    futures = set()
    try:
        while (pending or futures) and not STOP_EVENT.is_set():
            while pending and len(futures) < workers and not STOP_EVENT.is_set():
                index, (tool, dataset) = pending.pop(0)
                futures.add(executor.submit(run_job, args, index, total, tool, dataset, tool_workers[tool]))
            done, futures = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                result = future.result()
                if result["returncode"] != 0:
                    failures.append(result)
    except KeyboardInterrupt:
        STOP_EVENT.set()
        print("\nInterrupted. Stopping active benchmarks and leaving queued jobs unstarted.", flush=True)
        terminate_active_processes()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        return 130
    finally:
        if STOP_EVENT.is_set():
            terminate_active_processes()
            executor.shutdown(wait=False, cancel_futures=True)
        else:
            executor.shutdown(wait=True)

    if failures:
        print("\nFailed jobs:", flush=True)
        for result in failures:
            print(f"  {result['tool']}:{result['dataset']} exit={result['returncode']}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
