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

from benchmark import DATASETS, TOOLS, ROOT


CSV_RE = re.compile(r"^\s*CSV:\s*(.+results\.csv)\s*$")
PRINT_LOCK = threading.Lock()
ACTIVE_PROCS: set[subprocess.Popen] = set()
ACTIVE_PROCS_LOCK = threading.Lock()
STOP_EVENT = threading.Event()
ALL_TOOLS = TOOLS | {"basics"}

RECOMMENDED_SUITE = [
    ("basics", "sard"),
    ("basics", "juliet"),
    ("cwe_checker", "sard"),
    ("cwe_checker", "juliet"),
    ("binabsinspector", "sard"),
    ("binabsinspector", "juliet"),
    ("codeql", "sard"),
    ("codeql", "juliet"),
    ("flawfinder", "sard"),
    ("flawfinder", "juliet"),
    ("manticore", "sard"),
    ("valgrind", "sard"),
    ("manticore", "juliet-dynamic"),
    ("valgrind", "juliet-dynamic"),
]

EXHAUSTIVE_SUITE = [
    (tool, dataset)
    for tool in sorted(ALL_TOOLS - {"arbiter", "rex"})
    for dataset in ("sard", "juliet", "juliet-dynamic")
    if not (tool == "basics" and dataset == "juliet-dynamic")
]


def parse_job(spec: str) -> tuple[str, str]:
    if ":" not in spec:
        raise argparse.ArgumentTypeError(f"job must be TOOL:DATASET, got {spec!r}")
    tool, dataset = spec.split(":", 1)
    if tool not in ALL_TOOLS:
        raise argparse.ArgumentTypeError(f"unknown tool {tool!r}; choices: {', '.join(sorted(ALL_TOOLS))}")
    if dataset not in DATASETS:
        raise argparse.ArgumentTypeError(f"unknown dataset {dataset!r}; choices: {', '.join(sorted(DATASETS))}")
    return tool, dataset


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


def run_streaming(cmd: list[str], prefix: str) -> tuple[int, str, list[Path]]:
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
    lines: list[str] = []
    csv_paths: list[Path] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if STOP_EVENT.is_set():
                terminate_process_group(proc)
                break
            line = line.rstrip("\n")
            lines.append(line)
            match = CSV_RE.match(line)
            if match:
                csv_paths.append(Path(match.group(1)))
            print_line(prefix, line)
        return proc.wait(), "\n".join(lines), csv_paths
    finally:
        with ACTIVE_PROCS_LOCK:
            ACTIVE_PROCS.discard(proc)


def benchmark_command(args, tool: str, dataset: str) -> list[str]:
    if tool == "basics":
        spec = DATASETS[dataset]
        cmd = [
            "python3",
            "scripts/run_basics_benchmark.py",
            "--manifest",
            str(spec["manifest"]),
            "--timeout-sec",
            str(args.timeout),
            "--cfg-mode",
            args.basics_cfg_mode,
            "--function-simulation",
            args.basics_simulation,
            "--patched-function-simulation",
            args.basics_simulation,
        ]
        if spec["dataset"]:
            cmd.extend(["--dataset", spec["dataset"]])
        if not args.basics_patching:
            cmd.append("--no-patching")
    else:
        cmd = [
            "python3",
            "scripts/benchmark.py",
            tool,
            dataset,
            str(args.timeout),
            "--no-metrics",
        ]
    if args.limit is not None:
        cmd.extend(["--limit", str(args.limit)])
    for case_id in args.case_id:
        cmd.extend(["--case-id", case_id])
    return cmd


def run_job(args, index: int, total: int, tool: str, dataset: str) -> dict:
    prefix = f"[{index}/{total} {tool}:{dataset}]"
    if STOP_EVENT.is_set():
        return {
            "tool": tool,
            "dataset": dataset,
            "returncode": 130,
            "csv_paths": [],
            "output": "skipped because benchmark queue was interrupted",
        }
    print_line(prefix, "starting")
    rc, output, csv_paths = run_streaming(benchmark_command(args, tool, dataset), prefix)
    metric_rc = None
    if rc == 0 and not args.no_metrics:
        for csv_path in csv_paths:
            metric_cmd = ["python3", "scripts/calc_metrics.py", str(csv_path), "--by-dataset"]
            metric_rc, _, _ = run_streaming(metric_cmd, prefix)
            if metric_rc != 0:
                rc = metric_rc
                break
    status = "ok" if rc == 0 else f"failed:{rc}"
    print_line(prefix, f"finished {status}")
    return {
        "tool": tool,
        "dataset": dataset,
        "returncode": rc,
        "csv_paths": csv_paths,
        "output": output,
    }


def expand_jobs(args) -> list[tuple[str, str]]:
    jobs = list(args.job)
    if args.suite == "recommended":
        jobs.extend(RECOMMENDED_SUITE)
    elif args.suite == "exhaustive":
        jobs.extend(EXHAUSTIVE_SUITE)
    if args.tool or args.dataset:
        tools = args.tool or sorted(ALL_TOOLS)
        datasets = args.dataset or sorted(DATASETS)
        jobs.extend((tool, dataset) for tool in tools for dataset in datasets)
    seen = set()
    unique_jobs = []
    for job in jobs:
        if job in seen:
            continue
        seen.add(job)
        unique_jobs.append(job)
    return unique_jobs


def main():
    parser = argparse.ArgumentParser(
        description="Run multiple external benchmarks with a fixed-size worker pool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "job",
        nargs="*",
        type=parse_job,
        help="Benchmark job as TOOL:DATASET, for example cwe_checker:sard.",
    )
    parser.add_argument("--tool", action="append", choices=sorted(ALL_TOOLS), default=[], help="Tool to include in a tool x dataset grid.")
    parser.add_argument("--dataset", action="append", choices=sorted(DATASETS), default=[], help="Dataset to include in a tool x dataset grid.")
    parser.add_argument(
        "--suite",
        choices=["recommended", "exhaustive"],
        default=None,
        help=(
            "Preset queue. recommended runs SARD and Juliet for static/source tools, "
            "and SARD plus juliet-dynamic for runtime tools. exhaustive runs every "
            "available non-experimental tool over sard, juliet, and juliet-dynamic."
        ),
    )
    parser.add_argument("--jobs", type=int, default=2, help="Number of benchmarks to run concurrently.")
    parser.add_argument("--timeout", type=int, default=300, help="Per-case timeout in seconds.")
    parser.add_argument("--limit", type=int, default=None, help="Optional quick-test case limit passed to each benchmark.")
    parser.add_argument("--case-id", action="append", default=[], help="Optional substring filter passed to each benchmark; repeatable.")
    parser.add_argument("--no-metrics", action="store_true", help="Skip metrics after each finished benchmark.")
    parser.add_argument("--basics-cfg-mode", choices=["auto", "emulated", "fast"], default="fast", help="CFG mode for basics jobs.")
    parser.add_argument("--basics-simulation", choices=["auto", "static", "angr"], default="static", help="Function simulation mode for basics jobs.")
    parser.add_argument("--basics-patching", action="store_true", help="Enable BASICS patch generation/validation. By default BASICS jobs run detection only, matching scripts/run_compiled_stack_benchmarks.sh.")
    parser.add_argument("--basics-no-patching", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.basics_patching and args.basics_no_patching:
        parser.error("--basics-patching and --basics-no-patching are mutually exclusive")

    jobs = expand_jobs(args)
    if not jobs:
        parser.error("provide at least one TOOL:DATASET job, or use --tool/--dataset")
    if args.jobs < 1:
        parser.error("--jobs must be at least 1")

    total = len(jobs)
    workers = min(args.jobs, total)
    print(f"Running {total} benchmark job(s) with {workers} worker(s).", flush=True)

    failures = []
    executor = ThreadPoolExecutor(max_workers=workers)
    pending_jobs = list(enumerate(jobs, start=1))
    futures = set()
    try:
        while (pending_jobs or futures) and not STOP_EVENT.is_set():
            while pending_jobs and len(futures) < workers and not STOP_EVENT.is_set():
                index, (tool, dataset) = pending_jobs.pop(0)
                futures.add(executor.submit(run_job, args, index, total, tool, dataset))
            done, futures = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                result = future.result()
                if result["returncode"] != 0:
                    failures.append(result)
    except KeyboardInterrupt:
        STOP_EVENT.set()
        print("\nInterrupted. Stopping running benchmarks and leaving queued jobs unstarted.", flush=True)
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
