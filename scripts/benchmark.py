#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "Benchmarks" / "stack_benchmark"

DATASETS = {
    "sard": {
        "manifest": STACK / "stack_cases_combined.json",
        "dataset": "SARD",
        "description": "SARD stack benchmark",
    },
    "juliet": {
        "manifest": STACK / "juliet_cwe121_isolated_cases.json",
        "dataset": None,
        "description": "Juliet CWE-121 isolated whole-binary benchmark",
    },
    "juliet-dynamic": {
        "manifest": STACK / "juliet_cwe121_dynamic_cases.json",
        "dataset": None,
        "description": "Juliet CWE-121 no-driver dynamic-tool subset",
    },
}


TOOLS = {
    "arbiter",
    "binabsinspector",
    "codeql",
    "cwe_checker",
    "flawfinder",
    "manticore",
    "rex",
    "valgrind",
}


def run(cmd: list[str]):
    print("$ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def newest_results(tool: str) -> Path | None:
    base = STACK / "external_results" / tool
    if not base.exists():
        return None
    results = sorted(base.glob("*/results.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return results[0] if results else None


def main():
    parser = argparse.ArgumentParser(
        description="Run one external benchmark: tool + dataset + timeout.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("tool", choices=sorted(TOOLS))
    parser.add_argument("dataset", choices=sorted(DATASETS))
    parser.add_argument("timeout", type=int, help="Per-case timeout in seconds.")
    parser.add_argument("--limit", type=int, default=None, help="Optional quick-test case limit.")
    parser.add_argument("--case-id", action="append", default=[], help="Optional substring filter; repeatable.")
    parser.add_argument("--prepare", action="store_true", help="Run the standard preparation step first.")
    parser.add_argument("--no-metrics", action="store_true", help="Do not print metrics after the run.")
    args = parser.parse_args()

    if args.prepare:
        prepare_cmd = ["python3", "scripts/prepare_external_benchmarks.py"]
        if args.dataset == "sard":
            prepare_cmd.append("--skip-juliet")
        elif args.dataset in {"juliet", "juliet-dynamic"}:
            prepare_cmd.append("--skip-sard")
        run(prepare_cmd)

    spec = DATASETS[args.dataset]
    cmd = [
        "python3",
        "scripts/run_external_tool_benchmark.py",
        "--manifest",
        str(spec["manifest"]),
        "--tool",
        args.tool,
        "--timeout-sec",
        str(args.timeout),
    ]
    if spec["dataset"]:
        cmd.extend(["--dataset", spec["dataset"]])
    if args.limit is not None:
        cmd.extend(["--limit", str(args.limit)])
    for case_id in args.case_id:
        cmd.extend(["--case-id", case_id])

    run(cmd)

    if not args.no_metrics:
        results = newest_results(args.tool)
        if results is not None:
            run(["python3", "scripts/calc_metrics.py", str(results), "--by-dataset"])


if __name__ == "__main__":
    main()
