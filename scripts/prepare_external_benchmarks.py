#!/usr/bin/env python3
"""
Standard preparation step for external-tool benchmarks.

This creates the manifests used by external tools and compiles the binaries
ahead of time. Tool runners should then analyze existing binaries only.
"""

import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "Benchmarks" / "stack_benchmark"


def run_step(cmd: list[str]):
    script = ROOT / cmd[1] if len(cmd) > 1 and str(cmd[1]).startswith("scripts/") else None
    if script is not None and not script.exists():
        raise SystemExit(
            f"Missing required prep script: {script}\n"
            "Sync the repository scripts before running this command."
        )
    print("$ " + " ".join(str(part) for part in cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description="Prepare manifests and precompiled binaries for external benchmarks.")
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--skip-sard", action="store_true")
    parser.add_argument("--skip-juliet", action="store_true")
    parser.add_argument("--force", action="store_true", help="Recompile binaries even if they already exist.")
    args = parser.parse_args()

    if not args.skip_sard:
        run_step(["python3", "scripts/prepare_stack_datasets.py"])
        run_step(
            [
                "python3",
                "scripts/prepare_benchmark_binaries.py",
                "--manifest",
                str(STACK / "stack_cases_combined.json"),
                "--dataset",
                "SARD",
                "--workers",
                str(args.workers),
                "--timeout-sec",
                str(args.timeout_sec),
                "--out",
                str(STACK / "sard_prepare_report.json"),
            ]
            + (["--force"] if args.force else [])
        )

    if not args.skip_juliet:
        run_step(["python3", "scripts/prepare_juliet_cwe121_isolated_manifest.py"])
        run_step(["python3", "scripts/prepare_juliet_cwe121_dynamic_manifest.py"])
        run_step(
            [
                "python3",
                "scripts/prepare_benchmark_binaries.py",
                "--manifest",
                str(STACK / "juliet_cwe121_isolated_cases.json"),
                "--workers",
                str(args.workers),
                "--timeout-sec",
                str(args.timeout_sec),
                "--out",
                str(STACK / "juliet_cwe121_isolated_prepare_report.json"),
            ]
            + (["--force"] if args.force else [])
        )

    print("\nPrepared external benchmark inputs:")
    if not args.skip_juliet:
        print(f"  Juliet isolated: {STACK / 'juliet_cwe121_isolated_cases.json'}")
        print(f"  Juliet dynamic : {STACK / 'juliet_cwe121_dynamic_cases.json'}")
    if not args.skip_sard:
        print(f"  SARD           : {STACK / 'stack_cases_combined.json'} --dataset SARD")


if __name__ == "__main__":
    main()
