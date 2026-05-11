#!/usr/bin/env python3
"""
Juliet CWE-121 (Stack-Based Buffer Overflow) evaluation for BASICS.

For each compiled test binary:
  - Runs BASICS targeting the _bad function  → expects violation  (TP if found, FN if not)
  - Runs BASICS targeting the _good function → expects no violation (TN if clean, FP if flagged)

Outputs per-binary results, then precision / recall / F1.

Usage:
  python3 scripts/juliet_cwe121_eval.py [--timeout SEC] [--workers N]
                                        [--limit N] [--out FILE]
                                        [--cwe-dir PATH]
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASICS_DIR = Path(__file__).resolve().parent.parent
RUN_SCRIPT = BASICS_DIR / "run_basics.sh"
DEFAULT_CWE_DIR = (
    BASICS_DIR / "Benchmarks/C/testcases/CWE121_Stack_Based_Buffer_Overflow"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_cwe_functions(binary: Path):
    """Return (bad_func, good_func) by inspecting the symbol table."""
    try:
        out = subprocess.check_output(["nm", str(binary)], stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return None, None

    bad_func = good_func = None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] != "T":
            continue
        name = parts[2]
        if not name.startswith("CWE"):
            continue
        # Accept exactly _bad / _good suffix (not _badSink etc.)
        if name.endswith("_bad") and bad_func is None:
            bad_func = name
        elif name.endswith("_good") and good_func is None:
            good_func = name

    return bad_func, good_func


def run_basics(binary: Path, entry: str, timeout: int, concolic_step_limit: int):
    """
    Run BASICS on *binary* starting from *entry*.
    Returns (violated: bool|None, elapsed: float, output: str).
    None means timeout or crash.
    """
    cmd = [
        "bash", str(RUN_SCRIPT),
        str(binary),
        "--analysis-entry", entry,
        "--cfg-mode", "fast",
        "--concolic-step-limit", str(concolic_step_limit),
        "--no-patching",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(BASICS_DIR),
        )
        output = result.stdout + result.stderr
        # Heuristic: look for the violation/no-violation summary lines
        if "No security property violations found" in output:
            return False, output
        if "security property violations found" in output:
            return True, output
        # Fallback: if report section exists but no clear verdict, treat as no-violation
        if "Model Checking Report" in output:
            return False, output
        return None, output          # crashed / unknown
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT"
    except Exception as exc:
        return None, str(exc)


def evaluate_binary(binary: Path, timeout: int, concolic_step_limit: int):
    """Evaluate one binary. Returns a result dict."""
    bad_func, good_func = get_cwe_functions(binary)

    result = {
        "binary": str(binary.relative_to(BASICS_DIR)),
        "bad_func": bad_func,
        "good_func": good_func,
        "bad_result": None,   # True=violated, False=clean, None=skip/timeout
        "good_result": None,
        "bad_output": "",
        "good_output": "",
        "tp": 0, "fn": 0, "fp": 0, "tn": 0, "skip": 0,
    }

    if bad_func is None and good_func is None:
        result["skip"] = 1
        return result

    if bad_func:
        violated, output = run_basics(binary, bad_func, timeout, concolic_step_limit)
        result["bad_result"] = violated
        result["bad_output"] = output
        if violated is True:
            result["tp"] = 1
        elif violated is False:
            result["fn"] = 1
        else:
            result["skip"] += 1

    if good_func:
        violated, output = run_basics(binary, good_func, timeout, concolic_step_limit)
        result["good_result"] = violated
        result["good_output"] = output
        if violated is False:
            result["tn"] = 1
        elif violated is True:
            result["fp"] = 1
        else:
            result["skip"] += 1

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=int, default=60, metavar="SEC",
                        help="Per-function BASICS timeout in seconds (default: 60)")
    parser.add_argument("--concolic-step-limit", type=int, default=200, metavar="N",
                        help="angr steps per loop/call reachability query (default: 200)")
    parser.add_argument("--workers", type=int, default=1, metavar="N",
                        help="Parallel workers (default: 1; increase carefully — angr is memory-hungry)")
    parser.add_argument("--limit", type=int, default=None, metavar="N",
                        help="Analyse only the first N binaries (for quick smoke tests)")
    parser.add_argument("--out", default=None, metavar="FILE",
                        help="Write per-binary results as CSV to FILE")
    parser.add_argument("--cwe-dir", default=str(DEFAULT_CWE_DIR), metavar="PATH",
                        help="Root directory of the CWE121 test cases")
    parser.add_argument("--include", default=None, metavar="REGEX",
                        help="Only evaluate binaries whose path matches REGEX")
    parser.add_argument("--exclude", default=None, metavar="REGEX",
                        help="Skip binaries whose path matches REGEX")
    args = parser.parse_args()

    cwe_dir = Path(args.cwe_dir).resolve()
    # Only include numbered C-variant binaries (source is a .c file, not .cpp).
    # This matches the paper's 1,762 instances and excludes the C++ class-based
    # combined binaries (_82.out, _83.out …) whose source spans multiple files.
    binaries = sorted(
        b for b in cwe_dir.rglob("*.out")
        if b.with_suffix(".c").exists()
    )
    if args.include:
        include_re = re.compile(args.include)
        binaries = [b for b in binaries if include_re.search(str(b))]
    if args.exclude:
        exclude_re = re.compile(args.exclude)
        binaries = [b for b in binaries if not exclude_re.search(str(b))]
    if args.limit:
        binaries = binaries[: args.limit]

    if not binaries:
        print(f"No .out files found under {cwe_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(binaries)} binaries under {cwe_dir.name}")
    print(f"Timeout: {args.timeout}s  Workers: {args.workers}  Concolic steps: {args.concolic_step_limit}\n")

    results = []
    done = 0

    def _run(binary):
        return evaluate_binary(binary, args.timeout, args.concolic_step_limit)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_run, b): b for b in binaries}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            done += 1

            bad_sym  = "✓" if r["tp"] else ("✗" if r["fn"] else "?")
            good_sym = "✓" if r["tn"] else ("✗" if r["fp"] else "?")
            # ? = timeout or crash (no verdict); ✓ = correct; ✗ = wrong
            binary_name = Path(r["binary"]).name
            bad_detail  = "" if bad_sym  != "?" else f"  [bad:{r['bad_output'][:40].strip()!r}]"
            good_detail = "" if good_sym != "?" else f"  [good:{r['good_output'][:40].strip()!r}]"
            print(f"[{done:>4}/{len(binaries)}] bad={bad_sym}  good={good_sym}  {binary_name}{bad_detail}{good_detail}", flush=True)

    # Totals
    tp = sum(r["tp"] for r in results)
    fn = sum(r["fn"] for r in results)
    fp = sum(r["fp"] for r in results)
    tn = sum(r["tn"] for r in results)
    sk = sum(r["skip"] for r in results)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("\n" + "=" * 60)
    print("Juliet CWE-121 Evaluation — BASICS")
    print("=" * 60)
    print(f"  True Positives  (bad detected):      {tp}")
    print(f"  False Negatives (bad missed):         {fn}")
    print(f"  True Negatives  (good clean):         {tn}")
    print(f"  False Positives (good flagged):       {fp}")
    print(f"  Skipped / timeout:                    {sk}")
    print(f"  Precision:  {precision:.3f}")
    print(f"  Recall:     {recall:.3f}")
    print(f"  F1:         {f1:.3f}")
    print(f"  FPR:        {fpr:.3f}")

    # Optional CSV output
    if args.out:
        fieldnames = [
            "binary", "bad_func", "good_func",
            "bad_result", "good_result",
            "tp", "fn", "fp", "tn", "skip",
        ]
        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
        print(f"\nPer-binary results written to {args.out}")

    # Also save JSON summary
    summary = {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn, "skipped": sk,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "n_binaries": len(binaries),
        "timeout_sec": args.timeout,
    }
    summary_path = BASICS_DIR / "reports" / "juliet_cwe121_summary.json"
    summary_path.parent.mkdir(exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary JSON written to {summary_path.relative_to(BASICS_DIR)}")


if __name__ == "__main__":
    main()
