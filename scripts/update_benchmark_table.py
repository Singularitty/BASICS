#!/usr/bin/env python3
"""
Keep the README benchmark table in sync with benchmarks/results.json.

Usage:
  # Re-render the README table from benchmarks/results.json
  python3 scripts/update_benchmark_table.py

  # Publish a finished run as the current result for a dataset
  python3 scripts/update_benchmark_table.py \
      --dataset "Juliet CWE-121" \
      --run Benchmarks/stack_benchmark/results/<run>

  # Only count rows whose CSV "dataset" column matches
  python3 scripts/update_benchmark_table.py --dataset "Juliet CWE-121" \
      --run Benchmarks/stack_benchmark/results/<run> --csv-dataset Juliet_CWE121_isolated

Only runs passed explicitly with --run are published, so scratch reruns never
reach the README.
"""

import argparse
import importlib.util
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_JSON = ROOT / "benchmarks" / "results.json"
README = ROOT / "README.md"
START_MARKER = "<!-- benchmark-table:start -->"
END_MARKER = "<!-- benchmark-table:end -->"

_spec = importlib.util.spec_from_file_location("calc_metrics", ROOT / "scripts" / "calc_metrics.py")
calc_metrics = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(calc_metrics)


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------

def entry_from_run(run: Path, csv_dataset: str | None = None) -> dict:
    csv_files = calc_metrics.find_csv_files(run)
    if not csv_files:
        raise SystemExit(f"No results.csv found under {run}")
    rows = [r for f in csv_files for r in calc_metrics.load_csv(f)]
    if csv_dataset:
        rows = [r for r in rows if r.get("dataset") == csv_dataset]
    if not rows:
        raise SystemExit(f"No rows for dataset {csv_dataset!r} under {run}")
    m = calc_metrics.compute_metrics(rows)
    c = m["confusion"]
    if not (c["positives"] + c["negatives"]):
        raise SystemExit(f"No graded cases under {run} ({m['errors']} errors); not publishing")
    return {
        "cases": m["total_rows"],
        "errors": m["errors"],
        "TP": c["TP"],
        "FP": c["FP"],
        "TN": c["TN"],
        "FN": c["FN"],
        "updated": date.today().isoformat(),
        "source": f"run {run.name} at {git_short_head()}",
    }


def git_short_head() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown commit"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def ratio(num: int, den: int) -> str:
    return f"{100 * num / den:.1f}%" if den else "n/a"


def render_table(results: dict) -> str:
    lines = [
        "| Dataset | Cases | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | Updated |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for name, e in results.items():
        tp, fp, tn, fn = e["TP"], e["FP"], e["TN"], e["FN"]
        graded = tp + fp + tn + fn
        cases = f"{e['cases']:,}"
        if e.get("errors"):
            cases += f" ({e['errors']:,} errors)"
        counts = [f"{n:,} ({ratio(n, graded)})" for n in (tp, fp, tn, fn)]
        lines.append("| " + " | ".join([
            name, cases, *counts,
            ratio(tp, tp + fp), ratio(tp, tp + fn), ratio(2 * tp, 2 * tp + fp + fn),
            ratio(tp + tn, graded), e["updated"],
        ]) + " |")
    sources = "; ".join(f"{name}: {e['source']}" for name, e in results.items())
    lines += ["", f"Percentages next to counts are shares of graded cases. Source: {sources}."]
    return "\n".join(lines)


def replace_section(text: str, table: str) -> str:
    start = text.find(START_MARKER)
    end = text.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise SystemExit(f"README is missing {START_MARKER} / {END_MARKER}")
    return text[:start + len(START_MARKER)] + "\n" + table + "\n" + text[end:]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", help="Table row to replace, e.g. 'Juliet CWE-121'")
    ap.add_argument("--run", type=Path, help="Run directory or results.csv to publish")
    ap.add_argument("--csv-dataset", help="Only count rows with this CSV dataset value")
    args = ap.parse_args()

    if bool(args.dataset) != bool(args.run):
        ap.error("--dataset and --run must be given together")

    results = json.loads(RESULTS_JSON.read_text()) if RESULTS_JSON.exists() else {}
    if args.run:
        results[args.dataset] = entry_from_run(args.run, args.csv_dataset)
        RESULTS_JSON.write_text(json.dumps(results, indent=2) + "\n")
        print(f"Updated {args.dataset} in {RESULTS_JSON.relative_to(ROOT)}")

    README.write_text(replace_section(README.read_text(), render_table(results)))
    print(f"Rendered {len(results)} dataset(s) into {README.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
