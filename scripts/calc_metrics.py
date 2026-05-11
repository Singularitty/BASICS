#!/usr/bin/env python3
"""
Calculate benchmark metrics from results.csv files produced by run_basics_benchmark.py.

Usage:
  # Single CSV file
  python scripts/calc_metrics.py Benchmarks/stack_benchmark/results/20260508T161647Z/results.csv

  # Single run directory
  python scripts/calc_metrics.py Benchmarks/stack_benchmark/results/20260508T161647Z/

  # All runs under a results/ directory
  python scripts/calc_metrics.py Benchmarks/stack_benchmark/results/

  # Flags
  --by-dataset   Break down metrics per dataset
  --by-run       Print metrics for each run separately (when given a results/ dir)
  --min-rows N   Skip runs with fewer than N rows (default: 1)
  --json         Output as JSON instead of plain text
"""

import argparse
import csv
import json
import math
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def find_csv_files(path: Path) -> list[Path]:
    path = path.resolve()
    if path.is_file() and path.suffix == ".csv":
        return [path]
    if path.is_dir():
        direct = path / "results.csv"
        if direct.exists():
            return [direct]
        found = sorted(path.glob("*/results.csv"))
        if found:
            return found
    return []


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def parse_bool(value: str) -> bool | None:
    if value.strip().lower() in ("true", "1", "yes"):
        return True
    if value.strip().lower() in ("false", "0", "no"):
        return False
    return None


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------

def compute_metrics(rows: list[dict], label: str = "") -> dict:
    ok_rows = [r for r in rows if r.get("status", "ok") == "ok"]
    error_rows = [r for r in rows if r.get("status", "ok") != "ok"]

    tp = tn = fp = fn = 0
    skipped = 0

    for r in ok_rows:
        gt = parse_bool(r.get("true_present_vuln", ""))
        pred = parse_bool(r.get("reported_vuln", ""))
        if gt is None or pred is None:
            skipped += 1
            continue
        if gt and pred:
            tp += 1
        elif not gt and not pred:
            tn += 1
        elif not gt and pred:
            fp += 1
        else:
            fn += 1

    total = tp + tn + fp + fn
    p_total = tp + fn
    n_total = tn + fp

    def safe_div(a, b):
        return a / b if b else None

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)       # sensitivity / TPR
    specificity = safe_div(tn, tn + fp)  # TNR
    accuracy = safe_div(tp + tn, total)
    f1 = safe_div(2 * tp, 2 * tp + fp + fn)
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)

    mcc_num = tp * tn - fp * fn
    mcc_den_sq = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = mcc_num / math.sqrt(mcc_den_sq) if mcc_den_sq > 0 else None

    # Patching metrics (only on rows that should be patched: TP cases)
    patch_cols_present = "patch_validation_status" in (ok_rows[0] if ok_rows else {})
    patched_count = sum(1 for r in ok_rows if parse_bool(r.get("patched", "false")))
    patch_validation_counts = {}
    if patch_cols_present:
        for r in ok_rows:
            status = r.get("patch_validation_status", "").strip() or "not_run"
            patch_validation_counts[status] = patch_validation_counts.get(status, 0) + 1

    # Performance
    elapsed = [float(r["elapsed_sec"]) for r in ok_rows if r.get("elapsed_sec")]
    analysis = [float(r["analysis_exec_time_sec"]) for r in ok_rows if r.get("analysis_exec_time_sec")]

    def stats(vals):
        if not vals:
            return {}
        vals_s = sorted(vals)
        n = len(vals_s)
        return {
            "mean": sum(vals_s) / n,
            "median": vals_s[n // 2] if n % 2 else (vals_s[n // 2 - 1] + vals_s[n // 2]) / 2,
            "min": vals_s[0],
            "max": vals_s[-1],
        }

    result = {
        "label": label,
        "total_rows": len(rows),
        "ok": len(ok_rows),
        "errors": len(error_rows),
        "skipped_parse": skipped,
        "confusion": {"TP": tp, "TN": tn, "FP": fp, "FN": fn,
                      "positives": p_total, "negatives": n_total},
        "detection": {
            "precision": precision,
            "recall_tpr": recall,
            "specificity_tnr": specificity,
            "fpr": fpr,
            "fnr": fnr,
            "accuracy": accuracy,
            "f1": f1,
            "mcc": mcc,
        },
        "patching": {
            "patched": patched_count,
            "patch_validation": patch_validation_counts,
        },
        "performance": {
            "elapsed_sec": stats(elapsed),
            "analysis_exec_time_sec": stats(analysis),
        },
    }
    return result


def split_by_dataset(rows: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for r in rows:
        ds = r.get("dataset", "unknown")
        groups.setdefault(ds, []).append(r)
    return groups


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def pct(v) -> str:
    return f"{v * 100:.1f}%" if v is not None else "N/A"


def fmt_float(v, decimals=4) -> str:
    return f"{v:.{decimals}f}" if v is not None else "N/A"


def fmt_time(d: dict) -> str:
    if not d:
        return "N/A"
    return f"mean={d['mean']:.2f}s  median={d['median']:.2f}s  min={d['min']:.2f}s  max={d['max']:.2f}s"


def print_metrics(m: dict, indent: str = "") -> None:
    i = indent
    label = f" [{m['label']}]" if m.get("label") else ""
    print(f"{i}{'─' * 60}")
    if m.get("label"):
        print(f"{i}  Run / group: {m['label']}")
    print(f"{i}  Rows: {m['total_rows']}  (ok={m['ok']}, errors={m['errors']}, parse_skipped={m['skipped_parse']})")

    c = m["confusion"]
    print(f"{i}  Confusion matrix: TP={c['TP']}  TN={c['TN']}  FP={c['FP']}  FN={c['FN']}"
          f"  (P={c['positives']}, N={c['negatives']})")

    d = m["detection"]
    print(f"{i}  Detection metrics:")
    print(f"{i}    Accuracy   : {pct(d['accuracy'])}")
    print(f"{i}    Precision  : {pct(d['precision'])}")
    print(f"{i}    Recall/TPR : {pct(d['recall_tpr'])}")
    print(f"{i}    Specificity: {pct(d['specificity_tnr'])}")
    print(f"{i}    FPR        : {pct(d['fpr'])}")
    print(f"{i}    FNR        : {pct(d['fnr'])}")
    print(f"{i}    F1         : {fmt_float(d['f1'])}")
    print(f"{i}    MCC        : {fmt_float(d['mcc'])}")

    p = m["patching"]
    print(f"{i}  Patching: patched={p['patched']}")
    if p["patch_validation"]:
        pv = "  ".join(f"{k}={v}" for k, v in sorted(p["patch_validation"].items()))
        print(f"{i}    Validation: {pv}")

    perf = m["performance"]
    print(f"{i}  Elapsed    : {fmt_time(perf['elapsed_sec'])}")
    print(f"{i}  Analysis   : {fmt_time(perf['analysis_exec_time_sec'])}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Compute benchmark metrics from results CSV files.")
    parser.add_argument("path", help="CSV file, run directory, or results/ parent directory")
    parser.add_argument("--by-dataset", action="store_true", help="Break down metrics per dataset")
    parser.add_argument("--by-run", action="store_true",
                        help="Print metrics for each run when given a results/ directory")
    parser.add_argument("--min-rows", type=int, default=1,
                        help="Skip runs with fewer than this many rows")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    csv_files = find_csv_files(Path(args.path))
    if not csv_files:
        print(f"No results.csv files found under {args.path}", file=sys.stderr)
        sys.exit(1)

    all_rows: list[dict] = []
    run_results: list[dict] = []

    for csv_path in csv_files:
        rows = load_csv(csv_path)
        if len(rows) < args.min_rows:
            continue
        all_rows.extend(rows)
        run_label = csv_path.parent.name
        run_results.append((run_label, rows))

    if not all_rows:
        print("No data rows found (check --min-rows).", file=sys.stderr)
        sys.exit(1)

    output: list[dict] = []

    if args.by_run and len(run_results) > 1:
        for label, rows in run_results:
            m = compute_metrics(rows, label=label)
            output.append(m)
            if args.by_dataset:
                for ds, ds_rows in split_by_dataset(rows).items():
                    output.append(compute_metrics(ds_rows, label=f"{label}/{ds}"))
    else:
        # Aggregate across all runs
        if args.by_dataset:
            for ds, ds_rows in split_by_dataset(all_rows).items():
                output.append(compute_metrics(ds_rows, label=ds))

        agg_label = "aggregate" if len(run_results) > 1 else run_results[0][0]
        output.append(compute_metrics(all_rows, label=agg_label))

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        total_runs = len(run_results)
        print(f"\nBASICS Benchmark Metrics  ({total_runs} run(s) from: {args.path})")
        for m in output:
            print_metrics(m)
        print(f"{'─' * 60}\n")


if __name__ == "__main__":
    main()
