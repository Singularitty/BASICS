#!/usr/bin/env python3
"""Aggregate BASICS per-case stage timings into paper-ready tables.

Inputs may be JSONL timing files or result directories containing ``results.json``
and per-case logs. Result-directory logs are used to recover
``@@BASICS_TIMING`` records from older benchmark runs.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any, Iterable

STAGES = (
    ("disassembly_cfg_seconds", "Binary disassembly / CFG"),
    ("memstace_seconds", "MemStaCe construction"),
    ("ltl_model_checking_seconds", "LTL model checking"),
    ("patch_generation_seconds", "Patch generation"),
    ("patch_validation_seconds", "Patch validation"),
    ("end_to_end_seconds", "End-to-end"),
)


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _timing_from_log(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    timing = None
    for line in path.read_text(errors="replace").splitlines():
        marker = "@@BASICS_TIMING "
        if line.startswith(marker):
            try:
                timing = json.loads(line[len(marker) :])
            except json.JSONDecodeError:
                continue
    return timing if isinstance(timing, dict) else None


def _rows_from_json(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".jsonl":
        rows = []
        for line in path.read_text(errors="replace").splitlines():
            if line.strip():
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    rows.append(value)
        return rows
    value = json.loads(path.read_text(errors="replace"))
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for key in ("results", "records", "cases"):
            if isinstance(value.get(key), list):
                return [row for row in value[key] if isinstance(row, dict)]
        return [value]
    return []


def _load_input(path: Path) -> list[dict[str, Any]]:
    if path.is_file():
        return _rows_from_json(path)
    if not path.is_dir():
        raise FileNotFoundError(path)
    result_files = sorted(path.glob("results.json"))
    if not result_files:
        result_files = sorted(path.glob("*.jsonl"))
    rows: list[dict[str, Any]] = []
    for result_file in result_files:
        for row in _rows_from_json(result_file):
            case_id = row.get("case_id")
            log_path = path / "logs" / f"{case_id}.log" if case_id else None
            timing = _timing_from_log(log_path) if log_path else None
            if timing:
                row = {**row, **timing}
                # Preserve an explicit timeout/error from the result manifest.
                # Older runs can emit a timing marker before the wrapper times out.
                if not row.get("status") and not row.get("execution_status"):
                    row["execution_status"] = "completed"
            rows.append(row)
    return rows


def _dataset(row: dict[str, Any]) -> str:
    value = str(row.get("dataset") or row.get("run_id") or "unknown")
    if value.lower().startswith("sard"):
        return "SARD"
    if "juliet" in value.lower():
        return "Juliet"
    return value


def _completed(row: dict[str, Any]) -> bool:
    return row.get("execution_status") == "completed" or row.get("status") in {"ok", "completed"}


def _timed(row: dict[str, Any]) -> int:
    return sum(_number(row.get(key)) is not None for key, _ in STAGES)


def _deduplicate(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one record per case, preferring timed and completed records."""
    selected: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        case_id = str(row.get("case_id") or f"__row_{index}")
        current = selected.get(case_id)
        rank = (_timed(row), _completed(row), str(row.get("timestamp") or ""), index)
        old_rank = (
            (_timed(current), _completed(current), str(current.get("timestamp") or ""), -1)
            if current else None
        )
        if current is None or rank > old_rank:
            selected[case_id] = row
    return list(selected.values())


def _stats(values: list[float]) -> dict[str, Any]:
    return {
        "sum_seconds": sum(values) if values else None,
        "mean_seconds": statistics.mean(values) if values else None,
        "stddev_seconds": statistics.stdev(values) if len(values) > 1 else None,
        "median_seconds": statistics.median(values) if values else None,
        "min_seconds": min(values) if values else None,
        "max_seconds": max(values) if values else None,
        "n": len(values),
    }


def _fmt(stats: dict[str, Any]) -> str:
    if not stats["n"]:
        return "N/A"
    spread = f" ± {stats['stddev_seconds']:.3f}" if stats["stddev_seconds"] is not None else ""
    return f"{stats['mean_seconds']:.3f}{spread} (n={stats['n']})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    raw_rows: list[dict[str, Any]] = []
    for path in args.inputs:
        raw_rows.extend(_load_input(path))
    rows = _deduplicate(raw_rows)
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(_dataset(row), []).append(row)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"inputs": [str(p) for p in args.inputs], "deduplicated_records": len(rows), "datasets": {}}
    csv_rows: list[dict[str, Any]] = []
    for dataset, dataset_rows in sorted(groups.items()):
        completed = [row for row in dataset_rows if _completed(row)]
        dataset_summary: dict[str, Any] = {
            "records": len(dataset_rows), "completed_records": len(completed), "status_counts": {}, "stages": {}
        }
        for row in dataset_rows:
            status = row.get("execution_status") or row.get("status") or "unknown"
            dataset_summary["status_counts"][status] = dataset_summary["status_counts"].get(status, 0) + 1
        for key, label in STAGES:
            values = [_number(row.get(key)) for row in completed]
            if key in {"patch_generation_seconds", "patch_validation_seconds"} and any(
                row.get("patch_attempted") is True for row in completed
            ):
                # Report average time spent per benchmark case. When patching
                # was enabled but an optional patch stage was not invoked, that
                # case spent zero seconds in the stage. If patching was disabled
                # for the run entirely, preserve N/A instead.
                values = [value if value is not None else 0.0 for value in values]
            else:
                values = [value for value in values if value is not None]
            stats = _stats(values)
            dataset_summary["stages"][key] = stats
            csv_rows.append({"dataset": dataset, "stage": label, **stats})
        summary["datasets"][dataset] = dataset_summary

    fields = ["dataset", "stage", "sum_seconds", "mean_seconds", "stddev_seconds", "median_seconds", "min_seconds", "max_seconds", "n"]
    with (args.out_dir / "stage_timings.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(csv_rows)

    md = [
        "Table X: Mean per-case BASICS pipeline stage time in seconds (mean ± standard deviation; n).",
        "",
        "| Dataset | Completed | Binary disassembly / CFG | MemStaCe construction | LTL model checking | Patch generation | Patch validation | End-to-end |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for dataset, dataset_summary in sorted(summary["datasets"].items()):
        stages = dataset_summary["stages"]
        md.append(f"| {dataset} | {dataset_summary['completed_records']} | " + " | ".join(_fmt(stages[key]) for key, _ in STAGES) + " |")
    md += ["", "Statistics are computed over completed cases. When patching was enabled but an optional patch stage was not invoked, that case contributes zero seconds to the per-case stage average. Juliet was run without patching; its patch-generation and patch-validation entries are N/A."]
    (args.out_dir / "stage_timings.md").write_text("\n".join(md) + "\n")

    tex = [
        r"\begin{table}[t]", r"\centering",
        r"\caption{Mean per-case BASICS pipeline stage time in seconds (mean $\pm$ standard deviation; $n$).}",
        r"\label{tab:pipeline-timings}", r"\begin{tabular}{lrrrrrrr}", r"\toprule",
        r"Dataset & Completed & Disassembly/CFG & MemStaCe & LTL checking & Patch generation & Patch validation & End-to-end \\", r"\midrule",
    ]
    for dataset, dataset_summary in sorted(summary["datasets"].items()):
        values = [dataset, str(dataset_summary["completed_records"])] + [_fmt(dataset_summary["stages"][key]).replace("±", r"$\pm$") for key, _ in STAGES]
        tex.append(" & ".join(values) + r" \\")
    tex += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    (args.out_dir / "stage_timings.tex").write_text("\n".join(tex) + "\n")
    (args.out_dir / "stage_timings_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print((args.out_dir / "stage_timings.md").read_text(), end="")


if __name__ == "__main__":
    main()
