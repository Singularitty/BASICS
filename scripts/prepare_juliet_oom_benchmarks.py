#!/usr/bin/env python3
"""Prepare focused Juliet benchmark manifests from errored BASICS results."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "Benchmarks" / "stack_benchmark"
RESULTS = STACK / "results"
DEFAULT_MANIFEST = STACK / "juliet_cwe121_isolated_cases.json"
DEFAULT_OUT_DIR = STACK / "specialized"


def rel(path: Path) -> str:
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


def latest_juliet_results() -> Path:
    candidates = sorted(
        RESULTS.glob("basics_juliet_*/results.csv"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise SystemExit(f"No basics_juliet_*/results.csv files found under {RESULTS}")
    return candidates[0]


def family(case_id: str) -> str:
    name = case_id.removeprefix("juliet_CWE121_Stack_Based_Buffer_Overflow__")
    return re.sub(r"_\d+_(bad|good)_only$", "", name)


def flow_variant(case_id: str) -> str:
    match = re.search(r"_(\d+)_(bad|good)_only$", case_id)
    return match.group(1) if match else "unknown"


def direct_analysis_entry(case_id: str) -> str | None:
    if not case_id.startswith("juliet_"):
        return None
    name = case_id.removeprefix("juliet_")
    if name.endswith("_bad_only"):
        return name[: -len("_bad_only")] + "_bad"
    if name.endswith("_good_only"):
        return name[: -len("_good_only")] + "_good"
    return None


def with_direct_entries(cases: list[dict]) -> list[dict]:
    direct_cases = []
    for case in cases:
        new_case = dict(case)
        entry = direct_analysis_entry(new_case["case_id"])
        if entry:
            new_case["analysis_entry"] = entry
            new_case["patched_analysis_entry"] = entry
        direct_cases.append(new_case)
    return direct_cases


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def write_manifest(path: Path, cases: list[dict], description: str, source_results: Path) -> None:
    payload = {
        "description": description,
        "generated_by": "scripts/prepare_juliet_oom_benchmarks.py",
        "source_results": rel(source_results),
        "case_count": len(cases),
        "cases": cases,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create specialized Juliet manifests from a BASICS results.csv with run_error/OOM cases."
    )
    parser.add_argument(
        "--results-csv",
        type=Path,
        default=None,
        help="Source results.csv. Defaults to newest Benchmarks/stack_benchmark/results/basics_juliet_*/results.csv.",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--status",
        action="append",
        default=["run_error"],
        help="Result status to isolate. Repeatable. Default: run_error.",
    )
    parser.add_argument(
        "--error",
        default="exit=-9",
        help="Optional exact error text to isolate. Use empty string to accept any error.",
    )
    args = parser.parse_args()

    results_csv = args.results_csv or latest_juliet_results()
    results_csv = results_csv.resolve()
    manifest = args.manifest.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    all_cases = {case["case_id"]: case for case in load_cases(manifest)}
    rows = list(csv.DictReader(results_csv.open(newline="", encoding="utf-8")))
    statuses = set(args.status)
    selected_rows = [
        row
        for row in rows
        if row.get("status") in statuses and (not args.error or row.get("error") == args.error)
    ]
    missing = [row["case_id"] for row in selected_rows if row["case_id"] not in all_cases]
    if missing:
        raise SystemExit(f"{len(missing)} selected result rows were absent from {manifest}: {missing[:5]}")

    selected_cases = [all_cases[row["case_id"]] for row in selected_rows]
    selected_ids = {case["case_id"] for case in selected_cases}
    source_label = results_csv.parent.name

    all_manifest = out_dir / f"{source_label}_oom_error_cases.json"
    write_manifest(
        all_manifest,
        selected_cases,
        f"Juliet cases from {source_label} with status in {sorted(statuses)} and error {args.error or '<any>'}.",
        results_csv,
    )
    direct_all_manifest = out_dir / f"{source_label}_oom_direct_entry_cases.json"
    write_manifest(
        direct_all_manifest,
        with_direct_entries(selected_cases),
        (
            f"Direct-entry variant of Juliet cases from {source_label} with status in "
            f"{sorted(statuses)} and error {args.error or '<any>'}."
        ),
        results_csv,
    )

    rows_by_family: dict[str, list[dict]] = defaultdict(list)
    cases_by_family: dict[str, list[dict]] = defaultdict(list)
    for row in selected_rows:
        rows_by_family[family(row["case_id"])].append(row)
        cases_by_family[family(row["case_id"])].append(all_cases[row["case_id"]])

    family_manifest_paths = []
    for fam in sorted(cases_by_family):
        path = out_dir / f"{source_label}_oom_{slug(fam)}.json"
        family_manifest_paths.append(path)
        write_manifest(
            path,
            cases_by_family[fam],
            f"Juliet OOM/error cases in family {fam} from {source_label}.",
            results_csv,
        )
        direct_path = out_dir / f"{source_label}_oom_direct_{slug(fam)}.json"
        write_manifest(
            direct_path,
            with_direct_entries(cases_by_family[fam]),
            f"Direct-entry Juliet OOM/error cases in family {fam} from {source_label}.",
            results_csv,
        )

    repro_cases = []
    for fam in sorted(rows_by_family):
        row = max(rows_by_family[fam], key=lambda item: float(item.get("elapsed_sec") or 0.0))
        repro_cases.append(all_cases[row["case_id"]])
    repro_manifest = out_dir / f"{source_label}_oom_repro_one_per_family.json"
    write_manifest(
        repro_manifest,
        repro_cases,
        f"One longest-running OOM/error representative per Juliet family from {source_label}.",
        results_csv,
    )
    direct_repro_manifest = out_dir / f"{source_label}_oom_direct_repro_one_per_family.json"
    write_manifest(
        direct_repro_manifest,
        with_direct_entries(repro_cases),
        f"Direct-entry one-per-family OOM/error representatives from {source_label}.",
        results_csv,
    )

    summary_path = out_dir / f"{source_label}_oom_error_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "case_id",
            "family",
            "flow_variant",
            "label_rule",
            "true_present_vuln",
            "elapsed_sec",
            "error",
            "stdout_log_path",
            "source_path",
            "binary_path",
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in selected_rows:
            case = all_cases[row["case_id"]]
            writer.writerow(
                {
                    "case_id": row["case_id"],
                    "family": family(row["case_id"]),
                    "flow_variant": flow_variant(row["case_id"]),
                    "label_rule": row.get("label_rule", ""),
                    "true_present_vuln": row.get("true_present_vuln", ""),
                    "elapsed_sec": row.get("elapsed_sec", ""),
                    "error": row.get("error", ""),
                    "stdout_log_path": row.get("stdout_log_path", ""),
                    "source_path": case.get("source_path", ""),
                    "binary_path": case.get("binary_path", ""),
                }
            )

    print(f"Source results: {results_csv}")
    print(f"Selected cases: {len(selected_cases)}")
    print(f"Wrote all-case manifest: {all_manifest}")
    print(f"Wrote direct-entry all-case manifest: {direct_all_manifest}")
    print(f"Wrote repro manifest: {repro_manifest}")
    print(f"Wrote direct-entry repro manifest: {direct_repro_manifest}")
    print(f"Wrote summary CSV: {summary_path}")
    print("By family:")
    family_counts = Counter(family(case_id) for case_id in selected_ids)
    for fam, count in sorted(family_counts.items()):
        print(f"  {count:4d}  {fam}")
    print("Family manifests:")
    for path in family_manifest_paths:
        print(f"  {path}")


if __name__ == "__main__":
    main()
