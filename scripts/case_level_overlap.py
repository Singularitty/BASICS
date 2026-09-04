#!/usr/bin/env python3
"""Compare case-level positive reports from BASICS and CWE_Checker."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def load_rows(path: Path) -> list[dict[str, Any]]:
    if path.is_dir():
        path = path / "results.csv"
    if path.suffix == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = value.get("results", value.get("records", []))
    if not isinstance(value, list):
        raise ValueError(f"Unsupported result structure: {path}")
    return [row for row in value if isinstance(row, dict)]


def completed(row: dict[str, Any]) -> bool:
    status = str(row.get("status") or row.get("execution_status") or "ok").lower()
    return status in {"ok", "completed"}


def index(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    result = {}
    for row in rows:
        case_id = str(row.get("case_id") or "")
        if not case_id:
            raise ValueError(f"{label} contains a row without case_id")
        if case_id in result:
            raise ValueError(f"{label} contains duplicate case_id {case_id!r}")
        result[case_id] = row
    return result


def category(basics_positive: bool, cwe_positive: bool) -> str:
    if basics_positive and cwe_positive:
        return "Both"
    if basics_positive:
        return "BASICS only"
    if cwe_positive:
        return "CWE_Checker only"
    return "Neither"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basics", type=Path, required=True)
    parser.add_argument("--cwe-checker", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    basics = index(load_rows(args.basics), "BASICS")
    cwe = index(load_rows(args.cwe_checker), "CWE_Checker")
    shared = sorted(set(basics) & set(cwe))
    if not shared:
        raise ValueError("The result files have no shared case IDs")

    details = []
    excluded = Counter()
    counts: dict[str, Counter[str]] = {}
    for case_id in shared:
        b, c = basics[case_id], cwe[case_id]
        dataset = str(b.get("dataset") or c.get("dataset") or "unknown")
        if not completed(b) or not completed(c):
            excluded[dataset] += 1
            continue
        b_positive = parse_bool(b.get("reported_vuln"))
        c_positive = parse_bool(c.get("reported_vuln"))
        truth = parse_bool(b.get("true_present_vuln"))
        c_truth = parse_bool(c.get("true_present_vuln"))
        if b_positive is None or c_positive is None or truth is None:
            raise ValueError(f"Unparseable Boolean field for {case_id}")
        if c_truth is not None and c_truth != truth:
            raise ValueError(f"Ground-truth mismatch for {case_id}")
        group = "Vulnerable" if truth else "Non-vulnerable"
        overlap = category(b_positive, c_positive)
        counts.setdefault(dataset, Counter())[overlap] += 1
        counts[dataset][f"{group}: {overlap}"] += 1
        details.append({
            "dataset": dataset,
            "case_id": case_id,
            "ground_truth": truth,
            "basics_positive": b_positive,
            "cwe_checker_positive": c_positive,
            "overlap": overlap,
        })

    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "case_overlap_details.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(details[0]))
        writer.writeheader()
        writer.writerows(details)

    headers = ["Dataset", "Population", "Both", "BASICS only", "CWE_Checker only", "Neither", "BASICS subset?"]
    table_rows = []
    for dataset, counter in sorted(counts.items()):
        for population, prefix in (("All", ""), ("Vulnerable", "Vulnerable: "), ("Non-vulnerable", "Non-vulnerable: ")):
            values = {name: counter[prefix + name] for name in ("Both", "BASICS only", "CWE_Checker only", "Neither")}
            table_rows.append([dataset, population, *(values[name] for name in ("Both", "BASICS only", "CWE_Checker only", "Neither")), "Yes" if values["BASICS only"] == 0 else "No"])

    md = [
        "| " + " | ".join(headers) + " |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    md.extend("| " + " | ".join(map(str, row)) + " |" for row in table_rows)
    md += ["", "Only cases completed by both tools are included."]
    (args.out_dir / "case_overlap.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    summary = {
        "shared_case_ids": len(shared),
        "included_completed_by_both": len(details),
        "excluded_not_completed_by_both": dict(excluded),
        "rows": [dict(zip(headers, row)) for row in table_rows],
    }
    (args.out_dir / "case_overlap.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print((args.out_dir / "case_overlap.md").read_text(), end="")


if __name__ == "__main__":
    main()
