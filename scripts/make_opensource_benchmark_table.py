#!/usr/bin/env python3
"""Generate paper-style tables for the open-source BASICS benchmark pilots."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFESTS = [
    ROOT / "Benchmarks" / "opensource" / "opensource_cases.json",
    ROOT / "Benchmarks" / "opensource" / "opensource_function_cases.json",
    ROOT / "Benchmarks" / "opensource" / "seeded_vulns" / "seeded_vuln_cases.json",
]
RESULTS_DIR = ROOT / "Benchmarks" / "stack_benchmark" / "results"
SCAN_RESULTS_DIR = ROOT / "Benchmarks" / "opensource" / "scan_results"
DEFAULT_OUT = ROOT / "reports" / "opensource_benchmark_table.md"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_manifest_cases(paths: list[Path]) -> list[dict]:
    cases = []
    for path in paths:
        if not path.exists():
            continue
        obj = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(obj, list):
            next_cases = obj
        elif "cases" in obj:
            next_cases = obj["cases"]
        elif "datasets" in obj:
            next_cases = []
            for data in obj["datasets"].values():
                next_cases.extend(data.get("cases", []))
        else:
            raise ValueError(f"Unsupported manifest format: {path}")
        for case in next_cases:
            case = dict(case)
            case["_manifest"] = path
            cases.append(case)
    return cases


def mode_for(case: dict) -> str:
    rule = case.get("label_rule", "")
    if rule == "real_project_unlabeled":
        return "Whole binary"
    if rule == "real_project_function_entry_unlabeled":
        return "Function entry"
    if rule.startswith("seeded_"):
        return "Seeded vuln"
    return rule or "Unknown"


def project_for(case: dict) -> str:
    dataset = case.get("dataset", "")
    if dataset.startswith("opensource/"):
        return dataset.split("/", 1)[1]
    return case.get("project") or dataset or "unknown"


def load_latest_result_rows(results_dir: Path) -> dict[str, dict]:
    latest: dict[str, tuple[str, dict]] = {}
    for csv_path in sorted(results_dir.glob("*/results.csv")):
        stamp = csv_path.parent.name
        with csv_path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                dataset = row.get("dataset", "")
                if not dataset.startswith("opensource/"):
                    continue
                case_id = row["case_id"]
                previous = latest.get(case_id)
                if previous is None or stamp > previous[0]:
                    next_row = dict(row)
                    next_row["_result_stamp"] = stamp
                    latest[case_id] = (stamp, next_row)
    return {case_id: row for case_id, (_, row) in latest.items()}


def boolish(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def pct(num: int, den: int) -> str:
    if den == 0:
        return "N/A"
    return f"{(100.0 * num / den):.1f}%"


def summarize(cases: list[dict], results: dict[str, dict]) -> list[dict]:
    groups: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "available": 0,
            "run": 0,
            "ok": 0,
            "timeouts": 0,
            "memory": 0,
            "errors": 0,
            "reported": 0,
            "tp": 0,
            "tn": 0,
            "fp": 0,
            "fn": 0,
            "labeled": 0,
            "patched": 0,
            "validated": 0,
            "validation_blocked": 0,
            "elapsed": [],
        }
    )
    for case in cases:
        key = (project_for(case), mode_for(case))
        group = groups[key]
        group["available"] += 1
        row = results.get(case["case_id"])
        if row is None:
            continue
        group["run"] += 1
        status = row.get("status", "")
        if status == "ok":
            group["ok"] += 1
        elif status == "timeout":
            group["timeouts"] += 1
        elif status == "memory_limit":
            group["memory"] += 1
        else:
            group["errors"] += 1
        reported = boolish(row.get("reported_vuln"))
        if reported:
            group["reported"] += 1
        truth = str(row.get("true_present_vuln", "")).strip().lower()
        if truth in {"true", "false"} and status == "ok":
            group["labeled"] += 1
            if truth == "true" and reported:
                group["tp"] += 1
            elif truth == "true" and not reported:
                group["fn"] += 1
            elif truth == "false" and reported:
                group["fp"] += 1
            elif truth == "false" and not reported:
                group["tn"] += 1
        if boolish(row.get("patched")):
            group["patched"] += 1
        if boolish(row.get("patch_validated")):
            group["validated"] += 1
        if row.get("patch_validation_status") == "blocked_ptrace":
            group["validation_blocked"] += 1
        try:
            group["elapsed"].append(float(row.get("elapsed_sec") or 0.0))
        except ValueError:
            pass

    rows = []
    for (project, mode), group in sorted(groups.items()):
        elapsed = group["elapsed"]
        mean_elapsed = sum(elapsed) / len(elapsed) if elapsed else 0.0
        rows.append(
            {
                "Project": project,
                "Mode": mode,
                "Available": group["available"],
                "Run": group["run"],
                "OK": group["ok"],
                "Timeout": group["timeouts"],
                "Memory": group["memory"],
                "Error": group["errors"],
                "Reported": group["reported"],
                "TP": group["tp"] if group["labeled"] else "N/A",
                "FP": group["fp"] if group["labeled"] else "N/A",
                "FN": group["fn"] if group["labeled"] else "N/A",
                "TN": group["tn"] if group["labeled"] else "N/A",
                "Recall": pct(group["tp"], group["tp"] + group["fn"]) if group["labeled"] else "N/A",
                "Patched": group["patched"],
                "Validated": group["validated"],
                "Blocked": group["validation_blocked"],
                "Mean s": f"{mean_elapsed:.2f}" if elapsed else "N/A",
            }
        )
    return rows


def load_scan_rows(results_dir: Path) -> list[dict]:
    latest: dict[str, tuple[str, dict]] = {}
    for csv_path in sorted(results_dir.glob("*/results.csv")):
        stamp = csv_path.parent.name
        with csv_path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                case_id = row["case_id"]
                previous = latest.get(case_id)
                if previous is None or stamp > previous[0]:
                    latest[case_id] = (stamp, dict(row))
    return [row for _, row in latest.values()]


def summarize_scan_rows(cases: list[dict], rows: list[dict]) -> list[dict]:
    available_by_project: dict[str, int] = defaultdict(int)
    for case in cases:
        if mode_for(case) == "Whole binary":
            available_by_project[project_for(case)] += 1

    groups: dict[str, dict] = defaultdict(
        lambda: {
            "run": 0,
            "ok": 0,
            "timeouts": 0,
            "memory": 0,
            "errors": 0,
            "reported": 0,
            "functions": 0,
            "vulnerable_functions": 0,
            "elapsed": [],
        }
    )
    for row in rows:
        project = row.get("project") or row.get("dataset", "").split("/", 1)[-1]
        group = groups[project]
        group["run"] += 1
        status = row.get("status", "")
        if status == "ok":
            group["ok"] += 1
        elif status == "timeout":
            group["timeouts"] += 1
        elif status == "memory_limit":
            group["memory"] += 1
        else:
            group["errors"] += 1
        if boolish(row.get("reported_vuln")):
            group["reported"] += 1
        try:
            group["functions"] += int(row.get("functions_scanned") or 0)
        except ValueError:
            pass
        try:
            group["vulnerable_functions"] += int(row.get("vulnerable_functions") or 0)
        except ValueError:
            pass
        try:
            group["elapsed"].append(float(row.get("elapsed_sec") or 0.0))
        except ValueError:
            pass

    out = []
    for project, group in sorted(groups.items()):
        elapsed = group["elapsed"]
        mean_elapsed = sum(elapsed) / len(elapsed) if elapsed else 0.0
        out.append(
            {
                "Project": project,
                "Mode": "All functions",
                "Available": available_by_project.get(project, "N/A"),
                "Run": group["run"],
                "OK": group["ok"],
                "Timeout": group["timeouts"],
                "Memory": group["memory"],
                "Error": group["errors"],
                "Reported": group["reported"],
                "TP": "N/A",
                "FP": "N/A",
                "FN": "N/A",
                "TN": "N/A",
                "Recall": "N/A",
                "Patched": 0,
                "Validated": 0,
                "Blocked": 0,
                "Mean s": f"{mean_elapsed:.2f}" if elapsed else "N/A",
            }
        )
    return out


def markdown_table(rows: list[dict]) -> str:
    headers = [
        "Project",
        "Mode",
        "Available",
        "Run",
        "OK",
        "Timeout",
        "Memory",
        "Error",
        "Reported",
        "TP",
        "FP",
        "FN",
        "TN",
        "Recall",
        "Patched",
        "Validated",
        "Blocked",
        "Mean s",
    ]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row[h]) for h in headers) + " |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate open-source benchmark summary tables.")
    parser.add_argument("--manifest", action="append", type=Path, default=[])
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--scan-results-dir", type=Path, default=SCAN_RESULTS_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    manifests = args.manifest or DEFAULT_MANIFESTS
    cases = load_manifest_cases(manifests)
    results = load_latest_result_rows(args.results_dir)
    rows = summarize(cases, results)
    rows.extend(summarize_scan_rows(cases, load_scan_rows(args.scan_results_dir)))
    rows.sort(key=lambda row: (str(row["Project"]), str(row["Mode"])))

    body = [
        "# Open-Source BASICS Benchmark Summary",
        "",
        "This table uses the latest result row per `case_id` under `Benchmarks/stack_benchmark/results`.",
        "Unlabeled real-project rows report coverage and findings only; TP/FP/FN/TN apply only to seeded ground-truth cases.",
        "",
        markdown_table(rows),
        "",
        "Inputs:",
    ]
    body.extend(f"- `{rel(path)}`" for path in manifests if path.exists())
    body.append(f"- results: `{rel(args.results_dir)}`")
    body.append(f"- scan results: `{rel(args.scan_results_dir)}`")
    text = "\n".join(body) + "\n"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(text)
    print(f"Wrote {rel(args.out)}")


if __name__ == "__main__":
    main()
