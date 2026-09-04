#!/usr/bin/env python3
"""Classify BASICS Juliet errors and detection outcomes by testcase family."""

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


CASE_RE = re.compile(r"^(.*)_([0-9]+)_(bad|good)(?:_only)?$")
PROPERTY_RE = re.compile(r"^Property:\s*(\S+)", re.MULTILINE)


def as_bool(value):
    return str(value).strip().lower() == "true"


def identity(case_id):
    match = CASE_RE.match(case_id)
    if not match:
        return case_id, case_id, "unknown"
    family, variant, side = match.groups()
    return family.removeprefix("juliet_CWE121_Stack_Based_Buffer_Overflow__"), f"{family}_{variant}", side


def verdict(row):
    if row["status"] != "ok":
        return row["status"]
    return "+" if as_bool(row["reported_vuln"]) else "-"


def properties(row, root):
    value = row.get("stdout_log_path", "")
    if not value:
        return ()
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    if not path.exists():
        return ()
    return tuple(sorted(set(PROPERTY_RE.findall(path.read_text(errors="replace")))))


def table(title, counter, headers):
    lines = [f"## {title}", "", "| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for key, count in counter.most_common():
        values = key if isinstance(key, tuple) else (key,)
        lines.append("| " + " | ".join([*(str(v) for v in values), str(count)]) + " |")
    lines.append("")
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    rows = list(csv.DictReader(args.results.open(newline="")))
    classes = Counter()
    family_classes = Counter()
    evidence = Counter()
    pairs = defaultdict(dict)

    for row in rows:
        family, pair_id, side = identity(row["case_id"])
        if row["status"] != "ok":
            outcome = row["status"]
        elif as_bool(row["true_present_vuln"]):
            outcome = "TP" if as_bool(row["reported_vuln"]) else "FN"
        else:
            outcome = "FP" if as_bool(row["reported_vuln"]) else "TN"
        classes[outcome] += 1
        family_classes[(outcome, family)] += 1
        if outcome in {"TP", "FP"}:
            props = properties(row, root)
            evidence[(outcome, ", ".join(props) or "unparsed")] += 1
        pairs[pair_id][side] = verdict(row)

    pair_counts = Counter()
    for sides in pairs.values():
        if "bad" in sides and "good" in sides:
            pair_counts[(sides["bad"], sides["good"])] += 1

    lines = [
        "# Juliet result classification",
        "",
        f"Source: `{args.results}`",
        "",
        f"Rows: {len(rows)}",
        "",
    ]
    lines += table("Outcome classes", classes, ("Class", "Cases"))
    lines += table("Family classes", family_classes, ("Class", "Family", "Cases"))
    lines += table("Positive-report evidence", evidence, ("Class", "Properties", "Cases"))
    lines += table("Paired bad/good outcomes", pair_counts, ("Bad", "Good", "Pairs"))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines), encoding="utf-8")
    json_path = args.out.with_suffix(".json")
    json_path.write_text(
        json.dumps(
            {
                "rows": len(rows),
                "classes": dict(classes),
                "family_classes": [
                    {"class": key[0], "family": key[1], "cases": count}
                    for key, count in family_classes.most_common()
                ],
                "evidence": [
                    {"class": key[0], "properties": key[1], "cases": count}
                    for key, count in evidence.most_common()
                ],
                "pair_outcomes": [
                    {"bad": key[0], "good": key[1], "pairs": count}
                    for key, count in pair_counts.most_common()
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(args.out)
    print(json_path)


if __name__ == "__main__":
    main()
