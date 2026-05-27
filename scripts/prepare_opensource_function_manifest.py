#!/usr/bin/env python3
"""Create a function-entry manifest from real-project binary manifests."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IN = ROOT / "Benchmarks" / "opensource" / "opensource_cases.json"
DEFAULT_OUT = ROOT / "Benchmarks" / "opensource" / "opensource_function_cases.json"
DEFAULT_SYMBOL_RE = r"(parse|decode|encode|handle|process|read|write|copy|config|packet|frame|message|socket|server|client|ec_|CS101|CS104)"
SKIP_SYMBOLS = {"main", "_start", "__libc_csu_init", "__libc_csu_fini"}


def load_cases(path: Path) -> list[dict]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, list):
        return obj
    if "cases" in obj:
        return obj["cases"]
    if "datasets" in obj:
        cases = []
        for dataset in obj["datasets"].values():
            cases.extend(dataset.get("cases", []))
        return cases
    raise ValueError(f"Unsupported manifest format: {path}")


def symbols_for(binary: Path) -> list[str]:
    proc = subprocess.run(
        ["nm", "-C", "--defined-only", str(binary)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    symbols = []
    for line in proc.stdout.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) != 3:
            continue
        _, kind, name = parts
        if kind.lower() != "t" and kind not in {"W", "V"}:
            continue
        name = name.split("(", 1)[0].strip()
        if not name or name in SKIP_SYMBOLS or name.startswith("_"):
            continue
        symbols.append(name)
    return sorted(set(symbols))


def safe_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")[:120]


def rel(path: Path) -> str:
    path = path if path.is_absolute() else ROOT / path
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate selected function-entry cases for open-source binaries.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--project", action="append", default=[], help="Filter by project name, repeatable.")
    parser.add_argument("--case-id", action="append", default=[], help="Filter binary case id substring, repeatable.")
    parser.add_argument("--symbol-regex", default=DEFAULT_SYMBOL_RE)
    parser.add_argument(
        "--max-functions-per-binary",
        type=int,
        default=None,
        help="Optional cap on selected functions per binary. By default all matching symbols are included.",
    )
    parser.add_argument(
        "--all-symbols",
        action="store_true",
        help="Include all defined user text symbols.",
    )
    parser.add_argument("--include-main", action="store_true")
    args = parser.parse_args()

    cases = load_cases(args.manifest)
    if args.project:
        allowed = {f"opensource/{name}" for name in args.project}
        cases = [case for case in cases if case.get("dataset") in allowed]
    if args.case_id:
        needles = [needle.lower() for needle in args.case_id]
        cases = [case for case in cases if any(needle in case["case_id"].lower() for needle in needles)]

    symbol_regex = ".*" if args.all_symbols else args.symbol_regex
    max_functions_per_binary = args.max_functions_per_binary
    pattern = re.compile(symbol_regex)
    out_cases = []
    for case in cases:
        binary = ROOT / case["binary_path"]
        selected = [sym for sym in symbols_for(binary) if pattern.search(sym)]
        if args.include_main:
            selected.insert(0, "main")
        selected = list(dict.fromkeys(selected))
        if max_functions_per_binary is not None:
            selected = selected[:max_functions_per_binary]
        for symbol in selected:
            next_case = dict(case)
            next_case["case_id"] = f"{case['case_id']}__entry_{safe_id(symbol)}"
            next_case["analysis_entry"] = symbol
            next_case["patched_analysis_entry"] = symbol
            next_case["label_rule"] = "real_project_function_entry_unlabeled"
            out_cases.append(next_case)

    manifest = {
        "generated_by": "scripts/prepare_opensource_function_manifest.py",
        "source_manifest": str(args.manifest),
        "symbol_regex": symbol_regex,
        "note": "Unlabeled real-project function-entry cases for BASICS.",
        "cases": out_cases,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(out_cases)} function-entry cases to {rel(args.out)}")


if __name__ == "__main__":
    main()
