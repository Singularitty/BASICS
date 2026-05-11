#!/usr/bin/env python3
"""
Build the paper-style Juliet CWE-121 manifest used by juliet_cwe121_eval.py.

The existing stack_cases_combined.json manifest is convenient for whole-binary
experiments, but it only contains filename-labelled _bad/_good source variants.
The Juliet evaluation script uses numbered C variants instead:

  1,762 numbered C binaries x (_bad entry + _good entry) = 3,524 rows

External whole-binary tools cannot usually start at entry_function, but keeping
the entry metadata in the manifest lets the CSV line up with BASICS' evaluation.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CWE_DIR = ROOT / "Benchmarks" / "C" / "testcases" / "CWE121_Stack_Based_Buffer_Overflow"
DEFAULT_OUT = ROOT / "Benchmarks" / "stack_benchmark" / "juliet_cwe121_entry_cases.json"


def get_symbols(binary: Path) -> list[str]:
    try:
        raw = subprocess.check_output(["nm", str(binary)], stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return []
    names = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "T":
            names.append(parts[2])
    return names


def pick_bad_good(symbols: list[str]) -> tuple[str | None, str | None]:
    bad = good = None
    for name in symbols:
        if not name.startswith("CWE"):
            continue
        if bad is None and name.endswith("_bad"):
            bad = name
        elif good is None and name.endswith("_good"):
            good = name
    return bad, good


def numbered_c_sources(cwe_dir: Path) -> list[Path]:
    sources = []
    for subdir in sorted(cwe_dir.iterdir()):
        if not subdir.is_dir():
            continue
        for src in sorted(subdir.glob("CWE*.c")):
            if "w32" in src.name or "wchar_t" in src.name:
                continue
            if src.stem and src.stem[-1].isdigit():
                sources.append(src)
    return sources


def relative_compile_command(binary: Path) -> list[str]:
    # Juliet's Makefiles build all individual binaries in a subdirectory. Use a
    # relative -C path so the manifest works after copying to the server.
    return ["make", "-C", str(binary.parent.relative_to(ROOT)), "individuals"]


def build_cases(cwe_dir: Path) -> list[dict]:
    cases = []
    for src in numbered_c_sources(cwe_dir):
        binary = src.with_suffix(".out")
        symbols = get_symbols(binary) if binary.exists() else []
        bad_func, good_func = pick_bad_good(symbols)
        if not bad_func:
            bad_func = f"{src.stem}_bad"
        if not good_func:
            good_func = f"{src.stem}_good"

        rel_src = src.relative_to(ROOT)
        rel_binary = binary.relative_to(ROOT)
        m = re.match(r"^(.*?)_(\d+)$", src.stem)
        base_name = m.group(1) if m else src.stem
        variant_number = m.group(2) if m else ""

        common = {
            "dataset": "Juliet_CWE121_entries",
            "family": "Juliet",
            "scope": "stack",
            "cwe_group": "CWE121",
            "label_confidence": "high",
            "source_path": str(rel_src),
            "binary_path": str(rel_binary),
            "subdir": src.parent.name,
            "base_name": base_name,
            "variant_number": variant_number,
            "compile": {
                "required": True,
                "command": relative_compile_command(binary),
            },
        }
        cases.append(
            {
                **common,
                "case_id": f"juliet_{src.stem}_bad",
                "entry_function": bad_func,
                "true_present_vuln": True,
                "label_rule": "entry_bad_function",
            }
        )
        cases.append(
            {
                **common,
                "case_id": f"juliet_{src.stem}_good",
                "entry_function": good_func,
                "true_present_vuln": False,
                "label_rule": "entry_good_function",
            }
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description="Build Juliet CWE-121 entry-function benchmark manifest.")
    parser.add_argument("--cwe-dir", type=Path, default=DEFAULT_CWE_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    cwe_dir = args.cwe_dir.resolve()
    cases = build_cases(cwe_dir)
    positives = sum(1 for c in cases if c["true_present_vuln"])
    obj = {
        "meta": {
            "generated_by": "scripts/prepare_juliet_cwe121_entry_manifest.py",
            "note": "Paper-style Juliet CWE-121 manifest: numbered C binaries x bad/good entry rows.",
            "external_tool_caveat": "Most external tools analyze the whole binary and cannot honor entry_function.",
        },
        "cases": cases,
        "summary": {
            "total": len(cases),
            "positive": positives,
            "negative": len(cases) - positives,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    print(f"Wrote {len(cases)} cases to {args.out}")
    print(f"Summary: {obj['summary']}")


if __name__ == "__main__":
    main()
