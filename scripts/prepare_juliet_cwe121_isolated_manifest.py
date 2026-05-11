#!/usr/bin/env python3
"""
Build a fair whole-binary Juliet CWE-121 manifest for external tools.

Juliet's normal numbered C binaries contain both _good and _bad functions. BASICS
can start analysis at either entry function, but whole-binary tools generally
cannot. This manifest compiles two isolated binaries from each numbered C source:

  - bad-only:  compiled with -DOMITGOOD, label True
  - good-only: compiled with -DOMITBAD,  label False

That gives the same 1,762 x 2 = 3,524 row shape as juliet_cwe121_eval.py, but
with binaries that are fair for whole-binary analyzers.
"""

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CWE_DIR = ROOT / "Benchmarks" / "C" / "testcases" / "CWE121_Stack_Based_Buffer_Overflow"
OUT_DIR = ROOT / "Benchmarks" / "stack_benchmark" / "generated_bins" / "Juliet_CWE121_isolated"
OUT_SOURCE_DIR = ROOT / "Benchmarks" / "stack_benchmark" / "generated_sources" / "Juliet_CWE121_isolated"
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "stack_benchmark" / "juliet_cwe121_isolated_cases.json"


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


def compile_command(src: Path, binary: Path, omit_macro: str) -> list[str]:
    return [
        "gcc",
        "-std=gnu99",
        "-g",
        "-gdwarf-4",
        "-O0",
        "-fno-stack-protector",
        "-fcf-protection=none",
        "-fno-omit-frame-pointer",
        "-march=x86-64",
        "-mtune=generic",
        "-no-pie",
        "-Wno-implicit-function-declaration",
        "-I",
        "Benchmarks/C/testcasesupport",
        "-DINCLUDEMAIN",
        f"-D{omit_macro}",
        str(src.relative_to(ROOT)),
        "Benchmarks/C/testcasesupport/io.c",
        "Benchmarks/C/testcasesupport/std_thread.c",
        "-o",
        str(binary.relative_to(ROOT)),
        "-lpthread",
        "-lm",
    ]


def write_analysis_source(src: Path, out_source: Path, defined_macros: set[str]):
    """Write a source view with Juliet's OMITGOOD/OMITBAD branches resolved."""
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    out_lines = [
        f"/* Generated from {src.relative_to(ROOT)} for source-level benchmark tools. */",
        f"/* Active macros: {', '.join(sorted(defined_macros))} */",
    ]
    stack: list[dict] = []
    active = True
    managed_macros = {"OMITGOOD", "OMITBAD", "INCLUDEMAIN"}

    def recompute_active():
        value = True
        for frame in stack:
            value = value and frame["condition"]
        return value

    for line in lines:
        stripped = line.strip()
        parts = stripped.split()
        directive = parts[0] if parts and parts[0].startswith("#") else ""
        macro = parts[1] if len(parts) > 1 else ""

        if directive in {"#ifdef", "#ifndef"} and macro in managed_macros:
            condition = macro in defined_macros
            if directive == "#ifndef":
                condition = not condition
            stack.append({"macro": macro, "condition": condition, "managed": True})
            active = recompute_active()
            continue
        if directive in {"#ifdef", "#ifndef", "#if"}:
            stack.append({"macro": macro, "condition": True, "managed": False})
            if active:
                out_lines.append(line)
            continue
        if directive == "#else" and stack:
            frame = stack[-1]
            if frame["managed"]:
                frame["condition"] = not frame["condition"]
                active = recompute_active()
            elif active:
                out_lines.append(line)
            continue
        if directive == "#elif" and stack:
            frame = stack[-1]
            if frame["managed"]:
                frame["condition"] = False
                active = recompute_active()
            elif active:
                out_lines.append(line)
            continue
        if directive == "#endif" and stack:
            frame = stack.pop()
            active = recompute_active()
            if not frame["managed"] and active:
                out_lines.append(line)
            continue

        if active:
            out_lines.append(line)

    out_source.parent.mkdir(parents=True, exist_ok=True)
    out_source.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


def build_cases(cwe_dir: Path) -> list[dict]:
    cases = []
    for src in numbered_c_sources(cwe_dir):
        rel_src = src.relative_to(ROOT)
        safe_stem = src.stem
        bad_bin = OUT_DIR / src.parent.name / f"{safe_stem}__bad_only.out"
        good_bin = OUT_DIR / src.parent.name / f"{safe_stem}__good_only.out"
        bad_source = OUT_SOURCE_DIR / src.parent.name / f"{safe_stem}__bad_only.c"
        good_source = OUT_SOURCE_DIR / src.parent.name / f"{safe_stem}__good_only.c"
        write_analysis_source(src, bad_source, {"INCLUDEMAIN", "OMITGOOD"})
        write_analysis_source(src, good_source, {"INCLUDEMAIN", "OMITBAD"})
        common = {
            "dataset": "Juliet_CWE121_isolated",
            "family": "Juliet",
            "scope": "stack",
            "cwe_group": "CWE121",
            "label_confidence": "high",
            "source_path": str(rel_src),
            "subdir": src.parent.name,
        }
        cases.append(
            {
                **common,
                "case_id": f"juliet_{safe_stem}_bad_only",
                "binary_path": str(bad_bin.relative_to(ROOT)),
                "analysis_source_path": str(bad_source.relative_to(ROOT)),
                "true_present_vuln": True,
                "label_rule": "isolated_bad_binary",
                "compile": {"required": True, "command": compile_command(src, bad_bin, "OMITGOOD")},
            }
        )
        cases.append(
            {
                **common,
                "case_id": f"juliet_{safe_stem}_good_only",
                "binary_path": str(good_bin.relative_to(ROOT)),
                "analysis_source_path": str(good_source.relative_to(ROOT)),
                "true_present_vuln": False,
                "label_rule": "isolated_good_binary",
                "compile": {"required": True, "command": compile_command(src, good_bin, "OMITBAD")},
            }
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description="Build fair isolated Juliet CWE-121 manifest for whole-binary tools.")
    parser.add_argument("--cwe-dir", type=Path, default=DEFAULT_CWE_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    cases = build_cases(args.cwe_dir.resolve())
    positives = sum(1 for c in cases if c["true_present_vuln"])
    obj = {
        "meta": {
            "generated_by": "scripts/prepare_juliet_cwe121_isolated_manifest.py",
            "note": "Fair whole-binary Juliet CWE-121 manifest: bad-only/good-only binaries.",
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
