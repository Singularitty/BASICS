#!/usr/bin/env python3
"""
Generate ground-truth Excel datasets for the SARD and Juliet CWE-121 benchmarks.

SARD sheet (151 rows):
  One row per binary — binary_path, ground_truth, source_path, vulnerability_type, label_rule.

Juliet CWE-121 sheet (3,524 rows, matching the paper):
  Two rows per numbered C binary — one targeting the _bad function (ground_truth=True)
  and one targeting the _good function (ground_truth=False).
  These entry-function columns are used by BASICS (--analysis-entry).
  For tools that analyse the whole binary, use the binary_path directly and note that
  every numbered binary contains BOTH vulnerable and safe code paths.
"""

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTCASES = ROOT / "Benchmarks/C/testcases/CWE121_Stack_Based_Buffer_Overflow"
MANIFEST   = ROOT / "Benchmarks/stack_benchmark/stack_cases_combined.json"
OUT_DIR    = ROOT / "datasets"

OUT_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_symbols(binary: Path):
    """Return list of T-section symbol names exported by *binary*."""
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


def pick_bad_good(symbols):
    """Return (bad_func, good_func) from a list of symbol names."""
    bad = good = None
    for n in symbols:
        if not n.startswith("CWE"):
            continue
        if bad is None and n.endswith("_bad"):
            bad = n
        if good is None and n.endswith("_good"):
            good = n
    return bad, good


FUNCTION_TYPE_MAP = {
    "strcpy_overflow":       "strcpy",
    "strcpy_safe":           "strcpy",
    "sprintf_overflow":      "sprintf",
    "sprintf_safe":          "sprintf",
    "scanf_unbounded":       "scanf",
    "scanf_width_lt_buffer": "scanf",
    "scanf_width_ge_buffer": "scanf",
    "sscanf_overflow":       "sscanf",
    "sscanf_safe":           "sscanf",
    "vsprintf_overflow":     "vsprintf",
    "vsprintf_safe":         "vsprintf",
    "vsprintf_global_safe":  "vsprintf",
    "gets_usage":            "gets",
    "stack_underwrite":      "buffer write",
    "heap_issue_only":       "heap (not stack)",
    "bounded_array_access":  "array access",
    "integer_scan_only":     "integer scan",
}


# ---------------------------------------------------------------------------
# SARD dataset
# ---------------------------------------------------------------------------

def build_sard(manifest: dict) -> list[dict]:
    cases = manifest["datasets"]["SARD"]["cases"]
    rows = []
    for c in cases:
        bin_path = ROOT / c["binary_path"]
        src_path = ROOT / c["source_path"]
        rows.append({
            "case_id":          c["case_id"],
            "binary_path":      str(bin_path),
            "binary_exists":    bin_path.exists(),
            "source_path":      str(src_path),
            "ground_truth":     c["true_present_vuln"],
            "label":            "Vuln" if c["true_present_vuln"] else "NotVuln",
            "label_confidence": c.get("label_confidence", ""),
            "label_rule":       c.get("label_rule", ""),
            "function_type":    FUNCTION_TYPE_MAP.get(c.get("label_rule", ""), ""),
            "compile_command":  " ".join(c.get("compile", {}).get("command", [])),
        })
    rows.sort(key=lambda r: r["case_id"])
    return rows


# ---------------------------------------------------------------------------
# Juliet CWE-121 dataset (numbered C variants, matches paper's 1,762 × 2 = 3,524)
# ---------------------------------------------------------------------------

def build_juliet() -> list[dict]:
    rows = []
    for subdir in sorted(TESTCASES.iterdir()):
        if not subdir.is_dir():
            continue
        # Numbered C source files only (variants 01–45).
        c_files = sorted(
            f for f in subdir.glob("CWE*.c")
            if "w32" not in f.name and "wchar_t" not in f.name and f.stem[-1].isdigit()
        )
        for src in c_files:
            binary = src.with_suffix(".out")
            # Extract base name and variant number — stem ends in _<digits>.
            m = re.match(r"^(.*?)_(\d+)$", src.stem)
            base_name    = m.group(1) if m else src.stem
            variant_num  = m.group(2) if m else ""

            # Resolve entry-function names from the binary's symbol table.
            syms = get_symbols(binary) if binary.exists() else []
            bad_func, good_func = pick_bad_good(syms)

            # If nm failed (binary not compiled yet) fall back to the convention.
            if not bad_func:
                bad_func  = f"{src.stem}_bad"
            if not good_func:
                good_func = f"{src.stem}_good"

            common = {
                "subdir":         subdir.name,
                "base_name":      base_name,
                "variant_number": variant_num,
                "binary_path":    str(binary),
                "binary_exists":  binary.exists(),
                "source_path":    str(src),
            }

            # One row for the bad (vulnerable) path.
            rows.append({
                **common,
                "case_id":        f"juliet_{src.stem}_bad",
                "entry_function": bad_func,
                "ground_truth":   True,
                "label":          "Vuln",
            })

            # One row for the good (safe) path.
            rows.append({
                **common,
                "case_id":        f"juliet_{src.stem}_good",
                "entry_function": good_func,
                "ground_truth":   False,
                "label":          "NotVuln",
            })

    return rows


# ---------------------------------------------------------------------------
# Write Excel
# ---------------------------------------------------------------------------

def write_xlsx(rows: list[dict], path: Path, sheet_name: str, freeze_col: str | None = None):
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name

    if not rows:
        wb.save(path)
        return

    headers = list(rows[0].keys())
    HEADER_FILL   = PatternFill("solid", fgColor="1F4E79")
    HEADER_FONT   = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
    VULN_FILL     = PatternFill("solid", fgColor="FCE4D6")
    NOT_VULN_FILL = PatternFill("solid", fgColor="E2EFDA")
    MISSING_FILL  = PatternFill("solid", fgColor="FFF2CC")
    NORMAL_FONT   = Font(name="Calibri", size=10)

    # Header row
    for col_idx, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx, value=h)
        cell.font   = HEADER_FONT
        cell.fill   = HEADER_FILL
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    ws.row_dimensions[1].height = 30

    # Data rows
    for row_idx, row in enumerate(rows, 2):
        gt = row.get("ground_truth")
        exists = row.get("binary_exists", True)

        for col_idx, h in enumerate(headers, 1):
            val = row[h]
            # Booleans as strings for readability in most columns,
            # but keep True/False for ground_truth and binary_exists
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.font = NORMAL_FONT
            cell.alignment = Alignment(vertical="center")

        # Row colour: red tint for vuln, green tint for not-vuln; yellow if binary missing.
        if not exists:
            fill = MISSING_FILL
        elif gt:
            fill = VULN_FILL
        else:
            fill = NOT_VULN_FILL

        for col_idx in range(1, len(headers) + 1):
            ws.cell(row=row_idx, column=col_idx).fill = fill

    # Column widths (auto-fit approximation).
    WIDTH_HINTS = {
        "case_id": 52, "binary_path": 90, "source_path": 90,
        "compile_command": 60, "entry_function": 65, "base_name": 60,
        "label_rule": 28, "function_type": 18, "label_confidence": 17,
        "binary_exists": 14, "ground_truth": 13, "label": 10,
        "subdir": 8, "variant_number": 12,
    }
    for col_idx, h in enumerate(headers, 1):
        width = WIDTH_HINTS.get(h, max(len(h) + 4, 14))
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    # Freeze header + optionally the first data column.
    ws.freeze_panes = "A2"

    # Auto-filter on header row.
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}1"

    wb.save(path)
    print(f"  Wrote {len(rows):,} rows → {path.relative_to(ROOT)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Loading manifest …")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    print("\nBuilding SARD dataset …")
    sard_rows = build_sard(manifest)
    vuln = sum(r["ground_truth"] for r in sard_rows)
    print(f"  {len(sard_rows)} cases: {vuln} Vuln, {len(sard_rows)-vuln} NotVuln")
    write_xlsx(sard_rows, OUT_DIR / "sard_dataset.xlsx", "SARD")

    print("\nBuilding Juliet CWE-121 dataset …")
    juliet_rows = build_juliet()
    vuln = sum(r["ground_truth"] for r in juliet_rows)
    binaries_exist = sum(r["binary_exists"] for r in juliet_rows)
    print(f"  {len(juliet_rows)} rows ({len(juliet_rows)//2} binaries × 2): "
          f"{vuln} Vuln, {len(juliet_rows)-vuln} NotVuln")
    print(f"  Binaries present on disk: {binaries_exist}/{len(juliet_rows)}")
    write_xlsx(juliet_rows, OUT_DIR / "juliet_cwe121_dataset.xlsx", "Juliet_CWE121")

    print("\nDone. Files are in datasets/")
    print("  Yellow rows = binary not yet compiled (run scripts/compile_juliet.sh first for Juliet).")
    print("  Red   rows = Vuln ground truth.")
    print("  Green rows = NotVuln ground truth.")
    print()
    print("Column notes:")
    print("  entry_function  — pass to BASICS via --analysis-entry")
    print("  binary_path     — pass directly to any other tool (CWE_Checker, etc.)")
    print("  ground_truth    — True = vulnerable, False = not vulnerable")


if __name__ == "__main__":
    main()
