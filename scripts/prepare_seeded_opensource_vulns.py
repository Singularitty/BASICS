#!/usr/bin/env python3
"""Create seeded vulnerable CPS-flavored binaries for BASICS patch testing."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "Benchmarks" / "opensource" / "seeded_vulns"
SRC_DIR = BASE / "sources"
BIN_DIR = BASE / "bins"
DEFAULT_MANIFEST = BASE / "seeded_vuln_cases.json"


CASES = [
    {
        "case_id": "seeded_soem_slaveinfo_name_strcpy",
        "entry": "seeded_soem_slaveinfo_name",
        "rule": "seeded_strcpy_stack_overflow",
        "source": r'''
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int seeded_soem_slaveinfo_name(void)
{
    char ethercat_name[16];
    const char *slave_name = "EL9800_default_slave_name_too_long";
    strcpy(ethercat_name, slave_name);
    return ethercat_name[0] == '\0';
}

int main(void)
{
    int rc = seeded_soem_slaveinfo_name();
    printf("slave rc=%d\n", rc);
    return rc;
}
''',
    },
    {
        "case_id": "seeded_lib60870_apdu_sprintf",
        "entry": "seeded_lib60870_apdu_log",
        "rule": "seeded_sprintf_stack_overflow",
        "source": r'''
#include <stdio.h>

__attribute__((noinline))
int seeded_lib60870_apdu_log(const char *station, int cot)
{
    char line[24];
    sprintf(line, "station=%s cot=%d", station, cot);
    return line[0] == '\0';
}

int main(int argc, char **argv)
{
    const char *station = argc > 1 ? argv[1] : "very_long_iec104_station_identifier";
    int rc = seeded_lib60870_apdu_log(station, 44);
    printf("apdu rc=%d\n", rc);
    return rc;
}
''',
    },
    {
        "case_id": "seeded_canopen_pdo_memcpy",
        "entry": "seeded_canopen_pdo_copy",
        "rule": "seeded_memcpy_stack_overflow",
        "source": r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int seeded_canopen_pdo_copy(const uint8_t *pdo, size_t pdo_len)
{
    uint8_t local_pdo[8];
    memcpy(local_pdo, pdo, pdo_len);
    return local_pdo[0];
}

int main(void)
{
    uint8_t frame[32];
    memset(frame, 0x41, sizeof(frame));
    int rc = seeded_canopen_pdo_copy(frame, sizeof(frame));
    printf("pdo rc=%d\n", rc);
    return rc == 0;
}
''',
    },
    {
        "case_id": "seeded_plc_tag_scanf",
        "entry": "seeded_plc_tag_scan",
        "rule": "seeded_scanf_stack_overflow",
        "source": r'''
#include <stdio.h>

__attribute__((noinline))
int seeded_plc_tag_scan(void)
{
    char tag_name[12];
    scanf("%s", tag_name);
    return tag_name[0] == '\0';
}

int main(void)
{
    return seeded_plc_tag_scan();
}
''',
    },
]


def compile_case(case: dict, force: bool) -> dict:
    SRC_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    source = SRC_DIR / f"{case['case_id']}.c"
    binary = BIN_DIR / case["case_id"]
    source_text = case["source"].lstrip()
    if not source.exists() or source.read_text(encoding="utf-8") != source_text:
        source.write_text(source_text, encoding="utf-8")

    source_is_newer = binary.exists() and source.stat().st_mtime > binary.stat().st_mtime
    if binary.exists() and not force and not source_is_newer:
        return {"case_id": case["case_id"], "status": "exists", "binary_path": str(binary.relative_to(ROOT)), "error": ""}

    cmd = [
        "gcc",
        "-g",
        "-gdwarf-4",
        "-O0",
        "-fno-stack-protector",
        "-U_FORTIFY_SOURCE",
        "-fcf-protection=none",
        "-fno-omit-frame-pointer",
        "-march=x86-64",
        "-mtune=generic",
        "-no-pie",
        str(source),
        "-o",
        str(binary),
    ]
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    if proc.returncode != 0:
        return {
            "case_id": case["case_id"],
            "status": "failed",
            "binary_path": str(binary.relative_to(ROOT)),
            "error": proc.stdout[-1600:],
        }
    return {"case_id": case["case_id"], "status": "compiled", "binary_path": str(binary.relative_to(ROOT)), "error": ""}


def manifest_rows() -> list[dict]:
    rows = []
    for case in CASES:
        rows.append(
            {
                "case_id": case["case_id"],
                "dataset": "opensource/seeded_vulns",
                "true_present_vuln": True,
                "label_confidence": "seeded",
                "label_rule": case["rule"],
                "analysis_entry": case["entry"],
                "patched_analysis_entry": case["entry"],
                "source_path": str((SRC_DIR / f"{case['case_id']}.c").relative_to(ROOT)),
                "binary_path": str((BIN_DIR / case["case_id"]).relative_to(ROOT)),
                "compile": {"required": False},
                "project": "seeded_opensource",
                "project_description": "Small CPS-flavored seeded vulnerabilities for BASICS detection and patch tests.",
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build seeded vulnerable binaries for BASICS.")
    parser.add_argument("--out", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    counts = {}
    rows = []
    for case in CASES:
        row = compile_case(case, args.force)
        rows.append(row)
        counts[row["status"]] = counts.get(row["status"], 0) + 1
        print(f"{row['case_id']}: {row['status']}")
        if row["error"]:
            print(row["error"])

    manifest = {
        "generated_by": "scripts/prepare_seeded_opensource_vulns.py",
        "note": "Ground-truth seeded vulnerable binaries; all cases should report CWE-121.",
        "cases": manifest_rows(),
        "prepare_rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(manifest['cases'])} cases to {args.out.relative_to(ROOT)}")
    print(f"Summary: {counts}")

    if counts.get("failed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
