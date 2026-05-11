#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path


HARNESS = Path(__file__).with_name("run_external_tool_benchmark.py")


def load_harness():
    spec = importlib.util.spec_from_file_location("external_bench", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    bench = load_harness()

    cwe_checker_empty = "INFO: CWE676: Program imports dangerous symbols:\n[]\n"
    assert bench.parse_cwe_checker_cwes(cwe_checker_empty) == []

    cwe_checker_hit = "INFO: CWE676 is mentioned in logs\n" + json.dumps(
        [{"name": "CWE119", "addresses": ["0x401000"]}],
        indent=2,
    )
    assert bench.parse_cwe_checker_cwes(cwe_checker_hit) == ["CWE-119"]

    codeql_no_result = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "cpp/very-likely-overrunning-write",
                                "properties": {"tags": ["external/cwe/cwe-120"]},
                            }
                        ]
                    }
                },
                "results": [],
            }
        ]
    }
    assert bench.parse_codeql_cwes("Loaded CWE-120 query\nSARIF_JSON:\n" + json.dumps(codeql_no_result)) == []

    codeql_hit = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "cpp/very-likely-overrunning-write",
                                "properties": {"tags": ["external/cwe/cwe-120", "external/cwe/cwe-787"]},
                            }
                        ]
                    }
                },
                "results": [{"ruleId": "cpp/very-likely-overrunning-write", "ruleIndex": 0}],
            }
        ]
    }
    assert bench.parse_codeql_cwes("SARIF_JSON:\n" + json.dumps(codeql_hit)) == ["CWE-120", "CWE-787"]

    codeql_stub_rule_hit = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "cpp/unbounded-write",
                                "properties": {"tags": ["external/cwe/cwe-120", "external/cwe/cwe-787"]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "cpp/unbounded-write",
                        "ruleIndex": 0,
                        "rule": {"id": "cpp/unbounded-write", "index": 0},
                    }
                ],
            }
        ]
    }
    assert bench.parse_codeql_cwes("SARIF_JSON:\n" + json.dumps(codeql_stub_rule_hit)) == ["CWE-120", "CWE-787"]

    bai_output = "\n".join(
        [
            "Loaded config: CWE119",
            json.dumps({"logger": "CWE", "message": "CWE190 not a buffer overflow"}),
            json.dumps({"logger": "CWE", "message": "CWE125 out-of-bounds read"}),
            json.dumps({"logger": "CWE", "message": "CWE787 buffer overflow"}),
            json.dumps({"logger": "CWE", "message": "CWE787: Heap Out-of-Bound Write"}),
        ]
    )
    assert bench.parse_binabsinspector_cwes(bai_output) == ["CWE-125", "CWE-787"]

    flawfinder_csv = 'File,Line,CWEs\na.c,1,"CWE-120, CWE-20"\n'
    assert bench.parse_flawfinder_cwes(flawfinder_csv) == ["CWE-120"]

    assert bench.parse_arbiter_cwes("ARBITER_REPORTS: 0\n") == []
    assert bench.parse_arbiter_cwes("ARBITER_REPORTS: 2\n") == ["CWE-121"]

    print("external tool parser tests passed")


if __name__ == "__main__":
    main()
