#!/usr/bin/env python3
"""
Build a dynamic-tool-friendly Juliet CWE-121 manifest.

Valgrind and similar runtime tools only observe bugs that are actually executed.
Some Juliet cases require external services or files (for example listen_socket
blocks waiting for a client), so they should not be counted as normal false
negatives in a plain no-driver run.
"""

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IN = ROOT / "Benchmarks" / "stack_benchmark" / "juliet_cwe121_isolated_cases.json"
DEFAULT_OUT = ROOT / "Benchmarks" / "stack_benchmark" / "juliet_cwe121_dynamic_cases.json"

DEFAULT_EXCLUDE_TOKENS = {
    "connect_socket",
    "listen_socket",
    "fscanf",
}


def main():
    parser = argparse.ArgumentParser(description="Filter isolated Juliet manifest for no-driver dynamic tools.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--exclude-token",
        action="append",
        default=sorted(DEFAULT_EXCLUDE_TOKENS),
        help="Case/source substring to exclude; repeatable. Defaults exclude socket/file-input cases.",
    )
    args = parser.parse_args()

    obj = json.loads(args.manifest.read_text(encoding="utf-8"))
    cases = obj["cases"]
    tokens = tuple(args.exclude_token)
    kept = [
        c for c in cases
        if not any(t in c.get("case_id", "") or t in c.get("source_path", "") for t in tokens)
    ]
    positives = sum(1 for c in kept if c["true_present_vuln"])
    out = {
        "meta": {
            "generated_by": "scripts/prepare_juliet_cwe121_dynamic_manifest.py",
            "source_manifest": str(args.manifest),
            "excluded_tokens": list(tokens),
            "note": "No-driver dynamic-tool subset; excludes cases requiring sockets/files by default.",
        },
        "cases": kept,
        "summary": {
            "total": len(kept),
            "positive": positives,
            "negative": len(kept) - positives,
            "excluded": len(cases) - len(kept),
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {len(kept)} cases to {args.out}")
    print(f"Summary: {out['summary']}")
    print(f"Excluded tokens: {', '.join(tokens)}")


if __name__ == "__main__":
    main()
