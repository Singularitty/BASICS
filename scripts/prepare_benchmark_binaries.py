#!/usr/bin/env python3
import argparse
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "stack_benchmark" / "juliet_cwe121_isolated_cases.json"
DEFAULT_REPORT = ROOT / "Benchmarks" / "stack_benchmark" / "binary_prepare_report.json"


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


def parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def normalize_command(cmd: list[str]) -> list[str]:
    old_roots = [
        "/home/luisf/Work/Projects/BASICS",
        str(ROOT),
    ]
    normalized = []
    for part in cmd:
        text = str(part)
        for old_root in old_roots:
            if text.startswith(old_root + "/"):
                text = str(ROOT / text[len(old_root) + 1 :])
                break
        normalized.append(text)
    return normalized


def prepare_case(case: dict, force: bool, timeout_sec: int) -> dict:
    case_id = case.get("case_id", "")
    binary_path = case.get("binary_path")
    if not binary_path:
        return {"case_id": case_id, "status": "skipped", "error": "missing_binary_path", "elapsed_sec": 0.0}

    binary = ROOT / binary_path
    if binary.exists() and not force:
        return {"case_id": case_id, "status": "exists", "binary_path": binary_path, "error": "", "elapsed_sec": 0.0}

    compile_info = case.get("compile", {})
    if not parse_bool(compile_info.get("required", False)):
        return {
            "case_id": case_id,
            "status": "missing",
            "binary_path": binary_path,
            "error": f"binary_missing:{binary}",
            "elapsed_sec": 0.0,
        }

    cmd = compile_info.get("command") or []
    if not cmd:
        return {"case_id": case_id, "status": "failed", "binary_path": binary_path, "error": "compile_command_missing", "elapsed_sec": 0.0}

    binary.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            normalize_command(cmd),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        elapsed = round(time.perf_counter() - start, 4)
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return {
            "case_id": case_id,
            "status": "timeout",
            "binary_path": binary_path,
            "error": output[-1200:],
            "elapsed_sec": timeout_sec,
        }

    if proc.returncode != 0:
        return {
            "case_id": case_id,
            "status": "failed",
            "binary_path": binary_path,
            "error": proc.stdout[-1200:],
            "elapsed_sec": elapsed,
        }
    if not binary.exists():
        return {
            "case_id": case_id,
            "status": "failed",
            "binary_path": binary_path,
            "error": "compile_finished_binary_missing",
            "elapsed_sec": elapsed,
        }
    return {"case_id": case_id, "status": "compiled", "binary_path": binary_path, "error": "", "elapsed_sec": elapsed}


def main():
    parser = argparse.ArgumentParser(description="Compile all missing binaries referenced by a benchmark manifest.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dataset", action="append", default=[])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--out", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    cases = load_cases(args.manifest)
    if args.dataset:
        allowed = set(args.dataset)
        cases = [case for case in cases if case.get("dataset") in allowed]
    if args.limit is not None:
        cases = cases[: args.limit]

    rows = []
    counts = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(prepare_case, case, args.force, args.timeout_sec): case for case in cases}
        for idx, future in enumerate(as_completed(futures), start=1):
            row = future.result()
            rows.append(row)
            counts[row["status"]] = counts.get(row["status"], 0) + 1
            print(f"[{idx}/{len(cases)}] {row['case_id']}: {row['status']}", flush=True)

    summary = {"manifest": str(args.manifest), "total": len(cases), "counts": counts, "rows": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote prepare report to {args.out}")
    print(f"Summary: {counts}")

    if any(status in counts for status in ("failed", "timeout", "missing", "skipped")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
