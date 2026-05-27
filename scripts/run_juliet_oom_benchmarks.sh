#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run focused Juliet OOM/error benchmark manifests without overwriting prior results.

Usage:
  scripts/run_juliet_oom_benchmarks.sh [all-errors|direct-errors|repro|direct-repro|family-name|direct-family-name|manifest-path] [options]

Options:
  --results-csv PATH     Source full-run results.csv used to prepare manifests
  --prepare              Regenerate specialized manifests before running
  --timeout SEC          Per-case timeout (default: 3600)
  --jobs N|auto          Concurrent cases (default: 1)
  --memory-limit MB      BASICS RSS ceiling passed to each analyzer (default: 8192)
  --mem-per-worker MB    Memory estimate used by --jobs auto
  --reserve-memory MB    Memory kept free by --jobs auto
  --limit N              Run at most N cases from the selected manifest
  --no-stats             Do not write benchmark stats

Examples:
  scripts/run_juliet_oom_benchmarks.sh --prepare repro
  scripts/run_juliet_oom_benchmarks.sh direct-repro --timeout 1800
  scripts/run_juliet_oom_benchmarks.sh all-errors --jobs 1 --memory-limit 8192
  scripts/run_juliet_oom_benchmarks.sh cwe135 --timeout 1800
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

selection="all-errors"
selection_explicit=0
if [[ $# -gt 0 && "${1:-}" != -* ]]; then
  selection="$1"
  selection_explicit=1
  shift
fi

results_csv=""
prepare=0
timeout_sec=3600
jobs=1
memory_limit=8192
mem_per_worker=""
reserve_memory=""
limit=""
stats=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --results-csv)
      results_csv="${2:?missing value for --results-csv}"
      shift 2
      ;;
    --prepare)
      prepare=1
      shift
      ;;
    --timeout)
      timeout_sec="${2:?missing value for --timeout}"
      shift 2
      ;;
    --jobs)
      jobs="${2:?missing value for --jobs}"
      shift 2
      ;;
    --memory-limit)
      memory_limit="${2:?missing value for --memory-limit}"
      shift 2
      ;;
    --mem-per-worker)
      mem_per_worker="${2:?missing value for --mem-per-worker}"
      shift 2
      ;;
    --reserve-memory)
      reserve_memory="${2:?missing value for --reserve-memory}"
      shift 2
      ;;
    --limit)
      limit="${2:?missing value for --limit}"
      shift 2
      ;;
    --no-stats)
      stats=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ "$1" != -* && "$selection_explicit" -eq 0 ]]; then
        selection="$1"
        selection_explicit=1
        shift
      else
        echo "Unknown option: $1" >&2
        usage >&2
        exit 2
      fi
      ;;
  esac
done

cd "$ROOT"

prepare_cmd=(python3 scripts/prepare_juliet_oom_benchmarks.py)
if [[ -n "$results_csv" ]]; then
  prepare_cmd+=(--results-csv "$results_csv")
fi
if [[ "$prepare" -eq 1 ]]; then
  echo "+ ${prepare_cmd[*]}"
  "${prepare_cmd[@]}"
fi

latest_manifest_prefix() {
  local pattern="$1"
  python3 - "$pattern" <<'PY'
import glob
import os
import sys

matches = glob.glob(sys.argv[1])
if not matches:
    raise SystemExit(f"No manifests matched {sys.argv[1]}")
matches.sort(key=os.path.getmtime, reverse=True)
print(matches[0])
PY
}

manifest=""
case "$selection" in
  all-errors)
    manifest="$(latest_manifest_prefix 'Benchmarks/stack_benchmark/specialized/*_oom_error_cases.json')"
    run_dataset_name="juliet_oom_errors"
    ;;
  direct-errors)
    manifest="$(latest_manifest_prefix 'Benchmarks/stack_benchmark/specialized/*_oom_direct_entry_cases.json')"
    run_dataset_name="juliet_oom_direct_errors"
    ;;
  repro)
    manifest="$(latest_manifest_prefix 'Benchmarks/stack_benchmark/specialized/*_oom_repro_one_per_family.json')"
    run_dataset_name="juliet_oom_repro"
    ;;
  direct-repro)
    manifest="$(latest_manifest_prefix 'Benchmarks/stack_benchmark/specialized/*_oom_direct_repro_one_per_family.json')"
    run_dataset_name="juliet_oom_direct_repro"
    ;;
  *.json|*/*.json)
    manifest="$selection"
    run_dataset_name="juliet_oom_custom"
    ;;
  *)
    normalized="$(echo "$selection" | tr '[:upper:]-' '[:lower:]_')"
    if [[ "$normalized" == direct_* ]]; then
      family="${normalized#direct_}"
      manifest="$(latest_manifest_prefix "Benchmarks/stack_benchmark/specialized/*_oom_direct_*${family}*.json")"
    else
      manifest="$(latest_manifest_prefix "Benchmarks/stack_benchmark/specialized/*_oom_*${normalized}*.json")"
    fi
    run_dataset_name="juliet_oom_${normalized}"
    ;;
esac

cmd=(
  python3 scripts/run_basics_benchmark.py
  --manifest "$manifest"
  --tool-name basics_oom
  --run-dataset-name "$run_dataset_name"
  --jobs "$jobs"
  --timeout-sec "$timeout_sec"
  --memory-limit-mb "$memory_limit"
  --no-patching
  --cfg-mode fast
  --function-simulation static
  --patched-function-simulation static
)

if [[ -n "$mem_per_worker" ]]; then
  cmd+=(--mem-per-worker-mb "$mem_per_worker")
fi
if [[ -n "$reserve_memory" ]]; then
  cmd+=(--reserve-memory-mb "$reserve_memory")
fi
if [[ -n "$limit" ]]; then
  cmd+=(--limit "$limit")
fi
if [[ "$stats" -eq 0 ]]; then
  cmd+=(--no-stats)
fi

echo "Selected manifest: $manifest"
echo "+ ${cmd[*]}"
"${cmd[@]}"
