#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run BASICS stack benchmarks against already-prepared binaries.

Usage:
  scripts/run_compiled_stack_benchmarks.sh [sard|juliet|all] [options]

Options:
  --timeout SEC        Per-case timeout passed to run_basics_benchmark.py (default: none)
  --jobs N|auto        Concurrent BASICS cases (default: auto)
  --mem-per-worker MB  Memory estimate used by --jobs auto
  --reserve-memory MB  Memory kept free by --jobs auto
  --limit N            Run at most N cases per dataset (default: all)
  --patching           Enable patching (default: --no-patching)
  --cfg-mode MODE      auto, emulated, or fast (default: fast)
  --simulation MODE    auto, static, or angr (default: static)
  --validation-timeout SEC
                       Per validation process/GDB timeout passed to BASICS
  --no-gdb-validation  Disable GDB patch-site validation
  --no-regression-validation
                       Disable benign/boundary regression validation
  --no-metrics         Do not write stats files after each run

Examples:
  scripts/run_compiled_stack_benchmarks.sh sard
  scripts/run_compiled_stack_benchmarks.sh juliet --timeout 180
  scripts/run_compiled_stack_benchmarks.sh all --limit 20 --no-metrics
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dataset="${1:-all}"
if [[ "$dataset" == "-h" || "$dataset" == "--help" ]]; then
  usage
  exit 0
fi
if [[ "$dataset" != "sard" && "$dataset" != "juliet" && "$dataset" != "all" ]]; then
  echo "Unknown dataset: $dataset" >&2
  usage >&2
  exit 2
fi
if [[ $# -gt 0 ]]; then
  shift
fi

timeout_sec=""
jobs="auto"
mem_per_worker=""
reserve_memory=""
limit=""
patch_flag="--no-patching"
cfg_mode="fast"
simulation="static"
metrics=1
validation_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)
      timeout_sec="${2:?missing value for --timeout}"
      shift 2
      ;;
    --jobs)
      jobs="${2:?missing value for --jobs}"
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
    --patching)
      patch_flag=""
      shift
      ;;
    --cfg-mode)
      cfg_mode="${2:?missing value for --cfg-mode}"
      shift 2
      ;;
    --simulation)
      simulation="${2:?missing value for --simulation}"
      shift 2
      ;;
    --no-metrics)
      metrics=0
      shift
      ;;
    --validation-timeout)
      validation_args+=(--validation-timeout "${2:?missing value for --validation-timeout}")
      shift 2
      ;;
    --no-gdb-validation)
      validation_args+=(--no-gdb-validation)
      shift
      ;;
    --no-regression-validation)
      validation_args+=(--no-regression-validation)
      shift
      ;;
    --strict-stderr-validation)
      validation_args+=(--strict-stderr-validation)
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

run_one() {
  local name="$1"
  local manifest="$2"
  local run_dataset_name="$3"
  shift 3

  local cmd=(
    python3 scripts/run_basics_benchmark.py
    --manifest "$manifest"
    --tool-name basics
    --run-dataset-name "$run_dataset_name"
    --jobs "$jobs"
    --cfg-mode "$cfg_mode"
    --function-simulation "$simulation"
    --patched-function-simulation "$simulation"
  )

  if [[ -n "$timeout_sec" ]]; then
    cmd+=(--timeout-sec "$timeout_sec")
  fi
  if [[ -n "$patch_flag" ]]; then
    cmd+=("$patch_flag")
  fi
  if [[ -n "$limit" ]]; then
    cmd+=(--limit "$limit")
  fi
  if [[ -n "$mem_per_worker" ]]; then
    cmd+=(--mem-per-worker-mb "$mem_per_worker")
  fi
  if [[ -n "$reserve_memory" ]]; then
    cmd+=(--reserve-memory-mb "$reserve_memory")
  fi
  if [[ "$metrics" -eq 0 ]]; then
    cmd+=(--no-stats)
  fi
  cmd+=("$@")
  cmd+=("${validation_args[@]}")

  echo
  echo "== Running $name =="
  echo "+ ${cmd[*]}"
  (cd "$ROOT" && "${cmd[@]}")
}

case "$dataset" in
  sard)
    run_one \
      "SARD" \
      "Benchmarks/stack_benchmark/stack_cases_combined.json" \
      "sard" \
      --dataset SARD
    ;;
  juliet)
    run_one \
      "Juliet CWE-121 isolated" \
      "Benchmarks/stack_benchmark/juliet_cwe121_isolated_cases.json" \
      "juliet"
    ;;
  all)
    run_one \
      "SARD" \
      "Benchmarks/stack_benchmark/stack_cases_combined.json" \
      "sard" \
      --dataset SARD
    run_one \
      "Juliet CWE-121 isolated" \
      "Benchmarks/stack_benchmark/juliet_cwe121_isolated_cases.json" \
      "juliet"
    ;;
esac
