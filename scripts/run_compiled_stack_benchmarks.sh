#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run BASICS stack benchmarks against already-prepared binaries.

Usage:
  scripts/run_compiled_stack_benchmarks.sh [sard|juliet|all] [options]

Options:
  --timeout SEC        Per-case timeout passed to run_basics_benchmark.py (default: 120)
  --limit N            Run at most N cases per dataset (default: all)
  --patching           Enable patching (default: --no-patching)
  --cfg-mode MODE      auto, emulated, or fast (default: fast)
  --simulation MODE    auto, static, or angr (default: static)
  --validation-timeout SEC
                       Per validation process/GDB timeout passed to BASICS
  --no-gdb-validation  Disable GDB patch-site validation
  --no-regression-validation
                       Disable benign/boundary regression validation
  --no-metrics         Do not print metrics after each run

Examples:
  scripts/run_compiled_stack_benchmarks.sh sard
  scripts/run_compiled_stack_benchmarks.sh juliet --timeout 180
  scripts/run_compiled_stack_benchmarks.sh all --limit 20 --no-metrics
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="$ROOT/Benchmarks/stack_benchmark/results"

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

timeout_sec=120
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

latest_results() {
  find "$RESULTS_DIR" -mindepth 2 -maxdepth 2 -name results.csv -printf '%T@ %p\n' \
    | sort -nr \
    | awk 'NR==1 {print $2}'
}

run_one() {
  local name="$1"
  local manifest="$2"
  shift 2

  local cmd=(
    python3 scripts/run_basics_benchmark.py
    --manifest "$manifest"
    --timeout-sec "$timeout_sec"
    --cfg-mode "$cfg_mode"
    --function-simulation "$simulation"
    --patched-function-simulation "$simulation"
  )

  if [[ -n "$patch_flag" ]]; then
    cmd+=("$patch_flag")
  fi
  if [[ -n "$limit" ]]; then
    cmd+=(--limit "$limit")
  fi
  cmd+=("$@")
  cmd+=("${validation_args[@]}")

  echo
  echo "== Running $name =="
  echo "+ ${cmd[*]}"
  (cd "$ROOT" && "${cmd[@]}")

  if [[ "$metrics" -eq 1 ]]; then
    local csv
    csv="$(latest_results)"
    if [[ -n "$csv" ]]; then
      echo
      echo "== Metrics for $name =="
      (cd "$ROOT" && python3 scripts/calc_metrics.py "$csv" --by-dataset)
    fi
  fi
}

case "$dataset" in
  sard)
    run_one \
      "SARD" \
      "Benchmarks/stack_benchmark/stack_cases_combined.json" \
      --dataset SARD
    ;;
  juliet)
    run_one \
      "Juliet CWE-121 isolated" \
      "Benchmarks/stack_benchmark/juliet_cwe121_isolated_cases.json"
    ;;
  all)
    run_one \
      "SARD" \
      "Benchmarks/stack_benchmark/stack_cases_combined.json" \
      --dataset SARD
    run_one \
      "Juliet CWE-121 isolated" \
      "Benchmarks/stack_benchmark/juliet_cwe121_isolated_cases.json"
    ;;
esac
