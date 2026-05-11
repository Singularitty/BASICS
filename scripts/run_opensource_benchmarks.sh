#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run BASICS over open-source real-project binaries prepared by setup_opensource_benchmarks.py.

Usage:
  scripts/run_opensource_benchmarks.sh [options]

Options:
  --manifest PATH      Manifest path (default: Benchmarks/opensource/opensource_cases.json)
  --project NAME       Filter dataset by project name, repeatable
  --case-id TEXT       Filter case id substring, repeatable
  --timeout SEC        Per-binary timeout (default: 180)
  --memory MB          RSS memory ceiling passed to BASICS
  --limit N            Run at most N matching binaries
  --patching           Enable patching (default: --no-patching)
  --cfg-mode MODE      auto, emulated, or fast (default: fast)
  --simulation MODE    auto, static, or angr (default: static)

Examples:
  scripts/setup_opensource_benchmarks.py --project soem --max-binaries-per-project 5
  scripts/run_opensource_benchmarks.sh --project soem --limit 3 --timeout 120
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

manifest="Benchmarks/opensource/opensource_cases.json"
timeout_sec=180
memory_limit=""
limit=""
patch_flag="--no-patching"
cfg_mode="fast"
simulation="static"
extra_filters=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      manifest="${2:?missing value for --manifest}"
      shift 2
      ;;
    --project)
      extra_filters+=(--dataset "opensource/${2:?missing value for --project}")
      shift 2
      ;;
    --case-id)
      extra_filters+=(--case-id "${2:?missing value for --case-id}")
      shift 2
      ;;
    --timeout)
      timeout_sec="${2:?missing value for --timeout}"
      shift 2
      ;;
    --memory)
      memory_limit="${2:?missing value for --memory}"
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

cmd=(
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
if [[ -n "$memory_limit" ]]; then
  cmd+=(--memory-limit-mb "$memory_limit")
fi
cmd+=("${extra_filters[@]}")

echo "+ ${cmd[*]}"
(cd "$ROOT" && "${cmd[@]}")
