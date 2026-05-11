#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build and run BASICS on seeded vulnerable CPS-flavored binaries.

Usage:
  scripts/run_seeded_opensource_vulns.sh [options]

Options:
  --timeout SEC        Per-case timeout (default: 120)
  --limit N            Run at most N cases
  --no-patching        Disable patching; default is to let BASICS patch
  --cfg-mode MODE      auto, emulated, or fast (default: fast)
  --simulation MODE    auto, static, or angr (default: static)

Examples:
  scripts/run_seeded_opensource_vulns.sh
  scripts/run_seeded_opensource_vulns.sh --limit 1 --timeout 60
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="Benchmarks/opensource/seeded_vulns/seeded_vuln_cases.json"

timeout_sec=120
limit=""
patch_flag=""
cfg_mode="fast"
simulation="static"

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
    --no-patching)
      patch_flag="--no-patching"
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

(cd "$ROOT" && python3 scripts/prepare_seeded_opensource_vulns.py)

cmd=(
  python3 scripts/run_basics_benchmark.py
  --manifest "$MANIFEST"
  --dataset opensource/seeded_vulns
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

echo "+ ${cmd[*]}"
(cd "$ROOT" && "${cmd[@]}")
