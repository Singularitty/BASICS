#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Remove generated BASICS outputs from the working tree.

Default cleanup removes ad-hoc report directories and root-level scratch files.
It preserves cloned/open-source benchmark trees and benchmark result CSV/JSON.

Usage:
  scripts/clean_generated_outputs.sh [options]

Options:
  --dry-run             Print what would be removed
  --benchmarks          Also remove generated benchmark outputs under Benchmarks
  --opensource-builds   Also remove Benchmarks/opensource/src cloned/build trees

Examples:
  scripts/clean_generated_outputs.sh --dry-run
  scripts/clean_generated_outputs.sh
  scripts/clean_generated_outputs.sh --benchmarks
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dry_run=0
clean_benchmarks=0
clean_opensource=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run=1
      shift
      ;;
    --benchmarks)
      clean_benchmarks=1
      shift
      ;;
    --opensource-builds)
      clean_opensource=1
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

remove_path() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    return
  fi
  if git ls-files -- "$path" | grep -q .; then
    printf 'skip tracked path %s\n' "$path"
    return
  fi
  if [[ "$dry_run" -eq 1 ]]; then
    printf 'would remove %s\n' "$path"
  else
    rm -rf "$path"
  fi
}

cd "$ROOT"

for path in \
  basics_*.csv \
  *_scan_report.txt \
  file.txt; do
  for match in $path; do
    [[ "$match" == "$path" && ! -e "$match" ]] && continue
    remove_path "$match"
  done
done

if [[ -d reports ]]; then
  while IFS= read -r path; do
    remove_path "$path"
  done < <(find reports -mindepth 1 -maxdepth 1)
fi

if [[ "$clean_benchmarks" -eq 1 ]]; then
  remove_path Benchmarks/stack_benchmark/results
  remove_path Benchmarks/stack_benchmark/external_results
  remove_path Benchmarks/opensource/scan_results
  remove_path Benchmarks/opensource/seeded_vulns/bins
fi

if [[ "$clean_opensource" -eq 1 ]]; then
  remove_path Benchmarks/opensource/src
fi
