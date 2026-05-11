#!/usr/bin/env bash
# Compile Juliet CWE-121 (and optionally CWE-124) individual test-case binaries.
#
# Runs "make individuals" in each testcase sub-directory, which produces a
# separate .out binary for every _bad / _goodB2G / _goodG2B / _good1 source
# file.  These binaries are what run_basics_benchmark.py and
# juliet_cwe121_eval.py expect.
#
# Usage:
#   ./scripts/compile_juliet.sh [OPTIONS]
#
# Options:
#   -j N        Parallel make jobs per subdirectory (default: 4)
#   -p N        Subdirectories compiled in parallel (default: 1; angr eats RAM)
#   --cwe PAT   Only compile dirs whose name matches PAT (e.g. CWE121, CWE124)
#   --clean     Run "make clean" before "make individuals"
#   --dry-run   Print what would run without executing it
#   -h          Show this help
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TESTCASES_DIR="$ROOT_DIR/Benchmarks/C/testcases"

MAKE_JOBS=4
SUBDIR_PARALLEL=1
CWE_PATTERN="CWE"
DO_CLEAN=0
DRY_RUN=0

usage() {
    sed -n '/^# Usage/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -j) MAKE_JOBS="$2"; shift 2 ;;
        -p) SUBDIR_PARALLEL="$2"; shift 2 ;;
        --cwe) CWE_PATTERN="$2"; shift 2 ;;
        --clean) DO_CLEAN=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ ! -d "$TESTCASES_DIR" ]]; then
    echo "ERROR: testcases directory not found: $TESTCASES_DIR" >&2
    exit 1
fi

# Collect all subdirectories that have a Makefile and whose path contains the CWE pattern.
mapfile -t SUBDIRS < <(
    find "$TESTCASES_DIR" -name Makefile \
        | while read -r mf; do
            dir="$(dirname "$mf")"
            if [[ "$dir" == *"$CWE_PATTERN"* ]]; then
                echo "$dir"
            fi
          done \
        | sort
)

if [[ ${#SUBDIRS[@]} -eq 0 ]]; then
    echo "No Makefile-bearing subdirectories found matching '$CWE_PATTERN' under $TESTCASES_DIR" >&2
    exit 1
fi

echo "Found ${#SUBDIRS[@]} subdirectories to compile."
echo "  make jobs per dir : $MAKE_JOBS"
echo "  parallel dirs      : $SUBDIR_PARALLEL"
echo "  clean before build : $DO_CLEAN"
echo ""

compile_subdir() {
    local dir="$1"
    local label
    label="$(basename "$(dirname "$dir")")/$(basename "$dir")"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        [[ "$DO_CLEAN" -eq 1 ]] && echo "[dry-run] make -C $dir clean"
        echo "[dry-run] make -C $dir -j$MAKE_JOBS individuals"
        return 0
    fi

    local log
    log="$(mktemp /tmp/juliet_compile_XXXXXX.log)"

    if [[ "$DO_CLEAN" -eq 1 ]]; then
        make -C "$dir" clean >>"$log" 2>&1 || true
    fi

    local start
    start=$(date +%s)
    if make -C "$dir" -j"$MAKE_JOBS" individuals >>"$log" 2>&1; then
        local elapsed=$(( $(date +%s) - start ))
        local n_out
        n_out=$(find "$dir" -maxdepth 1 -name "*.out" | wc -l)
        printf "  [OK]  %-60s  %3ds  %d binaries\n" "$label" "$elapsed" "$n_out"
    else
        local elapsed=$(( $(date +%s) - start ))
        printf "  [ERR] %-60s  %3ds  (see %s)\n" "$label" "$elapsed" "$log" >&2
        # Keep log on failure so the user can inspect it.
        return 1
    fi
    rm -f "$log"
}

export -f compile_subdir
export MAKE_JOBS DO_CLEAN DRY_RUN

FAILED=0

if command -v parallel >/dev/null 2>&1 && [[ "$SUBDIR_PARALLEL" -gt 1 ]]; then
    # GNU parallel: one job = one subdirectory.
    printf '%s\n' "${SUBDIRS[@]}" \
        | parallel -j"$SUBDIR_PARALLEL" compile_subdir {} \
        || FAILED=$?
else
    if [[ "$SUBDIR_PARALLEL" -gt 1 ]]; then
        echo "Note: GNU parallel not found; compiling directories sequentially." >&2
    fi
    for dir in "${SUBDIRS[@]}"; do
        compile_subdir "$dir" || FAILED=$(( FAILED + 1 ))
    done
fi

echo ""
if [[ "$FAILED" -gt 0 ]]; then
    echo "DONE — $FAILED subdirector$([ "$FAILED" -eq 1 ] && echo y || echo ies) failed to compile."
    exit 1
else
    total_out=$(find "$TESTCASES_DIR" -name "*.out" | wc -l)
    echo "DONE — all subdirectories compiled successfully."
    echo "Total .out binaries under testcases/: $total_out"
fi
