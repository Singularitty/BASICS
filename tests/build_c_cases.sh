#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"
CASES_DIR="$TESTS_DIR/cases"
BIN_DIR="$TESTS_DIR/bin"
CC="${CC:-gcc}"

COMMON_FLAGS=(
    -O0
    -g
    -fno-omit-frame-pointer
    -fno-stack-protector
    -no-pie
    -z execstack
    -Wno-deprecated-declarations
    -Wno-stringop-overflow
    -Wno-array-bounds
)

mkdir -p "$BIN_DIR"

for source in "$CASES_DIR"/*.c; do
    name="$(basename "$source" .c)"
    output="$BIN_DIR/$name"
    echo "Building $output"
    "$CC" "${COMMON_FLAGS[@]}" "$source" -o "$output"
done

cat <<EOF

Built C test binaries in:
  $BIN_DIR

Example BASICS run:
  python src/main.py --cfg-mode fast --function-simulation static --no-patching tests/bin/unsafe_strcpy_argv
EOF
