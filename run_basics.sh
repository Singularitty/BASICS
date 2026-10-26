#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
BASICS_PYTHON_VERSION="${BASICS_PYTHON_VERSION:-3.11.9}"
PYTHON_BIN="${PYTHON_BIN:-}"
STAMP_FILE="$VENV_DIR/.requirements.stamp"
REQUIREMENTS_FILE="$ROOT_DIR/requirements.lock"

export PATH="$ROOT_DIR/.tools/bin:$PATH"
if [ -d "$HOME/Repos/e9patch" ]; then
    export PATH="$HOME/Repos/e9patch:$HOME/Repos/e9patch/bin:$HOME/Repos/e9patch/build:$PATH"
fi

select_python() {
    if [ -n "$PYTHON_BIN" ]; then
        printf '%s\n' "$PYTHON_BIN"
        return
    fi

    if command -v pyenv >/dev/null 2>&1; then
        if ! pyenv versions --bare | grep -qx "$BASICS_PYTHON_VERSION"; then
            pyenv install "$BASICS_PYTHON_VERSION"
        fi
        printf '%s\n' "pyenv exec python"
        return
    fi

    if command -v python3.11 >/dev/null 2>&1; then
        printf '%s\n' "python3.11"
        return
    fi

    cat >&2 <<EOF
Current BASICS dependency stack requires Python 3.11.

Install pyenv and rerun this script, or provide a Python 3.11 interpreter:
  BASICS_PYTHON_VERSION=$BASICS_PYTHON_VERSION ./run_basics.sh --help
  PYTHON_BIN=/path/to/python3.11 ./run_basics.sh --help
EOF
    exit 1
}

if [ -x "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON_VERSION="$("$VENV_DIR/bin/python" -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')"
    if [ "$VENV_PYTHON_VERSION" != "3.11" ]; then
        echo "Recreating $VENV_DIR because it was built with Python $VENV_PYTHON_VERSION."
        rm -rf "$VENV_DIR"
    fi
fi

# Only look for an interpreter when the venv has to be created, so a venv made
# by install.sh (with a uv-managed Python) works without pyenv or python3.11.
if [ ! -d "$VENV_DIR" ]; then
    PYTHON_CMD="$(select_python)"
    if [ "$PYTHON_CMD" = "pyenv exec python" ]; then
        export PYENV_VERSION="$BASICS_PYTHON_VERSION"
    fi

    PYTHON_VERSION="$($PYTHON_CMD -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')"
    if [ "$PYTHON_VERSION" != "3.11" ]; then
        cat >&2 <<EOF
Selected Python is $PYTHON_VERSION, but BASICS requires Python 3.11.

Run ./install.sh, or set PYTHON_BIN to a Python 3.11 interpreter.
EOF
        exit 1
    fi

    $PYTHON_CMD -m venv "$VENV_DIR"
fi

if [ -f "$VENV_DIR/pyvenv.cfg" ]; then
    sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' "$VENV_DIR/pyvenv.cfg"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

if [ ! -f "$STAMP_FILE" ] || [ "$REQUIREMENTS_FILE" -nt "$STAMP_FILE" ]; then
    python -m pip install --upgrade -r "$REQUIREMENTS_FILE"
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$STAMP_FILE"
fi

# Spot translates the LTL properties. ltl2ba is only used when explicitly
# requested with BASICS_LTL_BACKEND=ltl2ba.
LTL_BACKEND_RUNTIME="${BASICS_LTL_BACKEND:-spot}"
EXTRA_ARGS=()
if [ "$LTL_BACKEND_RUNTIME" = "spot" ] && ! python -c "import spot" >/dev/null 2>&1 && ! command -v ltl2tgba >/dev/null 2>&1; then
    if ls "$ROOT_DIR"/security_properties/buchi_automata/*.pickle >/dev/null 2>&1; then
        echo "Spot not found. Reusing cached Buchi automata pickles (built with Spot)."
        EXTRA_ARGS+=(--no-recompilation-ltl)
    else
        cat >&2 <<EOF
Spot is required to translate the LTL properties.
Install it, for example with ./install.sh.
EOF
        exit 1
    fi
fi

if ! command -v e9tool >/dev/null 2>&1; then
    HAVE_NO_PATCH_FLAG=0
    for arg in "$@"; do
        if [ "$arg" = "--no-patching" ]; then
            HAVE_NO_PATCH_FLAG=1
            break
        fi
    done
    if [ "$HAVE_NO_PATCH_FLAG" -eq 0 ]; then
        echo "e9tool not found; running in analysis-only mode (--no-patching)."
        EXTRA_ARGS+=(--no-patching)
    fi
fi

PYVEX_LIB="$VENV_DIR/lib/python3.11/site-packages/pyvex/lib"
if [ -d "$PYVEX_LIB" ]; then
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$PYVEX_LIB"
fi

exec python "$ROOT_DIR/src/main.py" --ltl-backend "$LTL_BACKEND_RUNTIME" "${EXTRA_ARGS[@]}" "$@"
