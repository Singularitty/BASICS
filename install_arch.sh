#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
TOOLS_DIR="${TOOLS_DIR:-$ROOT_DIR/.tools}"
E9PATCH_REPO="${E9PATCH_REPO:-https://github.com/GJDuck/e9patch.git}"
BASICS_PYTHON_VERSION="${BASICS_PYTHON_VERSION:-3.11.9}"

if ! command -v pacman >/dev/null 2>&1; then
    echo "This installer is intended for Arch Linux systems with pacman." >&2
    exit 1
fi

sudo pacman -Syu --needed --noconfirm \
    base-devel \
    cmake \
    git \
    graphviz \
    patchelf \
    python \
    python-pip \
    tar \
    wget

if ! command -v pyenv >/dev/null 2>&1; then
    if pacman -Si pyenv >/dev/null 2>&1; then
        sudo pacman -S --needed --noconfirm pyenv
    else
        echo "Arch package 'pyenv' was not found in configured repositories."
        echo "Install pyenv manually or set PYTHON_BIN to a Python 3.11 interpreter."
    fi
fi

if pacman -Si spot >/dev/null 2>&1; then
    sudo pacman -S --needed --noconfirm spot
else
    echo "Arch package 'spot' was not found in configured repositories."
    echo "Install Spot Python bindings manually, or run BASICS with --ltl-backend ltl2ba."
fi

if command -v rustup >/dev/null 2>&1; then
    if ! rustup toolchain list | grep -q '^stable'; then
        rustup toolchain install stable
    fi
    rustup default stable
elif ! command -v cargo >/dev/null 2>&1; then
    sudo pacman -S --needed --noconfirm rustup
    rustup toolchain install stable
    rustup default stable
else
    echo "Using existing Rust toolchain: $(cargo --version)"
fi

mkdir -p "$TOOLS_DIR/bin"

if ! command -v e9tool >/dev/null 2>&1; then
    echo "Installing E9Patch into $TOOLS_DIR/e9patch"
    if [ ! -d "$TOOLS_DIR/e9patch/.git" ]; then
        git clone "$E9PATCH_REPO" "$TOOLS_DIR/e9patch"
    else
        git -C "$TOOLS_DIR/e9patch" pull --ff-only
    fi
    make -C "$TOOLS_DIR/e9patch"
    find "$TOOLS_DIR/e9patch" -type f -perm -111 -name 'e9tool' -exec install -Dm755 {} "$TOOLS_DIR/bin/e9tool" \; -quit
fi

PYTHON_CMD="${PYTHON_BIN:-}"
if [ -z "$PYTHON_CMD" ]; then
    if command -v pyenv >/dev/null 2>&1; then
        if ! pyenv versions --bare | grep -qx "$BASICS_PYTHON_VERSION"; then
            pyenv install "$BASICS_PYTHON_VERSION"
        fi
        export PYENV_VERSION="$BASICS_PYTHON_VERSION"
        PYTHON_CMD="pyenv exec python"
    elif command -v python3.11 >/dev/null 2>&1; then
        PYTHON_CMD="python3.11"
    else
        cat >&2 <<EOF
Python 3.11 is required for angr 9.2.102.
Install pyenv or set PYTHON_BIN to a Python 3.11 interpreter.
EOF
        exit 1
    fi
fi

PYTHON_VERSION="$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [ "$PYTHON_VERSION" != "3.11" ]; then
    echo "Selected Python is $PYTHON_VERSION, but BASICS requires Python 3.11." >&2
    exit 1
fi

if [ -x "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON_VERSION="$("$VENV_DIR/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    if [ "$VENV_PYTHON_VERSION" != "3.11" ]; then
        echo "Recreating $VENV_DIR because it was built with Python $VENV_PYTHON_VERSION."
        rm -rf "$VENV_DIR"
    fi
fi

$PYTHON_CMD -m venv "$VENV_DIR"
if [ -f "$VENV_DIR/pyvenv.cfg" ]; then
    sed -i 's/include-system-site-packages = true/include-system-site-packages = false/' "$VENV_DIR/pyvenv.cfg"
fi
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip wheel setuptools
python -m pip install -r "$ROOT_DIR/requirements.txt"

if [ -x "$ROOT_DIR/src/vulnerability_identifier_removal/patches/compile_patches.sh" ]; then
    (cd "$ROOT_DIR/src/vulnerability_identifier_removal/patches" && ./compile_patches.sh)
fi

cat <<EOF
BASICS Arch installation complete.

Add the local tool directory to PATH before running BASICS:
  export PATH="$TOOLS_DIR/bin:\$PATH"

Activate the Python environment:
  source "$VENV_DIR/bin/activate"

Run:
  python "$ROOT_DIR/src/main.py" --help
EOF
