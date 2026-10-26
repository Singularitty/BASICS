#!/usr/bin/env bash
# Install BASICS on Arch-based or Debian/Ubuntu-based Linux.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
TOOLS_DIR="${TOOLS_DIR:-$ROOT_DIR/.tools}"
BASICS_PYTHON_VERSION="${BASICS_PYTHON_VERSION:-3.11}"
E9PATCH_REPO="${E9PATCH_REPO:-https://github.com/GJDuck/e9patch.git}"
E9PATCH_REF="${E9PATCH_REF:-682ab1f7f0480aa45edf1fd94457e5ee2dd01043}"
LRDE_KEY_URL="https://www.lrde.epita.fr/repo/debian.gpg"
LRDE_REPO="deb [signed-by=/etc/apt/keyrings/lrde.gpg] http://www.lrde.epita.fr/repo/debian/ stable/"

usage() {
    cat <<EOF
Install BASICS and its tools on Arch- or Debian/Ubuntu-based systems.

Usage: ./install.sh [--skip-system] [--help]

  --skip-system   Do not install system packages (no sudo). Use this when
                  gcc, make, git, gdb, graphviz, patchelf, xxd and zlib
                  headers are already installed.

Everything else goes into the repo: uv and Python $BASICS_PYTHON_VERSION under
.tools/, E9Patch under .tools/e9patch, the Python environment in .venv.

Environment overrides: VENV_DIR, TOOLS_DIR, BASICS_PYTHON_VERSION,
E9PATCH_REPO, E9PATCH_REF.
EOF
}

skip_system=0
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-system) skip_system=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

step() { printf '\n==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

detect_family() {
    local ids=""
    if [ -r /etc/os-release ]; then
        # shellcheck source=/dev/null
        ids="$(. /etc/os-release && echo "${ID:-} ${ID_LIKE:-}")"
    fi
    case " $ids " in
        *" arch "*) echo arch ;;
        *" debian "*|*" ubuntu "*) echo debian ;;
        *)
            if command -v pacman >/dev/null 2>&1; then echo arch
            elif command -v apt-get >/dev/null 2>&1; then echo debian
            else echo unknown
            fi
            ;;
    esac
}

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------

install_system_arch() {
    $SUDO pacman -Syu --needed --noconfirm \
        base-devel curl discount gdb git graphviz patchelf tinyxxd zlib
}

install_system_debian() {
    $SUDO apt-get update
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        binutils build-essential ca-certificates curl gdb git gnupg graphviz \
        markdown patchelf xxd zlib1g-dev
}

# Spot provides ltl2tgba, which BASICS uses to translate its LTL properties.
# Without it BASICS falls back to the automata cached in security_properties/.
install_spot_arch() {
    if pacman -Qi spot >/dev/null 2>&1; then
        return 0
    fi
    local helper
    for helper in yay paru; do
        if command -v "$helper" >/dev/null 2>&1; then
            "$helper" -S --needed --noconfirm spot && return 0
            return 1
        fi
    done
    if [ "$(id -u)" -eq 0 ]; then
        warn "Spot is in the AUR and makepkg cannot run as root."
        return 1
    fi
    echo "Building Spot from the AUR (this takes a while)."
    rm -rf "$TOOLS_DIR/aur-spot"
    git clone --depth 1 https://aur.archlinux.org/spot.git "$TOOLS_DIR/aur-spot"
    (cd "$TOOLS_DIR/aur-spot" && makepkg -si --needed --noconfirm)
}

install_spot_debian() {
    if command -v ltl2tgba >/dev/null 2>&1; then
        return 0
    fi
    local added_repo=0
    if ! apt-cache policy spot 2>/dev/null | grep -q 'Candidate: [0-9]'; then
        echo "Adding the LRDE apt repository for Spot."
        $SUDO install -d -m 0755 /etc/apt/keyrings
        curl -fsSL "$LRDE_KEY_URL" | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/lrde.gpg
        echo "$LRDE_REPO" | $SUDO tee /etc/apt/sources.list.d/lrde.list >/dev/null
        $SUDO apt-get update
        added_repo=1
    fi
    if $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends spot; then
        return 0
    fi
    # LRDE builds against recent glibc, so older releases (e.g. Ubuntu 22.04)
    # cannot use it. Do not leave an unusable repository behind.
    if [ "$added_repo" -eq 1 ]; then
        $SUDO rm -f /etc/apt/sources.list.d/lrde.list /etc/apt/keyrings/lrde.gpg
        $SUDO apt-get update
    fi
    return 1
}

family="$(detect_family)"
mkdir -p "$TOOLS_DIR/bin"
export PATH="$TOOLS_DIR/bin:$PATH"

if [ "$skip_system" -eq 0 ]; then
    case "$family" in
        arch|debian)
            step "Installing system packages ($family)"
            "install_system_$family"
            step "Installing Spot"
            "install_spot_$family" || warn "Spot was not installed. BASICS will use the cached automata."
            ;;
        *)
            echo "Unsupported distribution. Install the packages listed in the README" >&2
            echo "yourself, then rerun with --skip-system." >&2
            exit 1
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# E9Patch
# ---------------------------------------------------------------------------

E9_DIR="$TOOLS_DIR/e9patch"
step "Building E9Patch ($E9PATCH_REF)"
if [ ! -d "$E9_DIR/.git" ]; then
    git clone "$E9PATCH_REPO" "$E9_DIR"
fi
e9_rebuild=0
if [ "$(git -C "$E9_DIR" rev-parse HEAD)" != "$(git -C "$E9_DIR" rev-parse "$E9PATCH_REF^{commit}" 2>/dev/null)" ]; then
    git -C "$E9_DIR" fetch --quiet origin
    if ! git -C "$E9_DIR" checkout --quiet "$E9PATCH_REF"; then
        echo "Could not check out E9Patch $E9PATCH_REF in $E9_DIR." >&2
        echo "If you changed files there, commit, stash or discard them and rerun." >&2
        exit 1
    fi
    e9_rebuild=1
fi
if [ "$e9_rebuild" -eq 1 ] || [ ! -x "$E9_DIR/e9tool" ] || [ ! -x "$E9_DIR/e9patch" ]; then
    # build.sh reports success even when make fails, so check the binaries.
    (cd "$E9_DIR" && ./build.sh)
    if [ ! -x "$E9_DIR/e9tool" ] || [ ! -x "$E9_DIR/e9patch" ]; then
        echo "E9Patch failed to build; see the compiler output above." >&2
        exit 1
    fi
fi
ln -sf "$E9_DIR/e9tool" "$TOOLS_DIR/bin/e9tool"
ln -sf "$E9_DIR/e9patch" "$TOOLS_DIR/bin/e9patch"
ln -sf "$E9_DIR/e9compile.sh" "$TOOLS_DIR/bin/e9compile"

# ---------------------------------------------------------------------------
# Python environment
# ---------------------------------------------------------------------------

step "Setting up Python $BASICS_PYTHON_VERSION with uv"
export UV_PYTHON_INSTALL_DIR="$TOOLS_DIR/python"
export UV_PYTHON_BIN_DIR="$TOOLS_DIR/bin"
if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh \
        | env UV_INSTALL_DIR="$TOOLS_DIR/bin" UV_NO_MODIFY_PATH=1 sh
fi
uv python install "$BASICS_PYTHON_VERSION"

if [ -x "$VENV_DIR/bin/python" ]; then
    venv_version="$("$VENV_DIR/bin/python" -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))')"
    if [ "$venv_version" != "$BASICS_PYTHON_VERSION" ]; then
        echo "Recreating $VENV_DIR (it uses Python $venv_version)."
        rm -rf "$VENV_DIR"
    fi
fi
if [ ! -x "$VENV_DIR/bin/python" ]; then
    uv venv --seed --python "$BASICS_PYTHON_VERSION" "$VENV_DIR"
fi
uv pip install --python "$VENV_DIR/bin/python" -r "$ROOT_DIR/requirements.lock"
# run_basics.sh reinstalls requirements when this stamp is older than requirements.lock.
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$VENV_DIR/.requirements.stamp"

# ---------------------------------------------------------------------------
# Patch stubs
# ---------------------------------------------------------------------------

step "Compiling patch stubs"
(cd "$ROOT_DIR/src/vulnerability_identifier_removal/patches" && ./compile_patches.sh)

ltl_status="Spot (ltl2tgba)"
if ! command -v ltl2tgba >/dev/null 2>&1; then
    ltl_status="not installed, using cached automata"
fi

cat <<EOF

BASICS is installed.
  Python:  $("$VENV_DIR/bin/python" -V) in $VENV_DIR
  E9Patch: $TOOLS_DIR/bin/e9tool
  LTL:     $ltl_status

Run it with:
  ./run_basics.sh --help
EOF
