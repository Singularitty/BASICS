#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$HOME/Benchmarks/basics_external_bench}"
TOOLS_DIR="$ROOT/tools"
mkdir -p "$TOOLS_DIR"

have() {
  command -v "$1" >/dev/null 2>&1
}

info() {
  printf '[setup] %s\n' "$*"
}

warn() {
  printf '[setup] warning: %s\n' "$*" >&2
}

info "workspace: $ROOT"

if have docker; then
  info "docker: $(docker --version)"
else
  warn "docker is not installed; BinAbsInspector/cwe_checker/valgrind containers will not run"
fi

if have valgrind; then
  info "valgrind: $(valgrind --version)"
elif have docker; then
  info "building Docker fallback image basics-valgrind:latest"
  cat >"$TOOLS_DIR/valgrind.Dockerfile" <<'EOF'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends valgrind libc6-dbg ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENTRYPOINT ["valgrind"]
EOF
  docker build -t basics-valgrind:latest -f "$TOOLS_DIR/valgrind.Dockerfile" "$TOOLS_DIR"
else
  warn "valgrind missing and no Docker fallback available"
fi

if have cwe_checker; then
  info "cwe_checker: $(cwe_checker --version 2>&1 | head -n 1)"
elif have docker; then
  if docker image inspect ghcr.io/fkie-cad/cwe_checker:latest >/dev/null 2>&1; then
    info "cwe_checker Docker image already present"
  else
    info "pulling ghcr.io/fkie-cad/cwe_checker:latest"
    docker pull ghcr.io/fkie-cad/cwe_checker:latest
  fi
else
  warn "cwe_checker missing and no Docker fallback available"
fi

if have docker; then
  if docker image inspect bai:latest >/dev/null 2>&1; then
    info "BinAbsInspector Docker image bai:latest is present"
  else
    warn "BinAbsInspector Docker image bai:latest is missing; build it from ~/src/BinAbsInspector if needed"
  fi
fi

SOURCE_VENV="${SOURCE_VENV:-$TOOLS_DIR/source-venv}"
if [[ ! -x "$SOURCE_VENV/bin/python" ]]; then
  info "creating source-tool virtualenv at $SOURCE_VENV"
  python3 -m venv "$SOURCE_VENV"
fi
if [[ -x "$SOURCE_VENV/bin/flawfinder" ]]; then
  info "flawfinder Python package is installed"
else
  info "installing flawfinder into $SOURCE_VENV"
  "$SOURCE_VENV/bin/python" -m pip install --upgrade pip wheel
  "$SOURCE_VENV/bin/python" -m pip install flawfinder
fi

CODEQL_DIR="${CODEQL_DIR:-$TOOLS_DIR/codeql}"
if have codeql; then
  info "codeql: $(codeql version --format=terse 2>/dev/null | head -n 1)"
elif [[ -x "$CODEQL_DIR/codeql" ]]; then
  info "codeql bundle: $("$CODEQL_DIR/codeql" version --format=terse 2>/dev/null | head -n 1)"
elif [[ "${INSTALL_CODEQL:-0}" == "1" ]]; then
  info "installing CodeQL bundle into $TOOLS_DIR (large download)"
  archive="$TOOLS_DIR/codeql-bundle-linux64.tar.gz"
  curl -L https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz -o "$archive"
  tar -xzf "$archive" -C "$TOOLS_DIR"
  "$CODEQL_DIR/codeql" version --format=terse 2>/dev/null | head -n 1 || true
else
  warn "codeql missing; set INSTALL_CODEQL=1 and rerun setup to install the CodeQL bundle"
fi

REX_VENV="${REX_VENV:-$TOOLS_DIR/rex-venv}"
if [[ ! -x "$REX_VENV/bin/python" ]]; then
  info "creating REX/angr virtualenv at $REX_VENV"
  python3 -m venv "$REX_VENV"
fi
if "$REX_VENV/bin/python" - <<'PY' >/dev/null 2>&1
import angr, rex
PY
then
  info "REX/angr Python packages are installed"
else
  info "installing angr and Shellphish REX into $REX_VENV"
  "$REX_VENV/bin/python" -m pip install --upgrade pip wheel
  "$REX_VENV/bin/python" -m pip install angr
  if ! "$REX_VENV/bin/python" -m pip install git+https://github.com/shellphish/rex.git; then
    warn "Shellphish REX did not install cleanly on this Python; angr remains installed"
  fi
fi

ARBITER_ROOT="${ARBITER_ROOT:-$TOOLS_DIR/arbiter}"
ARBITER_VENV="${ARBITER_VENV:-$TOOLS_DIR/arbiter-venv}"
if [[ "${INSTALL_ARBITER:-0}" == "1" ]]; then
  if [[ -d "$ARBITER_ROOT/.git" ]]; then
    info "Arbiter repository is present at $ARBITER_ROOT"
  else
    info "cloning Arbiter into $ARBITER_ROOT"
    git clone https://github.com/jkrshnmenon/arbiter.git "$ARBITER_ROOT"
  fi
  if [[ ! -x "$ARBITER_VENV/bin/python" ]]; then
    info "creating Arbiter virtualenv at $ARBITER_VENV"
    python3 -m venv "$ARBITER_VENV"
  fi
  if "$ARBITER_VENV/bin/python" - <<'PY' >/dev/null 2>&1
import arbiter, angr
PY
  then
    info "Arbiter Python package is installed"
  else
    info "installing Arbiter into $ARBITER_VENV"
    "$ARBITER_VENV/bin/python" -m pip install --upgrade pip wheel
    "$ARBITER_VENV/bin/python" -m pip install -e "$ARBITER_ROOT"
    "$ARBITER_VENV/bin/python" -m pip install 'protobuf<4' 'capstone<6' 'pycparser<3'
  fi
else
  warn "Arbiter is optional and template-driven; set INSTALL_ARBITER=1 to install it, then set ARBITER_TEMPLATE to a BO-specific VD"
fi

info "tool summary"
python3 "$ROOT/scripts/run_external_tool_benchmark.py" --list-tools || true
