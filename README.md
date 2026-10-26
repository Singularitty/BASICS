# BASICS

BASICS is a binary-analysis prototype for checking stack-memory safety
properties and patching common stack buffer overflows in ELF binaries. The code
is mostly Python, with small C patch stubs under
`src/vulnerability_identifier_removal/patches`.

## Setup

The installer supports Arch-based and Debian/Ubuntu-based distributions:

```bash
./install.sh
```

It installs the system packages with `pacman` or `apt-get`, installs Spot (from
the AUR on Arch, from the distribution or the LRDE apt repository on
Debian/Ubuntu), builds E9Patch under `.tools/e9patch`, sets up Python 3.11 with
`uv` under `.tools`, creates `.venv`, installs the Python requirements, and
compiles the patch stubs. It can be rerun safely. Use `--skip-system` if the
system packages are already installed and you do not want it to use `sudo`.

BASICS needs Python 3.11, since the pinned angr version is not meant for newer
releases. The installer takes care of this regardless of the system Python.

If Spot cannot be installed, BASICS reuses the automata cached in
`security_properties/`.

After it finishes, either use the wrapper:

```bash
./run_basics.sh --help
```

or activate the environment directly:

```bash
export PATH="$PWD/.tools/bin:$PATH"
source .venv/bin/activate
python src/main.py --help
```

### Manual Setup

On other distributions, install gcc, make, git, gdb, graphviz, patchelf, xxd,
zlib headers and, optionally, Spot, then run `./install.sh --skip-system`.

`run_basics.sh` can also create `.venv` from an existing Python 3.11 with
`PYTHON_BIN=python3.11 ./run_basics.sh --help`. Without E9Patch (`e9tool` on
`PATH`), it falls back to analysis-only mode.

## Run BASICS

Build the small C fixtures and run one binary:

```bash
./tests/build_c_cases.sh
./run_basics.sh tests/bin/unsafe_strcpy_argv
```

Useful variants:

```bash
./run_basics.sh --no-patching tests/bin/safe_strncpy
./run_basics.sh --cfg-mode fast --function-simulation static tests/bin/unsafe_sprintf
./run_basics.sh --no-patching --analysis-entry loader tests/bin/unsafe_strcpy_argv
```

Analysis starts at `main` unless `--analysis-entry loader` is used. Patch
validation writes reports under `reports/<binary>/`.

## Benchmark Results

Current detection results on the Juliet C/C++ CWE121 dataset

<!-- benchmark-table:start -->
| Cases | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | 
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3,524 | 900 (25.5%) | 145 (4.1%) | 1,617 (45.9%) | 862 (24.5%) | 86.1% | 51.1% | 64.1% | 71.4% | 

<!-- benchmark-table:end -->

## Cite BASICS

If you use BASICS in your research, please cite us:

```
@article{FERREIRINHA2027105165,
title = {BASICS: Binary Analysis and Stack Integrity Checker System for Buffer Overflow Mitigation},
journal = {Computers & Security},
volume = {172},
pages = {105165},
year = {2027},
issn = {0167-4048},
doi = {https://doi.org/10.1016/j.cose.2026.105165},
url = {https://www.sciencedirect.com/science/article/pii/S016740482600341X},
author = {Luís Ferreirinha and Ibéria Medeiros}
}
```

