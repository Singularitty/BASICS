# BASICS

BASICS is a binary-analysis prototype for checking stack-memory safety
properties and patching common stack buffer overflows in ELF binaries. The code
is mostly Python, with small C patch stubs under
`src/vulnerability_identifier_removal/patches`.

## Setup

Use Python 3.11. The pinned angr version in `requirements.txt` is not meant for
newer Python releases.

Choose one setup path.

### Arch Linux

On Arch, use the installer:

```bash
./install_arch.sh
```

The script uses `pacman`, sets up Python 3.11 through `pyenv` when needed,
installs Spot when available, builds E9Patch under `.tools/e9patch`, creates
`.venv`, installs the Python requirements, and compiles the patch stubs.

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

### Debian/Ubuntu or Manual Setup

There is no Debian/Ubuntu installer in this repo. Install the basic system
packages yourself:

```bash
sudo apt-get update
sudo apt-get install -y graphviz gcc gdb git make patchelf python3.11 python3.11-venv
```

Then let the wrapper create the local Python environment:

```bash
PYTHON_BIN=python3.11 ./run_basics.sh --help
```

`run_basics.sh` creates `.venv`, installs `requirements.txt`, adds `.tools/bin`
to `PATH`, and then forwards the remaining arguments to `src/main.py`.

For patching runs, install E9Patch separately and put `e9tool` on `PATH`.
Without it, the wrapper falls back to analysis-only mode. For LTL translation,
install Spot or `ltl2ba`; if neither is available, BASICS reuses the checked-in
automata cache.

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
| Dataset | Cases | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | 
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Juliet CWE-121 | 3,524 | 900 (25.5%) | 145 (4.1%) | 1,617 (45.9%) | 862 (24.5%) | 86.1% | 51.1% | 64.1% | 71.4% | 

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

