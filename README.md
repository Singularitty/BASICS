# BASICS: Binary Analysis and Stack Integrity Checker System
Model Checking tool to verify LTL properties in stack memory of binary programs

# Requirements

## Recomended
- PyPy is necessary to obtain better performance, we recommend setting a virtualenv with pyenv, using the PyPy Interpreter

## Required Software
In order for the tool to run you must install the following programs:  
- Graphviz
- Rust Compiler
- E9Patch
- Spot with Python bindings

## Python Packages
- angr
- angr-utils
- pwntools
- rustworkx
- lark
- numpy

# Running

Use the wrapper script to create/use the project virtual environment and run BASICS:

```bash
./run_basics.sh --help
./run_basics.sh tests/bin/unsafe_strcpy_argv
./run_basics.sh --function-simulation static --patched-function-simulation angr tests/bin/unsafe_sprintf
```

The wrapper uses `.venv`, adds `.tools/bin` to `PATH`, installs `requirements.txt` when needed, and forwards all arguments to `src/main.py`.

By default, analysis starts at `main`. To force the checker to start at the ELF loader entry point, use:

```bash
./run_basics.sh --no-patching --analysis-entry loader tests/bin/program_patched
```

For E9-patched validation, BASICS writes `reports/<binary>/patch_validation.json` with bounded malicious-input remediation checks, benign/boundary regression checks, and optional GDB patch-site contracts. BASICS explicitly does not claim full functional equivalence. The rationale and paper-facing validation claim are documented in [docs/e9patch_validation.md](/home/luisf/Work/Projects/BASICS/docs/e9patch_validation.md).

Juliet CWE-121 benchmark coverage and the conservative stack models for indexed writes and concrete `alloca` memory copies are documented in [docs/juliet_cwe121_modeling.md](/home/luisf/Work/Projects/BASICS/docs/juliet_cwe121_modeling.md).

The current SARD bounded patch-validation experiment is documented in [docs/sard_patch_validation_experiment.md](/home/luisf/Work/Projects/BASICS/docs/sard_patch_validation_experiment.md).

Experimental LTL properties are disabled by default. Enable them explicitly with `--include-experimental-properties` when running exploratory analyses.

BASICS uses Python 3.11 because `angr==9.2.102` is not compatible with Python 3.14. If `pyenv` is installed, the wrapper uses `.python-version` and installs Python 3.11.9 automatically when needed. You can override the interpreter with:

```bash
PYTHON_BIN=/path/to/python3.11 ./run_basics.sh --help
```
