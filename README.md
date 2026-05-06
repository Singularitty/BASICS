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

For patched-binary validation, BASICS can use a different function simulation mode than the original analysis. This is useful when original analysis uses static summaries for speed, but patched verification needs stricter modeling:

```bash
./run_basics.sh --function-simulation static --patched-function-simulation angr tests/bin/unsafe_sprintf
```

By default, analysis starts at `main`. To force the checker to start at the ELF loader entry point, use:

```bash
./run_basics.sh --no-patching --analysis-entry loader tests/bin/program_patched
```

For E9-patched validation, `--patched-analysis-entry loader` makes the patched recheck start in E9's added trampoline/mapping code instead of jumping straight to `main`. This is slower because angr must also reason about E9 startup code, mmap setup, and indirect loader control flow.

BASICS uses Python 3.11 because `angr==9.2.102` is not compatible with Python 3.14. If `pyenv` is installed, the wrapper uses `.python-version` and installs Python 3.11.9 automatically when needed. You can override the interpreter with:

```bash
PYTHON_BIN=/path/to/python3.11 ./run_basics.sh --help
```
