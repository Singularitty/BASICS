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

## Tests

The unit tests are small enough to run locally:

```bash
python -m unittest discover -s tests
```

If fixture binaries need to be rebuilt:

```bash
./tests/build_c_cases.sh
```

## Reproduce Benchmarks

The reproducibility wrapper records every command it runs under
`Benchmarks/reproducibility/<run-id>/commands.log`.

Show the full command sequence without running it:

```bash
python3 benchmarks/run_basics_repro.py --suite all --phase all --dry-run
```

Run a small stack-benchmark smoke test:

```bash
python3 benchmarks/run_basics_repro.py --suite stack --phase all --limit 5
```

Run the prepared SARD and Juliet stack manifests directly:

```bash
scripts/run_compiled_stack_benchmarks.sh all --jobs auto --timeout 180
```

For the focused Juliet OOM/error reruns:

```bash
scripts/run_juliet_oom_benchmarks.sh repro --prepare --jobs 1
scripts/run_juliet_oom_benchmarks.sh direct-repro --timeout 1800
```

The OSS and Linux-package suites need network access and an Ubuntu-like host.
They prepare binaries and manifests under `Benchmarks/` and write result CSV,
JSON, and stats files next to each run.

Generated benchmark corpora, scan reports, virtualenvs, downloaded tools, and
result directories are intentionally left out of git.
