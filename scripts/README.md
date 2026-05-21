# BASICS Scripts

Scripts are grouped by workflow. Keep command names stable; many notes and
benchmark commands refer to these paths directly.

## Core BASICS Benchmarks

- `run_basics_benchmark.py` - manifest-driven BASICS runner.
- `calc_metrics.py` - confusion-matrix and patching metrics for runner CSVs.
- `run_compiled_stack_benchmarks.sh` - convenience wrapper for prepared SARD/Juliet binaries.
- `prepare_benchmark_binaries.py` - compile binaries referenced by a manifest.

Benchmark compile flags and standard runner settings are documented in
[`docs/benchmark_flags.md`](../docs/benchmark_flags.md).

## Stack Datasets

- `prepare_stack_datasets.py` - generate combined SARD/tests/Juliet stack manifest.
- `prepare_juliet_cwe121_isolated_manifest.py` - bad-only/good-only Juliet manifest.
- `prepare_juliet_cwe121_entry_manifest.py` - paper-style Juliet entry-function manifest.
- `prepare_juliet_cwe121_dynamic_manifest.py` - Juliet subset for dynamic tools.
- `juliet_cwe121_eval.py` - focused BASICS Juliet CWE-121 evaluator.

## Open-Source Project Benchmarks

- `setup_opensource_benchmarks.py` - clone/build supported OSS projects.
- `setup_linux_repo_binaries.py` - download/extract apt package binaries for
  repo-binary scans.
- `prepare_opensource_function_manifest.py` - generate function-entry manifests.
- `run_opensource_benchmarks.sh` - run whole-binary or function-entry OSS manifests.
- `run_opensource_all_function_scan.py` - use BASICS `--scan-all-functions`;
  supports `--workers` and aggregate summaries.
- `run_opensource_low_memory_function_sweep.py` - one BASICS subprocess per
  function; supports `--workers` and per-function memory/concolic bounds for
  large low-memory OSS sweeps.
- `prepare_seeded_opensource_vulns.py` - build small seeded vulnerable probes.
- `run_seeded_opensource_vulns.sh` - run seeded detection/patch tests.
- `make_opensource_benchmark_table.py` - regenerate the OSS benchmark summary table.

Large low-memory OSS scan:

```bash
scripts/setup_opensource_benchmarks.py --project all --keep-going --jobs 8 --max-binaries-per-project 25
scripts/prepare_opensource_function_manifest.py \
  --manifest Benchmarks/opensource/opensource_cases.json \
  --out Benchmarks/opensource/opensource_function_cases_many.json \
  --include-main --all-symbols
scripts/run_opensource_low_memory_function_sweep.py \
  --manifest Benchmarks/opensource/opensource_function_cases_many.json \
  --workers 8 --timeout-sec 240 --memory-limit-mb 2500 \
  --concolic-step-limit 100 --concolic-active-limit 16 --max-states 5000
```

Linux repository binary scan:

```bash
scripts/setup_linux_repo_binaries.py --package default --keep-going \
  --max-binaries-per-package 20 --max-binary-size-mb 25
scripts/run_opensource_all_function_scan.py \
  --manifest Benchmarks/linux_repos/linux_repo_binary_cases.json \
  --workers 4 --timeout-sec 600 --scan-memory-limit-mb 3000 \
  --concolic-step-limit 100
```

## External Tool Benchmarks

- `setup_external_tools_server.sh` - install/setup external tools on a benchmark host.
- `prepare_external_benchmarks.py` - prepare manifests and binaries for external tools.
- `run_external_tool_benchmark.py` - run external tools over BASICS manifests.
- `benchmark.py` - convenience entry point for external benchmark runs.
- `benchmark_parallel.py` - run multiple tool/dataset benchmark jobs concurrently; use
  `--case-workers` to also parallelize cases within each external-tool job.
- `run_tool_benchmark_suite.py` - focused SARD/Juliet external-tool scheduler
  that skips Arbiter/Valgrind/REX and writes `stats.txt`/`stats.json` beside
  every result CSV.
- `test_external_tool_parsers.py` - parser regression tests.

## Maintenance

- `clean_generated_outputs.sh` - remove generated reports and root scratch files.
