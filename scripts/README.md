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
- `prepare_opensource_function_manifest.py` - generate function-entry manifests.
- `run_opensource_benchmarks.sh` - run whole-binary or function-entry OSS manifests.
- `run_opensource_all_function_scan.py` - use BASICS `--scan-all-functions`.
- `run_opensource_low_memory_function_sweep.py` - one BASICS subprocess per function.
- `prepare_seeded_opensource_vulns.py` - build small seeded vulnerable probes.
- `run_seeded_opensource_vulns.sh` - run seeded detection/patch tests.
- `make_opensource_benchmark_table.py` - regenerate the OSS benchmark summary table.

## External Tool Benchmarks

- `setup_external_tools_server.sh` - install/setup external tools on a benchmark host.
- `prepare_external_benchmarks.py` - prepare manifests and binaries for external tools.
- `run_external_tool_benchmark.py` - run external tools over BASICS manifests.
- `benchmark.py` - convenience entry point for external benchmark runs.
- `test_external_tool_parsers.py` - parser regression tests.

## Maintenance

- `clean_generated_outputs.sh` - remove generated reports and root scratch files.
