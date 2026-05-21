# BASICS Reproducible Benchmark Bundle

This directory contains committed inputs for reproducing the BASICS benchmark
runs without committing generated binaries or result CSVs.

Generated data is still written under the existing `Benchmarks/` tree:

- stack benchmark manifests/results: `Benchmarks/stack_benchmark/`
- open-source clones/manifests/results: `Benchmarks/opensource/`
- Linux package binaries/manifests/results: `Benchmarks/linux_repos/`
- reproducibility logs: `Benchmarks/reproducibility/<run-id>/`

## Files

- `oss_projects.json`: selected open-source projects, repository URLs, and
  reproducible runner defaults.
- `linux_packages.json`: Ubuntu package groups used for Linux binary sweeps.
- `run_basics_repro.py`: wrapper that prepares manifests and runs BASICS with
  stable flags.

## Examples

Dry-run all commands:

```bash
python3 benchmarks/run_basics_repro.py --suite all --phase all --dry-run
```

Prepare and run only SARD/Juliet BASICS benchmarks:

```bash
python3 benchmarks/run_basics_repro.py --suite stack --phase all --workers 8
```

Prepare real open-source project binaries and run function-entry BASICS:

```bash
python3 benchmarks/run_basics_repro.py --suite oss --phase all --workers 8 --build-jobs 8
```

Prepare Ubuntu package binaries and run all-function BASICS scans:

```bash
python3 benchmarks/run_basics_repro.py --suite linux --phase all --workers 4
```

For a smoke test, add `--limit N`. The limit is passed to run phases only; the
prepare phase still writes complete manifests for the selected projects or
packages.

## Notes

The OSS and Linux suites require network access during preparation. Linux
package preparation requires `apt-get` and `dpkg-deb` on an Ubuntu-like host.
Package versions are resolved from the host's configured apt repositories and
recorded in the generated `Benchmarks/linux_repos/linux_repo_binary_cases.json`.

The runner records an environment snapshot, copied input manifests, and
`commands.log` for each run id. Use those files with the result CSV/JSON paths
printed by the underlying scripts when reporting benchmark results.
