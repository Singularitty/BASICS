# Benchmark Flags

This document records the compile and runner settings used for the BASICS,
SARD, Juliet CWE-121, and external-tool benchmark runs.

## Binary Build Flags

SARD and isolated Juliet benchmark binaries are compiled with:

```text
gcc -std=gnu99 -Wno-implicit-function-declaration -O0 -g \
  -gdwarf-4 \
  -fno-stack-protector \
  -fcf-protection=none \
  -fno-omit-frame-pointer \
  -march=x86-64 \
  -mtune=generic \
  -no-pie
```

Juliet isolated binaries additionally use:

```text
-I Benchmarks/C/testcasesupport
-DINCLUDEMAIN
-DOMITGOOD   # bad-only binary
-DOMITBAD    # good-only binary
Benchmarks/C/testcasesupport/io.c
Benchmarks/C/testcasesupport/std_thread.c
-lpthread -lm
```

## Rationale

- `-O0 -g -gdwarf-4`: keep binaries simple and debuggable while emitting
  debug info accepted by the Ghidra/BinAbsInspector version used in the
  benchmark environment.
- `-fno-stack-protector`: disable compiler-inserted stack canaries so benchmark
  behavior reflects the original vulnerable code.
- `-no-pie`: use stable non-PIE addresses for binary analysis.
- `-fcf-protection=none`: disable CET/IBT `endbr64` instructions, which vary by
  distribution and change the CFG shape.
- `-fno-omit-frame-pointer`: keep explicit frame pointers for stable stack-frame
  recovery.
- `-march=x86-64 -mtune=generic`: force baseline x86-64 code generation. Some
  cloud images default to `x86-64-v3` and emit AVX/AVX2 instructions plus
  different stack layouts, which changes BASICS results.
- `-Wno-implicit-function-declaration`: allow legacy benchmark snippets to build
  under newer GCC versions.

## BASICS Runner Settings

The standard compiled stack benchmark command is:

```text
python3 scripts/run_basics_benchmark.py \
  --manifest Benchmarks/stack_benchmark/stack_cases_combined.json \
  --timeout-sec 120 \
  --cfg-mode fast \
  --function-simulation static \
  --patched-function-simulation static \
  --no-patching \
  --dataset SARD
```

`scripts/run_compiled_stack_benchmarks.sh sard` expands to the command above.
Juliet uses the same runner settings with:

```text
--manifest Benchmarks/stack_benchmark/juliet_cwe121_isolated_cases.json
```

`scripts/benchmark_parallel.py` also defaults BASICS jobs to no patching, matching
`run_compiled_stack_benchmarks.sh`. Pass `--basics-patching` only for patching
experiments.

## External Tool Runner Settings

External tools analyze the precompiled binaries from the manifests. The standard
entry point is:

```text
python3 scripts/benchmark.py TOOL DATASET TIMEOUT
```

For the overnight recommended suite:

```text
python3 scripts/benchmark_parallel.py --suite recommended --jobs 4 --timeout 300
```

Before running benchmarks on a fresh or changed machine, regenerate manifests and
force-recompile binaries:

```text
python3 scripts/prepare_external_benchmarks.py --workers 16 --timeout-sec 120 --force
```

## Scoring Scope

The comparison is BO-only. BASICS benchmark parsing counts only buffer-overflow
CWEs and excludes underflow-only detections such as `CWE-124`. External-tool
parsers are filtered to the same BO scope where possible.
