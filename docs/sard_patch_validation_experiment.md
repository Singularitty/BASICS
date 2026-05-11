# SARD Bounded Patch-Validation Experiment

Date: 2026-05-11

This note records the SARD run after replacing the old crash/no-crash validator
with bounded automated patch validation and improving the E9 patch payloads.
The result should be read as bounded validation evidence, not as proof of full
functional equivalence.

## Command

The full SARD run used the already prepared binaries under
`Benchmarks/stack_benchmark/generated_bins/SARD`:

```bash
scripts/run_compiled_stack_benchmarks.sh \
  sard \
  --patching \
  --timeout 180 \
  --validation-timeout 10 \
  --cfg-mode fast \
  --simulation static \
  --no-gdb-validation
```

This aggregate disables GDB validation to isolate patch payload behavior and
program-level bounded regression checks. GDB contract validation is still
supported by `src/vulnerability_identifier_removal/validator.py`, but ordinary
breakpoints on E9-rewritten call sites can remain inconclusive because E9 adds
loader/trampoline mappings. Per-case BASICS timeouts were enforced by the
benchmark harness.

## Output Artifacts

Primary results:

```text
Benchmarks/stack_benchmark/results/20260511T194553.822566Z/results.csv
Benchmarks/stack_benchmark/results/20260511T194553.822566Z/results.json
```

Each patched binary also wrote a structured validation report:

```text
reports/<binary>/patch_validation.json
```

The validator reports:

- vulnerability-remediation verdict;
- bounded functional-preservation verdict;
- per-input original and patched process outcomes;
- per-input regression comparisons;
- GDB patch-site observations where observable;
- explicit inconclusive/failure states;
- `full_functional_equivalence: false`.

## Aggregate Result

SARD rows: 151, all completed without harness errors.

Detection:

| Metric | Value |
| --- | ---: |
| TP | 38 |
| TN | 94 |
| FP | 6 |
| FN | 13 |
| Accuracy | 87.4% |
| Precision | 86.4% |
| Recall | 74.5% |
| Specificity | 94.0% |
| F1 | 0.8000 |
| MCC | 0.7130 |

Patching and validation:

| Category | Count |
| --- | ---: |
| Patched binaries | 46 |
| Validation not run | 105 |
| Fully passed bounded validation | 10 |
| Remediation passed, preservation inconclusive | 13 |
| Inconclusive | 23 |
| Failed bounded validation | 0 |

Patch-validation claim counts from the JSON reports:

| Remediation | Functional Preservation | Count |
| --- | --- | ---: |
| PASS | PASS | 10 |
| PASS | INCONCLUSIVE | 13 |
| INCONCLUSIVE | PASS | 20 |
| INCONCLUSIVE | INCONCLUSIVE | 3 |

Per-case verdict counts:

| Case Kind | Verdict | Count |
| --- | --- | ---: |
| malicious | pass | 23 |
| malicious | inconclusive | 23 |
| benign | pass | 31 |
| benign | inconclusive | 15 |
| boundary | pass | 31 |
| boundary | inconclusive | 15 |

The most common inconclusive reasons were:

| Reason | Count |
| --- | ---: |
| regression validation disabled or inconclusive | 30 |
| original run is not a safe benign/boundary baseline | 24 |
| original run did not crash or reach the vulnerable site | 23 |
| `sprintf` output preservation not observable on stdout | 4 |
| original behavior is not deterministic on this input | 2 |

## Interpretation

The new validator is intentionally stricter than the previous validator. It
does not count "patched binary did not crash" as sufficient evidence for patch
success.

The patch-payload improvement pass fixed the failures exposed by the first
structured run:

- patch payloads now preserve libc return values by writing through E9Patch's
  `&rax` clean-ABI argument;
- `gets` replacement now strips the newline, matching `gets` behavior on
  benign inputs;
- `scanf`, `fscanf`, and `sscanf` replacements parse simple `%s`/integer
  formats and respect field widths;
- `sprintf` replacement forces a terminating NUL after E9Patch's local
  `snprintf` implementation, whose truncation behavior otherwise left
  unterminated buffers;
- malloc-backed destinations are no longer patched with stack-size payloads;
- generated `sprintf` boundary inputs reserve space for simple format overhead
  so preservation checks do not intentionally force truncation;
- benign/boundary cases whose original execution crashes, times out, or is
  nondeterministic are marked inconclusive instead of being treated as safe
  preservation baselines.

The remaining inconclusive cases are not counted as passes. They mostly occur
when generated malicious input does not make the original binary crash or when
the original benign/boundary execution is not a stable baseline, for example
because the program prints uninitialized stack data.

The GDB layer can observe original call-site breakpoints. For E9-patched
binaries, patched-site breakpoints are often inconclusive because E9 runtime
mapping can make stale original addresses unobservable to ordinary GDB
breakpoints. The JSON reports preserve this as inconclusive GDB evidence rather
than silently passing it.

## Paper-Facing Statement

A defensible statement after this change is:

> BASICS performs automated bounded patch validation over generated or provided
> malicious, benign, and boundary inputs. Validation separately reports
> vulnerability-remediation evidence, bounded functional-preservation evidence,
> GDB patch-site observations where available, failures, and inconclusive cases.
> BASICS does not claim full functional equivalence.

Do not claim that all SARD patches are fully validated. In this run, 10 patched
cases passed both remediation and bounded preservation checks, 13 patched cases
had remediation evidence with inconclusive preservation, and 23 patched cases
remained inconclusive. No patched case failed bounded validation in the
no-GDB aggregate.
