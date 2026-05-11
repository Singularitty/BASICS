# BASICS Paper vs Current Implementation Drift

Date checked: 2026-05-11.

This note documents places where the current BASICS implementation has diverged
from the implementation described in the paper draft, with emphasis on the way
angr is now used.

## Summary

The paper currently describes BASICS as primarily using angr concolic/symbolic
execution to enrich the Memory State Space (MSS) with C library call and loop
effects, using `CFGEmulated` because accuracy is preferred over speed, and using
concolic inputs for patch validation.

The current implementation is different. BASICS is now a hybrid static and
bounded-angr system:

- CFG recovery is configurable and defaults to `--cfg-mode auto`, not always
  `CFGEmulated`. In `auto`, binaries larger than 1 MiB use `CFGFast`; smaller
  binaries use `CFGEmulated`. `CFGEmulated` also falls back to `CFGFast` on
  certain angr failures.
- Supported unsafe C library calls are usually modeled by static stack-effect
  summaries first. CLI default is `--function-simulation auto`, while the
  benchmark wrapper defaults to `--function-simulation static` and
  `--patched-function-simulation static`.
- angr is still used, but in a bounded and cached form through
  `ConcolicExecutor`. It is no longer the only or even the default mechanism for
  many C library calls in benchmark runs.
- Loop and direct user-function summaries remain angr-based, but they are
  best-effort, bounded by step/state limits, and can be skipped when angr cannot
  reach the target, exits the loop, or exceeds configured limits.
- Patch validation now includes E9Patch manifest checks and GDB contract checks,
  not just "run original and patched binaries with crash-inducing concolic
  inputs".
- The supported patch set has expanded beyond the five functions and ten
  templates described in the paper.

## Main Drift Points

| Paper claim | Current implementation | Revision action |
| --- | --- | --- |
| BASICS is implemented with Python 3.10.12, angr 9.2.102, LTL2BA 1.3, and E9Patch. | The repo pins Python 3.11.9 via `.python-version` and wrapper scripts. `requirements.txt` uses `angr>=9.2.130,<10`. LTL translation uses Spot when available, falling back to `ltl2ba`. | Update implementation dependencies and backend wording. |
| The Binary Data Extractor chooses `CFGEmulated` because accuracy is preferred over speed. | `src/main.py` defaults to `--cfg-mode auto`. `src/binary_data_extractor/core.py` uses `CFGFast` for binaries larger than 1 MiB and falls back to `CFGFast` if `CFGEmulated` fails. Large-binary mode forces `CFGFast`. | Replace the absolute `CFGEmulated` claim with configurable CFG recovery and state the default heuristic. |
| The MSS integrates C function and loop effects emulated by angr symbolic execution. | C library calls are now modeled by static stack-effect summaries when possible. In `auto`, static summaries are tried before angr; in benchmark runs, static-only is the default. angr remains as fallback or for explicitly requested `--function-simulation angr`. | Describe BASICS as using hybrid stack-effect inference: static summaries for supported libc calls, bounded angr summaries otherwise. |
| For each C library call, angr symbolically executes from the user-function initial state to the call, steps the call, and compares stack bytes before/after. | That old path still exists as the angr fallback, but it is no longer always used. The current path first recovers arguments and buffer sizes statically and computes affected stack bytes directly. | Move the old algorithm from "the implementation" to "angr fallback path". |
| Concrete malicious inputs are extracted during concolic execution and used to validate patches. | For statically modeled stdin functions, BASICS records generated filler inputs, not necessarily solver-derived malicious inputs. The validator also uses a cyclic fallback when no input file exists. | Avoid claiming all validation inputs are concolic/crash-inducing. Say inputs are collected or synthesized, and patch contracts are checked. |
| Patch validation executes original and patched binaries to confirm the original crashes and the patch does not. | `src/vulnerability_identifier_removal/validator.py` uses GDB contract instrumentation around patch sites and checks guard behavior. It can report ptrace/GDB failures separately. | Update validation description to GDB-based patch contract validation. |
| Ten patch templates support five functions: `strcpy`, `scanf`, `sprintf`, `gets`, `strcat`. | `src/vulnerability_identifier_removal/patcher.py` currently supports templates for `strcpy`, `gets`, `scanf`, `fscanf`, `sscanf`, `strcat`, `sprintf`, `memcpy`, and `memmove`, with known-size and unknown-size variants. | Update template count/function list or explicitly distinguish paper-era and revision-era versions. |
| LTL formulas are converted with LTL2BA into Promela never-claims. | `src/security_property_converter/ltl_translator.py` now supports Spot Python bindings, Spot CLI (`ltl2tgba`), and `ltl2ba`; default is `auto`. | State Spot as preferred/current backend and `ltl2ba` as compatibility fallback. |
| The main scalability bottleneck is concolic execution of C calls and loops. | This is still true for loop/user-call summaries, but benchmarked libc handling can now avoid angr entirely via `--function-simulation static`. Timeouts now depend heavily on selected mode. | Evaluation must report the exact BASICS flags used. |
| BASICS analyzes one selected program entry. | Current code supports `--analysis-entry`, `--patched-analysis-entry`, `--scan-all-functions`, patch-aware CFG starts, loader-entry diagnostics, and large-binary mode. | Mention these as engineering extensions, or exclude from paper if not used in reported experiments. |

## Current angr Usage

angr is currently used in four distinct ways:

1. **Project loading and CFG recovery**
   - `BinaryDataExtractor` creates an `angr.Project` with `auto_load_libs=False`.
   - Several libc/simprocedure names are excluded so BASICS can model or ignore
     them itself.
   - CFG construction can be `emulated`, `fast`, or `auto`.

2. **Bounded reaching-state queries**
   - `ConcolicExecutor.reaching_state()` starts from the selected analysis entry,
     searches for a target address, prunes symbolic-IP states, caps active states
     with `--concolic-active-limit`, and stops at `--concolic-step-limit`.
   - Results are cached by `(project, start_addr, target_addr)`.

3. **Fallback C library call emulation**
   - `CallEmulator` first attempts static summaries for supported sinks.
   - If the mode is `auto` and static modeling fails, it falls back to the older
     angr stack-delta path.
   - If the mode is `static`, the angr fallback is skipped.

4. **Loop and user-function summaries**
   - Loop summaries use angr to reach the loop entry, step until an exit or
     iteration limit, and compare stack bytes.
   - Direct user-defined calls are summarized by comparing caller stack bytes
     before and after one call step.
   - These summaries are best-effort and skipped on reachability or execution
     failures.

## Benchmark Configuration Caveat

The benchmark wrapper `scripts/run_basics_benchmark.py` defaults to:

```text
--cfg-mode auto
--function-simulation static
--patched-function-simulation static
```

That means benchmark results produced by this wrapper are not measuring the
paper-era "angr concolic emulation for every C library call" configuration.
They measure the revised static-summary configuration unless those flags are
overridden.

For a paper revision, report the exact flags. For example:

```text
BASICS was run with CFG auto-selection and static libc stack-effect summaries
for benchmark throughput. angr remained responsible for binary loading, CFG
construction, and bounded summaries for loops/user-defined calls where needed.
```

## Suggested Paper Replacement Wording

Use wording along these lines in the implementation section:

> BASICS uses angr for binary loading, CFG recovery, and bounded symbolic
> execution queries. CFG recovery is configurable: the default auto mode uses
> `CFGEmulated` on small binaries and `CFGFast` on larger binaries or when
> emulated CFG construction fails. To avoid repeated symbolic execution for
> common C library calls, the current implementation first applies static
> stack-effect summaries for supported functions such as `strcpy`, `strcat`,
> `gets`, `scanf`, `fscanf`, `sscanf`, `sprintf`, `memcpy`, and `memmove`.
> When static recovery is insufficient and the selected mode permits it, BASICS
> falls back to bounded angr execution to compare stack bytes before and after
> the call. Loop and user-function summaries are also computed through bounded
> angr execution and may be skipped when the target cannot be reached within the
> configured limits.

For validation:

> Patch validation uses an E9Patch manifest and GDB-based contracts at patched
> sites to check that the vulnerable call is reached in the original binary and
> that the patched binary preserves the expected guard behavior. Inputs are
> collected during analysis when available and synthesized otherwise.

## Claims To Avoid Unless Reverted

Do not claim the current implementation:

- always uses `CFGEmulated`;
- uses concolic execution to model every supported C library call;
- always extracts crash-inducing inputs from concolic execution;
- validates patches only by observing process crashes;
- supports only five patchable functions and ten templates;
- uses LTL2BA as the sole LTL backend.

## Fair Description For the Revision

The defensible description is that BASICS evolved from a concolic-heavy
prototype into a hybrid binary-analysis tool. angr remains central, but its role
is now bounded and selective: project loading, CFG recovery, cached reachability,
and best-effort stack deltas for loops/user calls or fallback call modeling. The
fast path used in current benchmarks is static libc stack-effect modeling.
