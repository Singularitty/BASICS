# BASICS Implementation Notes for Revision

This document records implementation changes made to address reviewer concerns about scalability, patch validation, E9-based patching, and ineffective concolic execution. It is written as engineering context that can later be translated into paper language.

## Problem Summary

The original implementation used angr concolic execution in a very expensive way. For each modeled C library call, BASICS created a new blank state at `main`, explored from the program entry to the target call instruction, stepped the call, compared the stack before and after, and then discarded the angr state. The same pattern was also used for loop emulation.

That design had two main problems:

1. It repeated path exploration from `main` for every function call and loop site.
2. It relied on angr function simulation for unsafe libc calls, which was slow and inconsistent across functions.

For larger binaries this caused heavy state explosion and made many analyses time out or fail before patch validation could run.

## Main Implementation Changes

### 1. Post-Patch Model Checking

`src/main.py` now has a reusable `analyze_binary(...)` function. The original binary and the E9-patched binary use the same analysis pipeline:

1. extract binary data,
2. build the state space,
3. model check security properties,
4. emit a report.

After patching, BASICS now model checks the patched binary by default. This directly addresses the old limitation where the patched binary was produced and crash-tested, but the formal checker was not run again.

New option:

```bash
python src/main.py --no-check-patched ./binary
```

This disables post-patch model checking when only patch generation is needed.

### LTL Translation Backend

`src/security_property_converter/ltl_translator.py` now supports Spot as the primary LTL-to-Buchi backend. Spot replaces the old default dependency on `ltl2ba`, which required downloading an old HTTP-hosted tool and parsing Promela never-claim output.

New option:

```bash
python src/main.py --ltl-backend spot ./binary
python src/main.py --ltl-backend auto ./binary
python src/main.py --ltl-backend ltl2ba ./binary
```

Modes:

- `spot`: translate formulas with Spot Python bindings and convert the resulting automaton directly into the BASICS `rustworkx` graph representation.
- `auto`: try Spot first and fall back to `ltl2ba`.
- `ltl2ba`: preserve the legacy Promela never-claim flow.

Spot-generated automata are saved as `.pickle` files for BASICS and `.hoa` files for debugging/reproducibility.

### 2. Larger Binary Controls

`src/main.py` and `src/binary_data_extractor/core.py` now expose CFG construction controls:

```bash
python src/main.py --cfg-mode auto ./binary
python src/main.py --cfg-mode fast ./binary
python src/main.py --cfg-mode emulated ./binary
```

Modes:

- `auto`: uses CFGEmulated for smaller binaries and CFGFast for binaries larger than 10 MiB.
- `fast`: uses angr `CFGFast`.
- `emulated`: uses angr `CFGEmulated`.

The state-space constructor also accepts a state budget:

```bash
python src/main.py --max-states 50000 ./binary
```

This gives the experimenter an explicit bound for large programs instead of allowing unbounded state expansion.

### 3. State Deduplication

`src/model_checker/models/state_space.py` now deduplicates memory states. Each state is keyed by:

- stack frame names,
- byte-state arrays,
- buffer maps,
- `rbp`,
- canary flags,
- current instruction address.

If an equivalent memory state is added again, the existing node is reused. This avoids repeated graph growth for equivalent stack configurations.

`src/model_checker/state_space_constructor.py` also tracks processed `(CFG node, memory state)` pairs. This prevents revisiting the same CFG location with the same abstract stack state.

### 4. E9 Patching Fixes

`src/vulnerability_identifier_removal/patcher.py` was changed to fix several patching limitations:

- E9 match expressions now use full instruction addresses instead of only the last four hex digits.
- All supported sinks are collected into one E9 invocation instead of returning after the first patch.
- The `CallEmulator` constructor argument order was fixed for patch argument recovery.
- E9 failures now raise an exception instead of being printed and ignored.

This makes patching more reliable on larger binaries where low address suffixes can collide.

### Angr Validation of E9-Patched Binaries

The old patched-binary validation could appear unchanged after E9 rewriting. This can happen for several reasons:

- the patched file is not actually different from the original,
- the wrong path is loaded after patching,
- the model checker searches for the same vulnerable call pattern even though E9 rewrote the call site into trampoline/instrumented code,
- angr builds a CFG for the rewritten binary where the original direct call site is no longer represented in the same way.

`src/binary_data_extractor/core.py` now canonicalizes binary paths with `realpath(abspath(...))` before creating an angr project, and computes a SHA-256 fingerprint for each loaded artifact.

`src/main.py` now prints, for both original and patched binaries:

- canonical path,
- file size,
- SHA-256,
- angr mapped base,
- min/max loaded addresses,
- entry point,
- section/segment count,
- CFG function count.

After patched analysis, BASICS compares original and patched hashes. If they are identical, validation reports that E9 may not have changed the output file. If they differ, the model checker is at least operating on a distinct patched artifact.

The patched validation path also disassembles each original vulnerable call-site address in the patched binary. This reports whether angr still sees the same unsafe call instruction or whether E9 rewrote that site into a different instruction such as a jump/trampoline.

`src/main.py` also compares executable loader segments between the original and patched binaries. This is the most useful way to detect E9's mapping/trampoline logic with angr. E9 can leave the original call-site bytes and decompiler output looking unchanged, while adding a new executable `LOAD` segment and moving the ELF entry point into that segment. The inspection reports:

- whether the entry point changed,
- executable segments present only in the patched binary,
- each candidate segment's virtual address range,
- file offset,
- file size and memory size,
- whether the patched entry point lies inside the candidate segment.

For example, an E9-patched binary may still show `call memcpy@plt` at the original function body, but angr/CLE can expose an added executable mapping such as `0x20e9e9000-...` with the patched entry point inside it. That is strong evidence that E9 installed loader/trampoline logic outside the original function body.

BASICS can now also start CFG construction and state-space construction from either `main` or the ELF loader entry:

```bash
python src/main.py --analysis-entry loader --no-patching ./program_patched
python src/main.py --patched-analysis-entry loader ./program
```

This makes it possible to run the standard model-checking pipeline from the E9 entry trampoline. The default remains `main`, including for patched validation, because the loader-entry path is substantially heavier: angr must reason about E9's startup/runtime mapping logic, indirect control flow, mmap behavior, and helper code before reaching the original application logic. Loader-entry checking is therefore best used as a patch-aware diagnostic mode, while `main`-entry checking remains the faster default for vulnerability discovery and routine patched rechecks.

For cases where Ghidra's decompiler view appears unchanged even though vulnerable behavior is gone, BASICS can now inspect patch artifacts without running the full checker:

```bash
python src/main.py ./original --inspect-patch-only ./original_patched
```

This prints original/patched fingerprints, angr loader metadata, added executable mappings, and the first raw byte regions that differ. This is useful because E9 can preserve a high-level decompiler view while changing bytes, adding sections, or redirecting control through instrumentation code that is not obvious in the decompiled function body.

This does not guarantee that the existing vulnerability detector will recognize the patched CFG shape. E9 patching can move behavior into trampolines or injected code, so a detector based on finding the original unsafe call instruction may need patch-aware validation logic.

### 5. Static Stack-Effect Modeling for Unsafe libc Calls

The old implementation used angr to execute unsafe libc calls such as `strcpy`, `gets`, `scanf`, `strcat`, and `sprintf`.

`src/model_checker/models/call_emulator.py` now has a faster static stack-effect model. When the destination buffer can be recovered from argument setup instructions, BASICS computes which stack bytes would be written without invoking angr.

Supported functions:

- `strcpy`
- `gets`
- `scanf`
- `strcat`
- `sprintf`

New option:

```bash
python src/main.py --function-simulation auto ./binary
python src/main.py --function-simulation static ./binary
python src/main.py --function-simulation angr ./binary
```

Modes:

- `auto`: try static stack-effect modeling first, then fall back to angr.
- `static`: only use static stack-effect modeling; skip angr fallback.
- `angr`: use the concolic execution path.

The intended default is `auto`, because it is much faster for supported unsafe libc calls while preserving angr fallback for incomplete argument recovery.

### Patched Binary Recheck Mode

A key validation issue was that patched binaries could still report the same `rip_integrity` violation even when runtime behavior had been fixed by E9. In practice this happened when both original and patched analyses used conservative static stack-effect summaries.

To address this, BASICS now supports a dedicated function-simulation mode for patched-binary rechecking:

```bash
python src/main.py --function-simulation static --patched-function-simulation angr ./binary
```

Implementation details:

- `--function-simulation` controls modeling for the original binary.
- `--patched-function-simulation` controls modeling only during the patched-binary recheck.
- default `--patched-function-simulation` is `angr`.

This separation keeps original analysis fast while making patched validation less prone to false "still vulnerable" reports caused by conservative static summaries.

### 6. Cached Concolic Executor

A new helper was added:

```text
src/model_checker/models/concolic_executor.py
```

This centralizes angr usage for repeated reachability queries.

The old pattern was:

```text
for each target:
    create blank_state(main)
    simgr.explore(find=target)
    use found state
    discard state
```

The new pattern is:

```text
get cached pre-target state
copy it
advance inside the block if needed
step the target operation
compare stack bytes
```

The executor caches states by:

```text
(project id, start address, target address)
```

This is useful because many stack summaries need the same prefix execution state.

New concolic bounds:

```bash
python src/main.py --concolic-step-limit 10000 --concolic-active-limit 64 ./binary
```

These options bound the amount of angr exploration and the number of active states kept during exploration.

### 7. Concolic Loop Summaries

`src/model_checker/state_space_constructor.py` now uses the cached `ConcolicExecutor` to reach loop headers. Once the loop-entry state is found, BASICS performs bounded loop execution and compares the stack before and after the loop.

The resulting byte differences are applied as a summary transition in the abstract memory state.

This keeps the paper’s existing bounded-model-checking semantics, but makes the implementation less wasteful because the expensive prefix to the loop header can be reused.

### 8. Concolic User-Function Call Summaries

The state-space constructor now attempts a lightweight stack summary for direct user-defined calls. When angr can execute through the call, BASICS compares the caller stack before and after the call and applies the observed stack-byte differences to the caller frame.

This does not replace explicit function-frame modeling. It supplements it by capturing caller-visible stack effects when concolic execution can produce them.

If the summary fails, the tool preserves the previous behavior and continues with explicit callee-frame modeling.

## How to Present This in the Paper

The implementation can be described as a hybrid stack-effect summarization strategy:

1. **Static summaries for modeled unsafe libc calls.**  
   For supported functions with recoverable stack-buffer arguments, BASICS directly computes the affected stack-byte interval.

2. **Cached concolic summaries for loops and functions.**  
   When static modeling is insufficient or when loop/user-function effects are needed, BASICS uses angr to compute a bounded stack delta. Reaching states are cached so multiple summaries do not repeat the same prefix exploration.

3. **Fallback and boundedness.**  
   Concolic summaries are bounded by step and active-state limits. If a summary cannot be computed, BASICS falls back to existing abstract interpretation/model-construction behavior.

Suggested wording:

```text
To reduce dependence on costly whole-program symbolic exploration, BASICS now separates stack-effect inference into two phases. First, calls to modeled unsafe C library functions are summarized statically from recovered calling-convention arguments and stack-buffer metadata. Second, for loops and user-defined functions whose effects cannot be determined syntactically, BASICS invokes a bounded concolic executor to compute a stack delta between the pre- and post-boundary states. Reaching states are cached by target address, avoiding repeated exploration from the program entry for every call site or loop header.
```

## Limitations to State Clearly

These changes improve scalability but do not make the analysis complete.

- Static libc summaries depend on successful argument recovery.
- Concolic loop summaries remain bounded by `--max-iterations`.
- Cached concolic summaries are path-sensitive to the first reachable state found for a target.
- User-defined function summaries are best-effort and can fail when angr cannot reach or step through the call.
- `CFGFast` improves scalability but may be less precise than `CFGEmulated` for indirect-control-flow-heavy binaries.

These limitations should be explicitly described as bounded analysis tradeoffs rather than hidden implementation details.

## Arch Installation Script

An Arch Linux installer was added:

```bash
./install_arch.sh
```

It installs system dependencies, installs Spot when the Arch package is available, builds E9Patch, creates a Python virtual environment, installs `requirements.txt`, and compiles the patch payloads.

The installer places locally built tools under:

```text
.tools/bin
```

Users should add that directory to `PATH` before running BASICS:

```bash
export PATH="$PWD/.tools/bin:$PATH"
source .venv/bin/activate
python src/main.py --help
```
