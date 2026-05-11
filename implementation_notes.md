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

---

## Second Revision: Static Modeling Accuracy and Patch Coverage

These changes improve the accuracy of the static call emulator and extend patch generation to more vulnerability patterns. The SARD benchmark (151 cases) went from TP=20, TN=97, FP=3, FN=31 (baseline) to TP=41, TN=96, FP=2, FN=9, with 100% of detected true positives both patched and validated via GDB.

### 9. Heap Buffer Size Tracking Through Stack Pointer Variables

The static call emulator (`src/model_checker/models/call_emulator.py`) now tracks the size of heap-allocated buffers through local stack pointer variables. This enables detection of vulnerabilities where `malloc` is followed by a clib write to a different, smaller stack buffer.

**Mechanism.** `__determine_local_pointer_assignments` now maintains two extra maps:

- `local_malloc_size_map`: maps rbp-relative slot offset → known heap buffer size for the pointer stored at that slot.
- `register_malloc_sizes`: maps register → the heap buffer size it currently holds a pointer to.

When a `call malloc` is seen, the constant in `rdi` (from `__track_alloca_constants`) is recorded as the allocation size in `rax`. When the return value is stored to a stack slot (`mov [rbp-N], rax`), the size is committed to `local_malloc_size_map[N]`. When that slot is later reloaded into a register (`mov reg, [rbp-N]`), the size is reinstated in `register_malloc_sizes[reg]`.

`__buffer_size_for_register` now falls back to `register_malloc_sizes` when a register is not in `buffer_map`, so write-size computation for functions like `strcpy` can use the source buffer's heap size.

**Memset interaction.** When `call memset` is seen, BASICS checks whether `rdi` carries a `register_malloc_source_slots` entry pointing to a stack slot in `local_malloc_size_map`. If so, `local_malloc_size_map[slot]` is updated to the memset byte count. This correctly reflects the effective string length after a memset-then-null-terminate pattern.

**Effect on SARD.** Nine malloc+strcpy cases (sard_0113–0131, odd-numbered) that were previously FN became TP. Cases with a safe memset (49 bytes into a 50-byte dest) remained TN.

### 10. Pointer Tracking Correctness: Non-rbp Load Clearing and Indirect Dereference

The previous implementation of `__determine_local_pointer_assignments` left stale entries in `register_points_to_stack` after non-rbp memory loads (e.g., `mov rax, [rax]`). This created circular entries in `local_pointer_map` for double-pointer patterns like:

```c
char *data;
char **dataPtr1 = &data;
data = malloc(100);
data = *dataPtr1;      // mov rax, [rbp-8]; mov rax, [rax]  ← stale rax persisted
mov [rbp-offset], rax  // circular: local_pointer_map[offset] = MemoryAddress(rbp, -offset)
```

The circular entry made downstream analysis treat the heap pointer as a stack address, causing false positives.

**Fix: clearing on untracked loads.** In the `mov reg, [mem]` handler, when the memory source is neither rbp-relative nor an indirect dereference through a known pointer, all tracking for the destination register is cleared:

```python
else:
    register_points_to_stack.pop(dst_reg, None)
    register_malloc_sizes.pop(dst_reg, None)
    register_malloc_source_slots.pop(dst_reg, None)
```

**Fix: indirect dereference tracking.** When the memory source is `[reg]` (simple dereference, no index or displacement) and `reg` is in `register_points_to_stack` pointing to an rbp slot, BASICS now looks up `local_malloc_size_map` for that slot and carries the heap buffer size forward without creating a circular stack pointer:

```python
elif (
    isinstance(src_mem, MemoryAddress)
    and src_mem.index_register is None
    and src_mem.displacement is None
    and canonical_register(src_mem.base_register) in register_points_to_stack
):
    base = canonical_register(src_mem.base_register)
    pointed_mem = register_points_to_stack[base]
    register_points_to_stack.pop(dst_reg, None)   # result is heap, not stack
    if isinstance(pointed_mem, MemoryAddress) and canonical_register(...) == "rbp":
        deref_slot = abs(pointed_mem.displacement or 0)
        if deref_slot in self.local_malloc_size_map:
            register_malloc_sizes[dst_reg] = self.local_malloc_size_map[deref_slot]
            register_malloc_source_slots[dst_reg] = deref_slot
```

**Fix: reg-to-reg clearing.** The `mov dst, src` (reg-to-reg) handler now clears `dst` tracking when `src` is not tracked, rather than silently leaving stale tracking values:

```python
if src_reg in register_points_to_stack:
    register_points_to_stack[dst_reg] = register_points_to_stack[src_reg]
else:
    register_points_to_stack.pop(dst_reg, None)
# same for register_malloc_sizes and register_malloc_source_slots
```

**Effect on SARD.** Three false positives caused by circular pointer confusion (sard_0107, sard_0108, sard_0134) became TN. The double-pointer TP case sard_0133 now correctly identifies `strcpy` as the vulnerable sink instead of `memset`.

### 11. fscanf and sscanf Patch Support

The patcher (`src/vulnerability_identifier_removal/patcher.py`) previously listed `scanf` but not `fscanf` or `sscanf`. Both functions use `rdx` as their first output argument (third parameter), unlike `scanf` which uses `rsi`.

Two entries were added to `PATCH_DETAILS`:

```python
"fscanf": {"args": ["rdi", "rsi", "rdx"], "patch_file": "fscanf_patch",
           "no_size": "fscanf_unknown_size_patch", "dest_reg": "rdx"},
"sscanf": {"args": ["rdi", "rsi", "rdx"], "patch_file": "sscanf_patch",
           "no_size": "sscanf_unknown_size_patch", "dest_reg": "rdx"},
```

Four new patch payloads were added and compiled with e9compile under `src/vulnerability_identifier_removal/patches/`:

- `fscanf_patch.c` / `fscanf_unknown_size_patch.c`: replace the `fscanf` call with `fgets(rdx, size, rdi)`, bounding the read to the known or dynamically computed destination buffer size.
- `sscanf_patch.c` / `sscanf_unknown_size_patch.c`: replace the `sscanf` call with `strncpy(rdx, rdi, size-1)` followed by a null terminator, bounding the copy to the destination buffer size.

The unknown-size variants use the same rbp-based runtime size computation as the existing `gets_unknown_size_patch` and `strcpy_unknown_size_patch`.

**Effect on SARD.** Five fscanf/sscanf cases (sard_0005, 0006, 0007, 0009, 0052) that were detected but unpatched are now patched and GDB-validated.

### 12. Identifier Coverage: no_stack_underwrite and no_buffer_overflow__by_one_clib

The vulnerability identifier (`src/vulnerability_identifier_removal/identifier.py`) previously handled only `rip_integrity`, `rbp_integrity`, `no_suspect_overflows`, `no_suspect_underflows`, `no_off_by_one_underflows_clib`, and `no_gets_usage` as triggers for sink-finding and patch generation. Two additional properties are now included:

- `no_stack_underwrite`: violations of this property occur when a clib function writes below a buffer's allocated stack region. The counterexample trace ends at the responsible `call` instruction (typically `strcpy`). Adding this property to the match case allows BASICS to identify and patch the responsible function.
- `no_buffer_overflow__by_one_clib`: violations of this property occur when a clib write exceeds the buffer allocated for the destination. Adding it means BASICS can patch cases that violate this specific property without also violating `rip_integrity` (e.g., when the stack frame is large enough that the overflow does not reach the saved return address).

The match statement in `Identifier.find_vulnerability` was extended:

```python
case "rip_integrity" | "rbp_integrity" | "no_suspect_overflows" | ... \
     | "no_stack_underwrite" | "no_buffer_overflow__by_one_clib":
```

**Effect on SARD.** Six previously unpatched TPs (sard_0133, 0135, 0140, 0142, 0144, 0146) now produce patches and pass GDB validation. For underwrite cases, the patcher uses the unknown-size variant because the write destination is typically a pointer arithmetic result rather than a directly stack-allocated buffer.

### Updated Benchmark Results (SARD, 151 cases)

| Metric | Baseline | After revision 1 (paper) | After revision 2 |
|---|---|---|---|
| TP | 20 | 36 | 41 |
| TN | 97 | 95 | 96 |
| FP | 3 | 3 | 2 |
| FN | 31 | 17 | 9 |
| Precision | 0.87 | 0.92 | 0.95 |
| Recall | 0.39 | 0.68 | 0.82 |
| F1 | 0.54 | 0.78 | 0.88 |
| TPs patched | — | — | 41/41 (100%) |
| Patches validated | — | — | 41/41 (100%) |

Remaining FPs (sard_0047, sard_0051) are pre-existing cases involving safe sprintf and sscanf patterns that require format-string width analysis beyond the current static model. Remaining FNs involve indirect pointer chains with more than two levels of indirection, loop-based writes, or multi-destination scanf calls not yet handled by the argument recovery logic.

### 13. Structured Bounded Patch Validation

The old patch validator effectively treated "patched binary did not crash" as
the main success criterion. It has been replaced with a structured bounded
validator that writes `reports/<binary>/patch_validation.json` and separates:

- malicious-input remediation evidence;
- benign/boundary regression evidence;
- GDB patch-site observations;
- failures;
- inconclusive cases.

The validator supports generated fallback inputs and optional JSON input files
via `--validation-inputs`. It records SHA-256 hashes and previews for inputs
and process outputs, not full large payloads. CLI controls were added for
`--validation-timeout`, `--no-gdb-validation`, `--no-regression-validation`,
and `--strict-stderr-validation`.

Important framing: the validator explicitly records
`full_functional_equivalence: false`. The supported claim is bounded automated
patch validation over generated or provided inputs.

### SARD Result With Structured Validation and Patch-Payload Fixes

Command:

```bash
scripts/run_compiled_stack_benchmarks.sh sard --patching --timeout 180 \
  --validation-timeout 10 --cfg-mode fast --simulation static \
  --no-gdb-validation
```

Results were written to:

```text
Benchmarks/stack_benchmark/results/20260511T194553.822566Z/results.csv
Benchmarks/stack_benchmark/results/20260511T194553.822566Z/results.json
```

Aggregate detection over 151 SARD cases:

- TP=38, TN=94, FP=6, FN=13
- accuracy=87.4%, precision=86.4%, recall=74.5%, specificity=94.0%
- F1=0.8000, MCC=0.7130

Patching/validation:

- patched=46
- validation not run=105
- fully passed bounded validation=10
- remediation passed with preservation inconclusive=13
- inconclusive=23
- bounded validation failed=0

The patch-payload pass fixed the failures surfaced by the first structured
validation run:

- E9Patch clean-ABI payloads now preserve return values through `&rax`.
- `gets` replacement strips newlines to match the removed libc call.
- `scanf`/`fscanf`/`sscanf` replacements handle simple `%s` and integer
  conversions, including field widths.
- `sprintf` replacement forces a terminating NUL after bounded formatting.
- malloc-backed destinations are skipped instead of being patched with
  stack-relative unknown-size payloads.
- input-patching for `scanf`/`gets` is capped when a later same-function stack
  copy would copy the input into a smaller adjacent destination.
- generated regression inputs avoid treating nondeterministic original behavior
  or unsafe original crashes as functional-preservation failures.

The no-GDB aggregate has no bounded-validation failures. Inconclusive cases are
still reported explicitly and should not be described as full validation
passes.

See `docs/sard_patch_validation_experiment.md` for the detailed SARD
experiment note.
