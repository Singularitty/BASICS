# E9Patch Validation Evidence

This document describes how BASICS validates patched binaries produced through
E9Patch and why patched-binary validation is implemented as runtime pre/post
contract checking instead of a second whole-binary model-checking pass.

## Problem

BASICS originally tried to re-run the model checker on the patched binary.
That approach is unreliable for default E9Patch ELF output.

E9Patch does not necessarily rewrite the original instruction bytes in a way
that ordinary static tools see directly. In the default ELF mode, E9Patch adds
a loader to the output binary. During process startup, that loader maps the
patched pages and trampoline code into memory. As a result:

- `objdump` may still show the original instruction bytes at the patched site.
- angr may load the file-level view and miss the runtime page replacement.
- GDB breakpoints planted too early can be overwritten when the E9 loader maps
  patched pages.

This is why checking the patched binary with the same static CFG/model-checking
pipeline can produce a false negative: the patch is installed and active at
runtime, but the static analysis still observes the original call site.

## Validation Strategy

BASICS now separates validation into two evidence layers.

The first layer is patch-installation evidence. BASICS records a
`patch_manifest.json` for each patched binary. The manifest captures:

- the original and patched binary paths;
- the original angr address and E9 address of each sink;
- the predecessor instruction address used to recover pre-call state;
- the continuation address after the patched instruction;
- the selected patch payload;
- the inferred destination buffer size;
- the analysis entry address;
- the raw E9Tool output, including `num_patched`.

BASICS treats E9Tool's install count as mandatory evidence. If E9Tool reports
that fewer instructions were patched than BASICS requested, patching fails.

The second layer is bounded runtime behavioral evidence. BASICS validates the
patch over generated or user-provided inputs, grouped as:

- `malicious`: inputs expected to exercise the vulnerable behavior;
- `benign`: safe inputs expected to preserve original observable behavior;
- `boundary`: inputs at or near recovered destination-buffer limits.

Inputs can come from `reports/<binary>/concolic_inputs.txt`, from BASICS'
cyclic fallback, or from a JSON file passed with `--validation-inputs`.
Benign and boundary cases are executed on both the original and patched binary.
By default, BASICS requires the same exit code, the same stdout, and no new
patched-binary crash. Stderr is ignored unless
`--strict-stderr-validation` is enabled.

The third layer is local patch-site evidence. BASICS validates a patched site
with a GDB contract:

1. Start the patched binary under GDB with the same generated input.
2. Stop at the analysis entry, normally `main`, using a hardware breakpoint.
3. After this stop, install breakpoints around the patched site. This timing is
   important: by then E9's loader has already mapped the patched runtime pages.
4. At the predecessor instruction, recover the destination pointer and safe
   buffer size from the manifest and live registers.
5. Place a sentinel guard immediately after the safe destination region.
6. Continue through the patched instruction and stop at the continuation address.
7. Check whether the sentinel guard changed.

For the patched binary, the same input should reach the patched site without a
crash, with sane observable stack registers. If the patch manifest exposes
enough reliable local information, BASICS records stronger observations around
the destination object; otherwise guard behavior is marked `not_observable` or
`inconclusive`. This directly supports the bounded claim the patch is supposed
to enforce: the observed vulnerable execution no longer causes the patched
binary to crash or violate the local patch-site contract.

Each run writes a machine-readable report:

```text
reports/<binary>/patch_validation.json
```

The report separates vulnerability-remediation evidence from bounded
functional-preservation evidence and records inconclusive cases explicitly.
The console summary always includes:

```text
Patch remediation: PASS/FAIL/INCONCLUSIVE
Bounded functional preservation: PASS/FAIL/INCONCLUSIVE
Full functional equivalence: NOT CLAIMED
```

## Why Stop At `main` First?

The initial stop is not just a convenience. It is required for E9Patch's default
runtime loader mode.

If BASICS plants breakpoints at the patched site immediately after `starti`, GDB
sets those breakpoints before the E9 loader has finished remapping patched
pages. The loader can then replace the page containing the breakpoint, so GDB
never observes the expected stop. BASICS avoids this by first stopping at the
analysis entry with `hbreak`, then installing site-level breakpoints after the
runtime mappings are stable.

This also explains why earlier validation attempts reported:

```text
patched: FAIL no patch contract reached
```

The patched code may have been active, but the breakpoints were installed
against pages that were later replaced by the E9 loader.

## Contract Semantics

The current contract is stack-write containment. For each patched site, BASICS
checks that bytes after the inferred destination object remain unchanged after
the patched operation returns to the continuation address.

This gives the following interpretation:

- For `strcpy`, the source may be larger than the destination, but bytes beyond
  the destination bound must remain unchanged.
- For `strcat`, the final destination string must stay within the destination
  bound.
- For `memcpy` and `memmove`, the effective write must stay within the inferred
  destination bound.
- For formatted-input/output patches such as `scanf` and `sprintf`, the
  produced destination string must stay within the inferred bound.
- For `gets`, input read into the destination must stay within the inferred
  bound.

The validator does not require source code for the target program. It uses only:

- the binary;
- the E9Patch manifest generated during patching;
- the input that triggers the vulnerable behavior;
- live process state observed through GDB.

## Limits

This validation provides bounded evidence for each patched sink under the tested
inputs. It does not prove whole-program semantic equivalence. That is
intentional: whole-program equivalence for stripped binaries is not tractable in
general, and E9Patch's runtime loader makes ordinary static re-analysis of the
patched artifact especially fragile.

The claim supported by this validation is deliberately narrower:

> BASICS performs automated bounded patch validation over generated or
> provided inputs, combining malicious-input remediation checks, bounded
> benign/boundary regression checks, and GDB patch-site contracts when
> available.

Full functional equivalence is never claimed by the validator or the JSON
report.

## Relevant Implementation Points

- `src/vulnerability_identifier_removal/patcher.py` writes the manifest and
  verifies E9Tool's patch count.
- `src/vulnerability_identifier_removal/validator.py` implements the bounded
  input model, original-vs-patched regression checks, GDB patch-site contracts,
  and `patch_validation.json`.
- `src/main.py` runs the validator after patching and skips patched-binary model
  checking by default.

Useful CLI options:

```bash
./run_basics.sh --validation-inputs inputs.json tests/bin/unsafe_strcpy_argv
./run_basics.sh --no-gdb-validation tests/bin/unsafe_strcpy_argv
./run_basics.sh --validation-timeout 30 --strict-stderr-validation tests/bin/unsafe_strcpy_argv
```

## SARD Experiment

The first full SARD run with the structured validator is recorded in
[sard_patch_validation_experiment.md](/home/luisf/Work/Projects/BASICS/docs/sard_patch_validation_experiment.md).
The important outcome is that bounded validation is now discriminating:
remediation can pass while bounded functional preservation fails or remains
inconclusive. This is the intended scientific framing and should replace any
paper wording that equates patch validation with "patched binary did not crash."
