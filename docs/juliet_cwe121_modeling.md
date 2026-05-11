# Juliet CWE-121 Modeling Notes

This document records the conservative BASICS model extensions added for the
Juliet CWE-121 stack-buffer-overflow benchmarks. The goal is to improve coverage
without turning the checker into a broad taint or symbolic bounds analysis.

## Scope

Juliet CWE-121 contains several different source-level overflow shapes. They
are all stack-buffer-overflow examples, but they do not all compile to the same
binary pattern. BASICS models stack memory as an abstract byte-state frame, so
coverage depends on whether the binary exposes enough local stack structure to
map a write to a concrete stack object.

The new modeling targets two patterns that are precise enough to add without
expected false positives:

- indexed writes into stack arrays, used by CWE129-style cases;
- concrete `alloca`-backed memory copies, used by CWE131 `memcpy`/`memmove`
  cases.

String-copy alloca cases were tested but not kept because they require stronger
path and source-size reasoning than the current model provides.

## Indexed Stack Writes

### Pattern

The model now recognizes writes of the form:

```asm
mov    DWORD PTR [rbp + rax*4 - 0x40], ...
mov    BYTE PTR  [rbp + rcx - 0x20], ...
```

This corresponds to source patterns like:

```c
int dataBuffer[10] = { 0 };
dataBuffer[data] = 1;
```

where `data` may come from `fgets`, `fscanf`, sockets, or another external
source.

### Implementation

`src/model_checker/models/memory_transitions.py` adds
`IndexedWriteOperation`, which records:

- the RBP-relative displacement;
- the index register;
- the scale;
- the written data size.

`src/model_checker/state_space_constructor.py` tracks simple local/register
constants inside each basic block. If the index value is known and non-negative,
BASICS performs the exact write. If the index is unknown, BASICS conservatively
marks a bounded region from the base stack slot toward nearby critical stack
metadata.

This is intentionally not full data-flow tracking. It is a local binary pattern
model for indexed writes into stack storage.

## Concrete `alloca` Memory Copies

### Pattern

Juliet CWE131 examples often compile to an `alloca` allocation followed by an
explicit-length memory operation:

```c
data = (int *)ALLOCA(10);
memcpy(data, source, 10 * sizeof(int));
```

At the binary level this appears as a concrete stack-pointer adjustment followed
by a libc memory call:

```asm
sub    rsp, rax        ; computed alloca size
mov    edx, 0x28       ; memcpy length
mov    rdi, rsp        ; destination derived from alloca
call   memcpy@plt
```

The bad Juliet case allocates fewer bytes than the later memory copy writes. The
good case allocates enough space.

### Implementation

`src/model_checker/models/call_emulator.py` now tracks the concrete size of an
`rsp` allocation when the arithmetic can be evaluated locally. It handles the
common compiler sequence used for aligned `alloca`:

- immediate/register `mov`;
- `add`/`sub` with immediate operands;
- `div` with concrete `rax` and concrete divisor;
- three-operand `imul`;
- `sub rsp, <known register>`.

The alloca model is only used for explicit-length memory calls:

- `memcpy`;
- `memmove`;
- `memset`.

If both the allocation size and the write size are concrete, BASICS compares
them:

- if `write_size <= alloca_size`, the call is modeled as safe for this pattern;
- if `write_size > alloca_size`, BASICS marks the overflow as a full-frame
  stack write, allowing the existing LTL properties to detect modified critical
  bytes.

The model deliberately does not apply to `strcpy`/`strcat` alloca cases. Those
need reliable source-string size and path reasoning. A quick test showed FP risk
on `src_char_alloca_cpy_good`, so that broader model was not kept.

## CFGFast PLT Fallthrough

The Juliet binaries are commonly analyzed with `--cfg-mode fast`. In these
binaries, angr `CFGFast` can represent a basic block ending in a PLT call as
having only the PLT target successor. The post-call fallthrough block then has
no predecessor and BASICS never reaches later stack writes or libc calls.

`src/model_checker/state_space_constructor.py` adds a same-function fallthrough
edge when:

- a CFG node has a concrete block;
- `node.addr + node.size` maps to another CFG node;
- both block addresses belong to the same function.

The same-function check prevents the recovered edge from bleeding into adjacent
functions in memory.

## What Is Still Not Modeled

The current additions are intentionally narrow. BASICS still does not fully
model:

- general taint propagation from input sources;
- path-sensitive bounds checks such as `if (data >= 0 && data < 10)`;
- arbitrary pointer arithmetic through memory;
- source-string length reasoning for alloca-backed `strcpy`/`strcat`;
- ROP/JOP behavior, because the current byte-state model does not represent
  gadgets, indirect control-flow targets, or return-address chains.

These are limitations of the current abstraction, not bugs in the new models.
The new models only claim detection for binary patterns where stack-object size
and write extent are recoverable with local reasoning.

## Validation Commands

Experimental LTL properties are not loaded by default. They can be enabled for
research runs with:

```bash
./run_basics.sh --include-experimental-properties ...
```

Default benchmark runs should leave this flag disabled. The experimental
properties are useful for exploring additional behavioral signals, but they are
not calibrated as default detection properties and can increase false positives
on SARD.

Run the focused Juliet evaluator with:

```bash
.venv/bin/python scripts/juliet_cwe121_eval.py \
  --include 'CWE129_(fgets|fscanf)' \
  --limit 8 \
  --timeout 90 \
  --workers 1
```

Run the concrete alloca memory-copy slice with:

```bash
.venv/bin/python scripts/juliet_cwe121_eval.py \
  --include 'CWE131_mem(copy|move)' \
  --limit 8 \
  --timeout 90 \
  --workers 1
```

Run the broader direct-buffer/memory-copy slice with:

```bash
.venv/bin/python scripts/juliet_cwe121_eval.py \
  --include 'src_char_declare_(cpy|cat)|CWE806_char_declare|char_type_overrun_memcpy' \
  --timeout 90 \
  --workers 1 \
  --out reports/juliet_cwe121_results.csv
```

The evaluator runs each binary twice:

- the `_bad` symbol should be detected;
- the `_good` symbol should remain clean.

The key safety metric for these additions is the false-positive count on `_good`
functions. In the focused checks used during implementation:

- CWE131 `memmove` sample: `TP=3`, `FN=5`, `TN=8`, `FP=0`;
- CWE129 `fgets`/`fscanf` sample: `TP=7`, `FN=1`, `TN=3`, `FP=0`, with five
  good cases timing out.

The low recall in some slices is expected from the conservative scope. The model
prefers missing cases that require broader reasoning over flagging good Juliet
variants.

## SARD Regression Check

After making the experimental properties opt-in and tightening static libc
summaries for unknown heap/non-stack destinations, the SARD-only no-patching
benchmark was rerun with:

```bash
.venv/bin/python scripts/run_basics_benchmark.py \
  --dataset SARD \
  --no-patching \
  --cfg-mode fast \
  --function-simulation static \
  --patched-function-simulation static \
  --timeout-sec 90
```

Result for run `20260510T000438Z`:

- `TP=20`
- `TN=95`
- `FP=3`
- `FN=30`
- `FPR=3.1%`

This is back in line with the earlier SARD behavior (`FP=4` in
`20260509T184134Z`) while preserving one additional true positive in this
configuration.
