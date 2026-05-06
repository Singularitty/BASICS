# Tests

Run the model-checker unit tests from the repository root:

```bash
python -m unittest discover -s tests
```

The current tests exercise the core `ModelChecker` with synthetic memory states and hand-built Buchi automata. They do not require angr, E9, Spot, or compiled binaries, but they do require the normal Python dependencies from `requirements.txt`, including `rustworkx` and `numpy`.

Covered behavior:

- accepting automaton transitions do not report violations,
- false automaton transitions report violations,
- stack-byte predicates can read `StackFrame` byte states,
- incorrect stack-byte predicates are reported as property violations.

## C Binary Fixtures

Build the C fixtures:

```bash
./tests/build_c_cases.sh
```

The binaries are written to `tests/bin`.

Fixtures:

- `safe_strncpy`: bounded copy; expected safe baseline.
- `unsafe_strcpy_argv`: `strcpy` overflow from argv into an 8-byte stack buffer.
- `unsafe_gets_stdin`: `gets` overflow from stdin.
- `unsafe_scanf_stdin`: `scanf("%s")` overflow from stdin.
- `unsafe_sprintf`: `sprintf` overflow into a stack buffer.
- `unsafe_strcat`: `strcat` overflow into a stack buffer.
- `loop_overflow`: direct indexed writes past a stack buffer in a loop.
- `off_by_one`: one-byte write past the end of a stack buffer.
- `user_function_overflow`: overflow happens inside a user-defined function.

Example BASICS runs:

```bash
python src/main.py --cfg-mode fast --function-simulation static --no-patching tests/bin/safe_strncpy
python src/main.py --cfg-mode fast --function-simulation static --no-patching tests/bin/unsafe_strcpy_argv
python src/main.py --cfg-mode fast --function-simulation auto tests/bin/unsafe_gets_stdin
```

The fixtures are compiled with `-O0`, frame pointers, no PIE, and no stack protector to keep stack frames and call sites deterministic for model-checker regression testing.
