"""
Opt-in tracing of library-call emulation outcomes.

Set BASICS_EMULATION_TRACE to a directory to append one JSON line per
emulated call (one file per process). Tracing is disabled otherwise and
has no effect on analysis results.
"""
import json
import os

import src.global_vars as global_vars

_TRACE_DIR = os.environ.get("BASICS_EMULATION_TRACE")
_trace_file = None


def enabled():
    return _TRACE_DIR is not None


def record(**fields):
    global _trace_file
    if _TRACE_DIR is None:
        return
    if _trace_file is None:
        os.makedirs(_TRACE_DIR, exist_ok=True)
        _trace_file = open(os.path.join(_TRACE_DIR, f"{os.getpid()}.jsonl"), "a")
    fields["binary"] = global_vars.BINARY_NAME
    _trace_file.write(json.dumps(fields, default=str) + "\n")
    _trace_file.flush()
