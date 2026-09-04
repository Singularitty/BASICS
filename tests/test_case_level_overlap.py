import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "case_level_overlap.py"
SPEC = importlib.util.spec_from_file_location("case_level_overlap", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_overlap_categories():
    assert MODULE.category(True, True) == "Both"
    assert MODULE.category(True, False) == "BASICS only"
    assert MODULE.category(False, True) == "CWE_Checker only"
    assert MODULE.category(False, False) == "Neither"


def test_status_and_boolean_parsing():
    assert MODULE.completed({"status": "ok"})
    assert MODULE.completed({"execution_status": "completed"})
    assert not MODULE.completed({"status": "timeout"})
    assert MODULE.parse_bool("True") is True
    assert MODULE.parse_bool("false") is False
