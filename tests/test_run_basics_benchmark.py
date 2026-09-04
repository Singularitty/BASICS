import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_basics_benchmark.py"
SPEC = importlib.util.spec_from_file_location("run_basics_benchmark", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_entry_function_is_accepted_as_analysis_entry():
    case = {"case_id": "case", "entry_function": "juliet_bad"}
    assert MODULE.case_analysis_entry(case) == "juliet_bad"
    assert MODULE.empty_result_row(case)["analysis_entry"] == "juliet_bad"


def test_analysis_entry_takes_precedence():
    case = {"analysis_entry": "explicit", "entry_function": "fallback"}
    assert MODULE.case_analysis_entry(case) == "explicit"


def test_report_parser_scores_bo_properties_but_not_underflow_only():
    bo = """Found security property violations:\n\nProperty: rip_integrity\n\n1 security property violations found.\n"""
    underflow = """Found security property violations:\n\nProperty: no_underflow_clib\n\n1 security property violations found.\n"""
    assert MODULE.parse_report(bo)["reported_vuln"] is True
    assert MODULE.parse_report(underflow)["reported_vuln"] is False


def test_stdout_parser_scores_property_reports_without_cwe_text():
    stdout = "Property: no_buffer_overflow__by_one_clib\n"
    parsed = MODULE.parse_stdout(stdout)
    assert parsed["reported_vuln"] is True
    assert parsed["stdout_properties"] == ["no_buffer_overflow__by_one_clib"]
