import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.vulnerability_identifier_removal.validator as validator_module
from src.vulnerability_identifier_removal.validator import (
    GdbContractResult,
    RegressionResult,
    RunResult,
    SinkInfo,
    ValidationInputCase,
    Validator,
)


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self._old_reports_dir = validator_module.REPORTS_DIR
        self.tmp = tempfile.TemporaryDirectory()
        validator_module.REPORTS_DIR = self.tmp.name

    def tearDown(self):
        validator_module.REPORTS_DIR = self._old_reports_dir
        self.tmp.cleanup()

    def _validator(self, **kwargs):
        return Validator(
            "/bin/true",
            patched_binary_path="/bin/true",
            enable_gdb=False,
            timeout=2,
            **kwargs,
        )

    def test_parses_validation_json_input_file(self):
        path = os.path.join(self.tmp.name, "inputs.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "default_channel": "argv",
                    "cases": [
                        {"name": "benign_short", "kind": "benign", "input": "hello"},
                        {
                            "name": "boundary_stdin",
                            "kind": "boundary",
                            "channel": "stdin",
                            "input": "AAAAAAAA",
                        },
                    ],
                },
                f,
            )

        cases = self._validator(validation_inputs=path).load_input_cases()

        self.assertEqual([case.name for case in cases], ["benign_short", "boundary_stdin"])
        self.assertEqual(cases[0].channel, "argv")
        self.assertEqual(cases[1].channel, "stdin")
        self.assertEqual(cases[1].kind, "boundary")

    def test_fallback_inputs_include_malicious_benign_and_boundary(self):
        cases = self._validator().load_input_cases()
        kinds = {case.kind for case in cases}

        self.assertIn("malicious", kinds)
        self.assertIn("benign", kinds)
        self.assertIn("boundary", kinds)
        self.assertTrue(any(case.source == "cyclic_fallback" for case in cases))

    def test_legacy_constructor_positional_arguments_still_work(self):
        manifest = os.path.join(self.tmp.name, "manifest.json")
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump({"patches": []}, f)

        validator = Validator("/bin/true", [0x401000], manifest)

        self.assertEqual(validator.patched_binary_path, "/bin/true_patched")
        self.assertEqual(validator.manifest_path, manifest)
        self.assertEqual(validator.sinks[0].address, 0x401000)

    def test_regression_comparison_detects_stdout_mismatch(self):
        validator = self._validator()
        original = RunResult(exit_code=0, stdout=b"same\n", stderr=b"")
        patched = RunResult(exit_code=0, stdout=b"different\n", stderr=b"")

        regression = validator.compare_regression(original, patched)

        self.assertEqual(regression.verdict, "fail")
        self.assertFalse(regression.stdout_match)

    def test_regression_is_inconclusive_without_safe_original_baseline(self):
        validator = self._validator()
        original = RunResult(exit_code=-11, crashed=True)
        patched = RunResult(exit_code=0)

        regression = validator.compare_regression(original, patched)

        self.assertEqual(regression.verdict, "inconclusive")
        self.assertIn("not a safe benign", regression.notes[0])

    def test_regression_comparison_passes_matching_exit_and_stdout(self):
        validator = self._validator()
        original = RunResult(exit_code=0, stdout=b"same\n", stderr=b"ignored original")
        patched = RunResult(exit_code=0, stdout=b"same\n", stderr=b"ignored patched")

        regression = validator.compare_regression(original, patched)

        self.assertEqual(regression.verdict, "pass")
        self.assertEqual(regression.stderr_match, "ignored")

    def test_regression_is_inconclusive_when_original_is_nondeterministic(self):
        validator = self._validator()
        original = RunResult(exit_code=0, stdout=b"first\n", stderr=b"")
        original_repeat = RunResult(exit_code=0, stdout=b"second\n", stderr=b"")
        patched = RunResult(exit_code=0, stdout=b"first\n", stderr=b"")

        regression = validator.compare_regression(original, patched, original_repeat)

        self.assertEqual(regression.verdict, "inconclusive")
        self.assertIn("not deterministic", regression.notes[0])

    def test_sprintf_generated_boundary_reserves_format_overhead(self):
        manifest = os.path.join(self.tmp.name, "manifest.json")
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump({"patches": [{"size": {"mode": "known", "known_size": 24}}]}, f)
        validator = self._validator(
            sinks=[SinkInfo(address=0x401000, func_name="sprintf")],
            manifest_path=manifest,
        )

        boundary = [case for case in validator.load_input_cases() if case.kind == "boundary"][0]

        self.assertEqual(len(boundary.input_data), 19)

    def test_sprintf_empty_stdout_preservation_is_inconclusive(self):
        validator = self._validator()
        case = ValidationInputCase("boundary", "boundary", "argv", "AAAA")
        regression = RegressionResult(checked=True, verdict="pass", stdout_match=True, exit_code_match=True)

        adjusted = validator._adjust_regression_for_sink(
            case,
            SinkInfo(address=0x401000, func_name="sprintf"),
            RunResult(exit_code=0, stdout=b""),
            RunResult(exit_code=0, stdout=b""),
            regression,
        )

        self.assertEqual(adjusted.verdict, "inconclusive")
        self.assertIn("sprintf", adjusted.notes[0])

    def test_malicious_verdict_requires_original_evidence(self):
        validator = self._validator()
        case = ValidationInputCase("mal", "malicious", "argv", "A" * 100)
        verdict, notes = validator._case_verdict(
            case,
            RunResult(exit_code=0),
            RunResult(exit_code=0),
            RegressionResult(checked=False),
            GdbContractResult(checked=False),
        )

        self.assertEqual(verdict, "inconclusive")
        self.assertIn("original run did not crash", notes[0])

    def test_benign_verdict_fails_on_regression_mismatch(self):
        validator = self._validator()
        case = ValidationInputCase("benign", "benign", "argv", "hello")
        verdict, notes = validator._case_verdict(
            case,
            RunResult(exit_code=0, stdout=b"a"),
            RunResult(exit_code=0, stdout=b"b"),
            RegressionResult(checked=True, stdout_match=False, exit_code_match=True, verdict="fail", notes=["stdout mismatch"]),
            GdbContractResult(checked=False),
        )

        self.assertEqual(verdict, "fail")
        self.assertEqual(notes, ["stdout mismatch"])

    def test_validate_writes_structured_json_report(self):
        path = os.path.join(self.tmp.name, "inputs.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "cases": [
                        {"name": "benign", "kind": "benign", "channel": "argv", "input": "hello"}
                    ]
                },
                f,
            )
        validator = self._validator(validation_inputs=path, sinks=[SinkInfo(address=0x401000, func_name="strcpy")])

        report = validator.validate()

        self.assertFalse(report["claims"]["full_functional_equivalence"])
        self.assertEqual(report["validation_scope"], "bounded-input-regression-and-gdb-contracts")
        self.assertTrue(os.path.exists(validator.report_path))
        with open(validator.report_path, "r", encoding="utf-8") as f:
            on_disk = json.load(f)
        self.assertIn("cases", on_disk)
        self.assertIn("input_sha256", on_disk["cases"][0])

    def test_gdb_unavailable_is_reported_not_raised(self):
        validator = Validator("/bin/true", patched_binary_path="/bin/true", enable_gdb=True, timeout=1)
        case = ValidationInputCase("benign", "benign", "argv", "hello")

        with mock.patch("src.vulnerability_identifier_removal.validator.shutil.which", return_value=None):
            result = validator.evaluate_gdb_contract(case, SinkInfo(address=0x401000, func_name="strcpy"))

        self.assertFalse(result.checked)
        self.assertEqual(result.verdict, "inconclusive")
        self.assertIn("gdb unavailable", result.notes)

    def test_gdb_ptrace_and_breakpoint_errors_are_parsed(self):
        validator = self._validator()
        obs = validator._parse_gdb_log(
            "ptrace: Operation not permitted\n"
            "Cannot insert breakpoint 1.\n"
            "@@BASICS_SITE_HIT rip=0x401000 rsp=0x7fffffffe000 rbp=0x7fffffffe100 "
            "rdi=0x1 rsi=0x2 rdx=0x3 rcx=0x4 r8=0x5 r9=0x6\n"
        )

        self.assertTrue(obs.ptrace_denied)
        self.assertTrue(obs.breakpoint_error)
        self.assertTrue(obs.site_hit)
        self.assertEqual(obs.registers["rip"], "0x401000")


if __name__ == "__main__":
    unittest.main()
