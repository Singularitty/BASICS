import importlib.util
import csv
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "update_benchmark_table.py"
SPEC = importlib.util.spec_from_file_location("update_benchmark_table", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

PAPER_JULIET = {
    "Juliet CWE-121": {
        "cases": 3524, "errors": 0, "TP": 900, "FP": 145, "TN": 1617, "FN": 862,
        "updated": "2026-10-04", "source": "paper",
    }
}


def test_render_matches_paper_metrics():
    table = MODULE.render_table(PAPER_JULIET)
    row = table.splitlines()[2]
    # Precision, recall, F1 and accuracy as printed in the paper.
    for value in ("86.1%", "51.1%", "64.1%", "71.4%"):
        assert value in row
    assert "900 (25.5%)" in row
    assert row.startswith("| 3,524 | ") and "errors" not in row


def test_replace_section_keeps_surrounding_text():
    text = f"intro\n{MODULE.START_MARKER}\nold table\n{MODULE.END_MARKER}\noutro\n"
    out = MODULE.replace_section(text, "new table")
    assert out == f"intro\n{MODULE.START_MARKER}\nnew table\n{MODULE.END_MARKER}\noutro\n"


def test_entry_from_run_counts_and_filters(tmp_path):
    fields = ["case_id", "dataset", "true_present_vuln", "reported_vuln", "status"]
    rows = [
        ("a", "J", "True", "True", "ok"),
        ("b", "J", "True", "False", "ok"),
        ("c", "J", "False", "True", "ok"),
        ("d", "J", "False", "False", "ok"),
        ("e", "J", "True", "", "timeout"),
        ("f", "SARD", "True", "True", "ok"),
    ]
    with (tmp_path / "results.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        w.writerows(rows)
    e = MODULE.entry_from_run(tmp_path, csv_dataset="J")
    assert (e["cases"], e["errors"], e["TP"], e["FN"], e["FP"], e["TN"]) == (5, 1, 1, 1, 1, 1)
    assert e["source"].startswith(f"run {tmp_path.name} at ")


def test_entry_from_run_refuses_all_error_runs(tmp_path):
    (tmp_path / "results.csv").write_text(
        "case_id,dataset,true_present_vuln,reported_vuln,status\n"
        "a,J,True,,run_error\n"
    )
    try:
        MODULE.entry_from_run(tmp_path)
    except SystemExit as exc:
        assert "No graded cases" in str(exc)
    else:
        raise AssertionError("all-error run was accepted")
