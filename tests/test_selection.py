"""Choosing which findings become capture scripts.

The invariant these tests exist to defend: **a selection is a scoping decision,
not a deletion.** Deselecting a finding must never remove it from the
inventory, give it a disposition, or make it look like a false positive; and
every artefact generated from a selection must state what it left out.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.cli.main import main
from vapt_verify.cli.picker import _parse_numbers, run_picker
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation.gate import reconcile
from vapt_verify.selection import Selection, SelectionCriteria, select_by_criteria
from vapt_verify.workspace import EngagementWorkspace

ITEMS: list[dict[str, Any]] = [
    {"plugin_id": "51192", "plugin_name": "SSL Certificate Cannot Be Trusted",
     "port": 443, "protocol": "tcp", "severity": 2, "svc_name": "https"},
    {"plugin_id": "57582", "plugin_name": "SSL Self-Signed Certificate",
     "port": 443, "protocol": "tcp", "severity": 1, "svc_name": "https"},
    {"plugin_id": "90317", "plugin_name": "SSH Weak Algorithms Supported",
     "port": 22, "protocol": "tcp", "severity": 2, "svc_name": "ssh"},
    {"plugin_id": "123456", "plugin_name": "Ubuntu Security Update for OpenSSL",
     "port": 0, "severity": 3, "family": "Ubuntu Local Security Checks"},
    {"plugin_id": "10287", "plugin_name": "Traceroute Information",
     "port": 0, "severity": 0, "family": "Service detection"},
]


@pytest.fixture
def ws(tmp_path: Path) -> EngagementWorkspace:
    host = report_host(
        name="192.0.2.10",
        props=default_host_props("192.0.2.10"),
        items=[report_item(**i) for i in ITEMS],  # type: ignore[arg-type]
    )
    path = tmp_path / "scan.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    workspace = EngagementWorkspace.create(
        tmp_path / "engagements" / "e1",
        Engagement(engagement_id="e1", approved_cidrs=["192.0.2.0/24"]),
    )
    result = NessusImporter(engagement_id="e1").import_file(path)
    workspace.persist_import(source_path=path, result=result, reconciliation=reconcile(result))
    return workspace


def _base(ws: EngagementWorkspace) -> str:
    return str(ws.root.parent)


# --- criteria ---------------------------------------------------------------


def test_criteria_are_ored_not_anded(ws: EngagementWorkspace) -> None:
    """"The criticals, plus that one SSH finding" must not intersect to nothing."""
    rows = ws.load_findings()
    criteria = SelectionCriteria.parse(severity="HIGH", plugin="90317")
    selection = select_by_criteria(rows, criteria, engagement_id="e1")
    names = {
        r["plugin_name"] for r in rows if r["finding_id"] in set(selection.selected_ids)
    }
    assert names == {"Ubuntu Security Update for OpenSSL", "SSH Weak Algorithms Supported"}


def test_empty_criteria_select_everything(ws: EngagementWorkspace) -> None:
    rows = ws.load_findings()
    selection = select_by_criteria(rows, SelectionCriteria(), engagement_id="e1")
    assert selection.count == len(rows)
    assert selection.covers_everything
    assert selection.method == "all"


def test_search_matches_name_and_service(ws: EngagementWorkspace) -> None:
    rows = ws.load_findings()
    selection = select_by_criteria(
        rows, SelectionCriteria.parse(search="self-signed"), engagement_id="e1"
    )
    assert selection.count == 1
    selection = select_by_criteria(
        rows, SelectionCriteria.parse(search="ssh"), engagement_id="e1"
    )
    assert selection.count == 1


def test_bad_port_is_rejected_with_a_readable_error() -> None:
    with pytest.raises(ValueError, match="not a port number"):
        SelectionCriteria.parse(port="443,notaport")


# --- the scoping-not-deletion invariant -------------------------------------


def test_deselected_findings_stay_in_the_inventory(
    ws: EngagementWorkspace, capsys: pytest.CaptureFixture[str]
) -> None:
    before = len(ws.load_findings())
    assert main(["select", "--base", _base(ws), "--engagement", "e1",
                 "--severity", "HIGH"]) == 0
    assert len(ws.load_findings()) == before, "selecting must not delete findings"

    # ...and no finding acquired a verdict or disposition from being deselected.
    for row in ws.load_findings():
        assert row["verdict"] == "unreviewed"
        assert row["disposition"] == "pending_classification"


def test_selection_states_what_it_left_out(
    ws: EngagementWorkspace, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    assert main(["select", "--base", _base(ws), "--engagement", "e1",
                 "--severity", "HIGH", "--operator", "regis"]) == 0
    out = capsys.readouterr().out
    assert "4 finding(s) deselected" in out
    assert "NOT false positives" in out
    assert "still require a disposition" in out


def test_coverage_still_reports_every_imported_finding(
    ws: EngagementWorkspace, capsys: pytest.CaptureFixture[str]
) -> None:
    """The 'did anything disappear?' report must ignore the selection."""
    assert main(["select", "--base", _base(ws), "--engagement", "e1",
                 "--severity", "HIGH"]) == 0
    capsys.readouterr()
    assert main(["coverage", "--base", _base(ws), "--engagement", "e1"]) == 0
    out = capsys.readouterr().out
    assert f"{len(ITEMS)}/{len(ITEMS)} findings accounted for" in out
    assert "capture selection: 1/5" in out
    assert "not a false-positive judgement" in out


def test_runbook_honours_the_selection_and_says_so(
    ws: EngagementWorkspace, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["select", "--base", _base(ws), "--engagement", "e1",
                 "--severity", "MEDIUM", "--operator", "regis"]) == 0
    capsys.readouterr()
    out_dir = tmp_path / "rb"
    assert main(["runbook", "--base", _base(ws), "--engagement", "e1",
                 "--output", str(out_dir)]) == 0
    out = capsys.readouterr().out
    assert "Using saved selection: 2 of 5" in out
    assert "3 deselected finding(s) are excluded" in out

    manifest = json.loads((out_dir / "runbook.json").read_text(encoding="utf-8"))
    assert len(manifest["entries"]) == 2
    assert "deselected" in manifest["selection_summary"]
    # The generated artefacts carry the caveat, not just the terminal output.
    assert "deselected" in (out_dir / "runbook.sh").read_text(encoding="utf-8")
    assert "deselected" in (out_dir / "runbook.md").read_text(encoding="utf-8")


def test_kit_build_honours_the_selection_and_says_so(
    ws: EngagementWorkspace, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["select", "--base", _base(ws), "--engagement", "e1",
                 "--severity", "MEDIUM", "--operator", "regis"]) == 0
    capsys.readouterr()
    kit = tmp_path / "kit"
    assert main(["kit", "build", "--base", _base(ws), "--engagement", "e1",
                 "--output", str(kit)]) == 0
    assert "Using saved selection: 2 of 5" in capsys.readouterr().out

    manifest = json.loads((kit / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["finding_count"] == 2
    assert manifest["imported_finding_count"] == 5
    assert manifest["deselected_finding_count"] == 3
    readme = (kit / "README.md").read_text(encoding="utf-8")
    assert "Scope of this kit" in readme
    assert "still require a" in readme


def test_all_findings_overrides_the_selection(
    ws: EngagementWorkspace, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["select", "--base", _base(ws), "--engagement", "e1",
                 "--severity", "HIGH"]) == 0
    capsys.readouterr()
    out_dir = tmp_path / "rb"
    assert main(["runbook", "--base", _base(ws), "--engagement", "e1",
                 "--all-findings", "--output", str(out_dir)]) == 0
    out = capsys.readouterr().out
    assert "--all-findings was passed" in out
    manifest = json.loads((out_dir / "runbook.json").read_text(encoding="utf-8"))
    assert len(manifest["entries"]) == len(ITEMS)


def test_no_selection_means_everything_is_covered(
    ws: EngagementWorkspace, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_dir = tmp_path / "rb"
    assert main(["runbook", "--base", _base(ws), "--engagement", "e1",
                 "--output", str(out_dir)]) == 0
    assert "Using saved selection" not in capsys.readouterr().out
    manifest = json.loads((out_dir / "runbook.json").read_text(encoding="utf-8"))
    assert len(manifest["entries"]) == len(ITEMS)
    assert manifest["selection_summary"] == ""


# --- editing ----------------------------------------------------------------


def test_add_and_remove_edit_the_existing_selection(
    ws: EngagementWorkspace, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _base(ws)
    assert main(["select", "--base", base, "--engagement", "e1", "--severity", "HIGH"]) == 0
    assert Selection.load(ws.root).count == 1  # type: ignore[union-attr]

    assert main(["select", "--base", base, "--engagement", "e1",
                 "--search", "self-signed", "--add"]) == 0
    selection = Selection.load(ws.root)
    assert selection is not None
    assert selection.count == 2
    assert selection.method == "edited"
    assert "added 1 finding(s)" in selection.last_operation

    assert main(["select", "--base", base, "--engagement", "e1",
                 "--severity", "LOW", "--remove"]) == 0
    selection = Selection.load(ws.root)
    assert selection is not None
    assert selection.count == 1
    assert "removed 1 finding(s)" in selection.last_operation


def test_an_edit_that_matches_nothing_says_so_and_changes_nothing(
    ws: EngagementWorkspace, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _base(ws)
    assert main(["select", "--base", base, "--engagement", "e1", "--severity", "HIGH"]) == 0
    before = Selection.load(ws.root)
    capsys.readouterr()
    assert main(["select", "--base", base, "--engagement", "e1",
                 "--severity", "CRITICAL", "--add"]) == 2
    assert "Nothing matched" in capsys.readouterr().out
    after = Selection.load(ws.root)
    assert before is not None and after is not None
    assert before.selected_ids == after.selected_ids


def test_edit_records_the_operation_not_a_misleading_criteria_line(
    ws: EngagementWorkspace,
) -> None:
    """After `--remove LOW`, the stored criteria describe the removal.

    Displaying them as though they described the *selection* would tell an
    operator they had selected the LOW findings they just took out.
    """
    base = _base(ws)
    assert main(["select", "--base", base, "--engagement", "e1", "--severity", "HIGH"]) == 0
    assert main(["select", "--base", base, "--engagement", "e1",
                 "--severity", "LOW", "--remove"]) == 0
    selection = Selection.load(ws.root)
    assert selection is not None
    assert selection.last_operation.startswith("removed")
    assert "severity in LOW" in selection.last_operation


def test_clear_restores_full_coverage(
    ws: EngagementWorkspace, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _base(ws)
    assert main(["select", "--base", base, "--engagement", "e1", "--severity", "HIGH"]) == 0
    assert Selection.load(ws.root) is not None
    capsys.readouterr()
    assert main(["select", "--base", base, "--engagement", "e1", "--clear"]) == 0
    assert "Selection cleared" in capsys.readouterr().out
    assert Selection.load(ws.root) is None

    out_dir = tmp_path / "rb"
    assert main(["runbook", "--base", base, "--engagement", "e1",
                 "--output", str(out_dir)]) == 0
    manifest = json.loads((out_dir / "runbook.json").read_text(encoding="utf-8"))
    assert len(manifest["entries"]) == len(ITEMS)


def test_selection_round_trips_through_disk(ws: EngagementWorkspace) -> None:
    selection = select_by_criteria(
        ws.load_findings(), SelectionCriteria.parse(severity="MEDIUM"),
        engagement_id="e1", operator="regis", note="readout",
    )
    selection.save(ws.root)
    restored = Selection.load(ws.root)
    assert restored is not None
    assert restored.selected_ids == selection.selected_ids
    assert restored.operator == "regis"
    assert restored.note == "readout"
    assert restored.criteria.severities == ["MEDIUM"]


def test_selection_is_recorded_in_the_audit_log(ws: EngagementWorkspace) -> None:
    assert main(["select", "--base", _base(ws), "--engagement", "e1",
                 "--severity", "HIGH", "--operator", "regis"]) == 0
    events = [
        json.loads(line) for line in ws.audit_log.read_text(encoding="utf-8").splitlines()
    ]
    entry = next(e for e in events if e["event"] == "selection_set")
    assert entry["operator"] == "regis"
    assert entry["selected"] == 1
    assert entry["total"] == 5


# --- the interactive picker -------------------------------------------------


def test_parse_numbers_handles_ranges_and_junk() -> None:
    assert _parse_numbers("1-3,7", 10) == [1, 2, 3, 7]
    assert _parse_numbers("3-1", 10) == [1, 2, 3]  # reversed range still works
    assert _parse_numbers("1 2 3", 10) == [1, 2, 3]
    assert _parse_numbers("99", 10) == []  # out of range is dropped, not an error
    assert _parse_numbers("banana", 10) == []


def _picker(ws: EngagementWorkspace, answers: list[str]) -> set[str] | None:
    it = iter(answers)
    return run_picker(
        ws.load_findings(),
        input_fn=lambda _prompt: next(it),
        output_fn=lambda _line: None,
    )


def test_picker_toggles_rows_by_number(ws: EngagementWorkspace) -> None:
    chosen = _picker(ws, ["1", "2", "d"])
    assert chosen is not None
    assert len(chosen) == 2


def test_picker_toggle_is_reversible(ws: EngagementWorkspace) -> None:
    assert _picker(ws, ["1", "1", "d"]) == set()


def test_picker_quit_returns_none_not_an_empty_selection(ws: EngagementWorkspace) -> None:
    """"I changed my mind" and "I chose nothing" are different answers."""
    assert _picker(ws, ["1", "q"]) is None


def test_picker_select_all_and_none(ws: EngagementWorkspace) -> None:
    chosen = _picker(ws, ["a", "d"])
    assert chosen is not None
    assert len(chosen) == len(ITEMS)
    assert _picker(ws, ["a", "n", "d"]) == set()


def test_picker_filter_limits_bulk_actions_to_the_view(ws: EngagementWorkspace) -> None:
    """`a` after a filter must select the filtered rows, not everything."""
    chosen = _picker(ws, ["/ssh", "a", "d"])
    assert chosen is not None
    names = {
        r["plugin_name"] for r in ws.load_findings() if r["finding_id"] in chosen
    }
    assert names == {"SSH Weak Algorithms Supported"}


def test_picker_selects_by_severity(ws: EngagementWorkspace) -> None:
    chosen = _picker(ws, ["s MEDIUM", "d"])
    assert chosen is not None
    names = {
        r["plugin_name"] for r in ws.load_findings() if r["finding_id"] in chosen
    }
    assert names == {"SSL Certificate Cannot Be Trusted", "SSH Weak Algorithms Supported"}


def test_picker_ignores_unrecognised_input_without_crashing(
    ws: EngagementWorkspace,
) -> None:
    chosen = _picker(ws, ["what?", "", "1", "d"])
    assert chosen is not None
    assert len(chosen) == 1


def test_picker_saves_on_end_of_input(ws: EngagementWorkspace) -> None:
    """A closed stdin must not throw away what was already picked."""

    def raise_eof(_prompt: str) -> str:
        raise EOFError

    answers = iter(["1"])

    def input_fn(prompt: str) -> str:
        try:
            return next(answers)
        except StopIteration:
            return raise_eof(prompt)

    chosen = run_picker(
        ws.load_findings(), input_fn=input_fn, output_fn=lambda _line: None
    )
    assert chosen is not None
    assert len(chosen) == 1


def test_picker_preselection_is_honoured(ws: EngagementWorkspace) -> None:
    rows = ws.load_findings()
    first = rows[0]["finding_id"]
    chosen = run_picker(
        rows, preselected={first},
        input_fn=lambda _p: "d", output_fn=lambda _line: None,
    )
    assert chosen == {first}
