"""Reconciliation gate tests (task sections 6, 14; mandatory tests 22 & 32)."""

from __future__ import annotations

from pathlib import Path

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.importers.base import ImportResult, ParseFailure
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.reconciliation import reconcile
from vapt_verify.reconciliation.gate import ReconciliationStatus

FIXTURES = Path(__file__).parent / "fixtures"


def test_balanced_clean_import(tmp_path: Path) -> None:
    result = NessusImporter(engagement_id="e").import_file(FIXTURES / "sample_small.nessus")
    report = reconcile(result)
    assert report.status is ReconciliationStatus.BALANCED_CLEAN
    assert report.is_balanced
    assert report.accounted == report.source_report_item_count


def test_malformed_record_is_reconciled_explicitly(tmp_path: Path) -> None:
    """Task 22.22 — a malformed source record becomes an explicit parse failure,
    and reconciliation still balances (source == normalized + failures)."""
    good = report_item(plugin_id="1", plugin_name="Good", port=443, protocol="tcp", severity=2)
    bad = report_item(plugin_id="2", plugin_name="Bad Port", raw_port="not-a-number",
                      protocol="tcp", severity=2)
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"),
                       items=[good, bad])
    path = tmp_path / "scan.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")

    result = NessusImporter(engagement_id="e").import_file(path)
    assert result.source_report_item_count == 2
    assert result.normalized_finding_count == 1
    assert result.parse_failure_count == 1
    assert "not-a-number" in result.parse_failures[0].reason

    report = reconcile(result)
    assert report.status is ReconciliationStatus.BALANCED_WITH_EXCEPTIONS
    assert report.is_balanced  # accounting still balances
    assert report.accounted == 2


def test_imbalance_is_detected_and_fails_closed() -> None:
    """A findings drop with no explanation must be flagged IMBALANCED."""
    result = ImportResult(
        import_id="x",
        source_scanner="nessus",
        source_file="f.nessus",
        source_file_hash="deadbeef",
        import_timestamp="now",
        source_report_item_count=10,
        source_host_count=1,
        findings=[],  # pretend 10 items produced 0 findings with no failures
    )
    report = reconcile(result)
    assert report.status is ReconciliationStatus.IMBALANCED
    assert not report.is_balanced
    assert report.unexplained_difference == 10


def test_suppressions_must_be_explicit() -> None:
    result = ImportResult(
        import_id="x",
        source_scanner="nessus",
        source_file="f.nessus",
        source_file_hash="deadbeef",
        import_timestamp="now",
        source_report_item_count=5,
        source_host_count=1,
        parse_failures=[
            ParseFailure(source_record_id="r", host_key="h", reason="broken", raw_excerpt="")
        ],
    )
    # 5 source == 0 normalized + 1 failure + 4 approved suppressions.
    report = reconcile(result, approved_suppressions=4)
    assert report.is_balanced
    assert report.status is ReconciliationStatus.BALANCED_WITH_EXCEPTIONS


def test_coverage_totals_back_to_imported(tmp_path: Path) -> None:
    """Task 22.32 — statistics always total back to imported findings."""
    result = NessusImporter(engagement_id="e").import_file(FIXTURES / "sample_small.nessus")
    report = reconcile(result)
    stats = report.statistics
    assert stats["normalized_finding_count"] == result.normalized_finding_count
    # Severity buckets partition the findings exactly.
    assert sum(stats["findings_by_severity"].values()) == result.normalized_finding_count
    # Host buckets partition the findings exactly.
    assert sum(stats["findings_by_host"].values()) == result.normalized_finding_count
    # The accounting identity holds.
    assert (
        report.normalized_finding_count
        + report.parse_failure_count
        + report.approved_suppression_count
        == report.source_report_item_count
    )
