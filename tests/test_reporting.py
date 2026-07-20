"""Reporting tests (task sections 20-21)."""

from __future__ import annotations

import json
from pathlib import Path

from vapt_verify.classification.classifier import Classifier
from vapt_verify.classification.models import KNOWN_TOOLS, Capabilities
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.finding import Finding
from vapt_verify.recipes.library import RecipeLibrary
from vapt_verify.reconciliation import reconcile
from vapt_verify.reporting.generator import ReportGenerator
from vapt_verify.workspace import EngagementWorkspace

FIXTURES = Path(__file__).parent / "fixtures"


def _prepared_ws(tmp_path: Path) -> EngagementWorkspace:
    ws = EngagementWorkspace.create(tmp_path / "e1", Engagement(engagement_id="e1",
                                                                client_alias="ExampleBank"))
    result = NessusImporter(engagement_id="e1").import_file(FIXTURES / "sample_small.nessus")
    ws.persist_import(source_path=FIXTURES / "sample_small.nessus", result=result,
                      reconciliation=reconcile(result))
    # classify so dispositions are populated
    library = RecipeLibrary.load_builtin()
    classifier = Classifier(library, Capabilities(available=set(KNOWN_TOOLS)))
    rows = ws.load_findings()
    for row in rows:
        c = classifier.classify(Finding.from_dict(row))
        row["disposition"] = c.disposition
    ws.rewrite_findings(rows)
    return ws


def test_json_report_has_coverage_totalling_to_imported(tmp_path: Path) -> None:
    gen = ReportGenerator(_prepared_ws(tmp_path))
    report = json.loads(gen.json_report())
    cov = report["coverage"]
    assert cov["accounted"] == cov["total_imported"] == report["finding_count"]
    assert cov["totals_balance"] is True


def test_csv_matrix_has_a_row_per_finding(tmp_path: Path) -> None:
    gen = ReportGenerator(_prepared_ws(tmp_path))
    csv_text = gen.csv_matrix().strip().splitlines()
    assert csv_text[0].startswith("finding_id,")
    assert len(csv_text) - 1 == 6  # header + 6 findings in the sample


def test_markdown_leads_with_coverage_not_automation(tmp_path: Path) -> None:
    md = ReportGenerator(_prepared_ws(tmp_path)).markdown()
    assert "Coverage (primary metric)" in md
    assert "accounted for" in md.lower()
    assert "automation" in md.lower()  # mentioned only to say it is NOT the metric


def test_html_dashboard_is_self_contained(tmp_path: Path) -> None:
    html_doc = ReportGenerator(_prepared_ws(tmp_path)).html_dashboard()
    assert html_doc.startswith("<!doctype html>")
    assert "http://" not in html_doc and "https://" not in html_doc  # no external assets
    assert "Coverage:" in html_doc


def test_report_cli_writes_all_formats(tmp_path: Path) -> None:
    from vapt_verify.cli.main import main

    _prepared_ws(tmp_path)  # creates tmp_path/e1
    base = str(tmp_path)
    rc = main(["report", "--base", base, "--engagement", "e1", "--format", "all"])
    assert rc == 0
    reports = tmp_path / "e1" / "reports"
    assert (reports / "report.md").exists()
    assert (reports / "report.json").exists()
    assert (reports / "verification_matrix.csv").exists()
    assert (reports / "dashboard.html").exists()
