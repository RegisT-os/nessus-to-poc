"""Workspace persistence and CLI end-to-end tests."""

from __future__ import annotations

import json
from pathlib import Path

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation import reconcile
from vapt_verify.utilities.hashing import sha256_file
from vapt_verify.workspace import EngagementWorkspace

FIXTURES = Path(__file__).parent / "fixtures"


def test_persist_import_preserves_original_and_writes_manifest(tmp_path: Path) -> None:
    root = tmp_path / "eng1"
    ws = EngagementWorkspace.create(root, Engagement(engagement_id="eng1"))
    result = NessusImporter(engagement_id="eng1").import_file(FIXTURES / "sample_small.nessus")
    report = reconcile(result)
    record = ws.persist_import(
        source_path=FIXTURES / "sample_small.nessus", result=result, reconciliation=report
    )

    # Original preserved unmodified (same hash) and never touched in place.
    assert record.original_path.exists()
    assert sha256_file(record.original_path) == sha256_file(FIXTURES / "sample_small.nessus")

    # Normalized findings written 1:1.
    findings = ws.load_findings()
    assert len(findings) == result.normalized_finding_count

    # Manifest carries tool versions and counts.
    manifest = json.loads(record.manifest_path.read_text(encoding="utf-8"))
    assert manifest["counts"]["normalized_finding_count"] == result.normalized_finding_count
    assert "vapt_verify" in manifest["tool_versions"]

    # Audit log has an immutable import entry.
    audit_lines = ws.audit_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(audit_lines) == 1


def test_repeated_import_appends_provenance(tmp_path: Path) -> None:
    root = tmp_path / "eng1"
    ws = EngagementWorkspace.create(root, Engagement(engagement_id="eng1"))
    imp = NessusImporter(engagement_id="eng1")
    for name, start in (("a.nessus", "Mon Jul 20 09:00:00 2026"),
                        ("b.nessus", "Tue Jul 21 09:00:00 2026")):
        props = default_host_props("192.0.2.10")
        props["HOST_START"] = start
        host = report_host(name="192.0.2.10", props=props, items=[
            report_item(plugin_id="51192", plugin_name="SSL Cert", port=443, protocol="tcp",
                        severity=2)
        ])
        path = tmp_path / name
        path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
        result = imp.import_file(path)
        ws.persist_import(source_path=path, result=result, reconciliation=reconcile(result))

    # Two scans => two finding rows retained with separate provenance.
    findings = ws.load_findings()
    assert len(findings) == 2
    assert len({f["provenance"]["import_id"] for f in findings}) == 2


def test_cli_full_flow(tmp_path: Path, capsys) -> None:
    base = str(tmp_path / "engagements")

    assert main(["engagement", "create", "--base", base, "--id", "eng1",
                 "--client-alias", "ExampleBank"]) == 0
    # Balanced-clean import returns 0.
    assert main(["import", "--base", base, "--engagement", "eng1",
                 str(FIXTURES / "sample_small.nessus")]) == 0
    out = capsys.readouterr().out
    assert "all source report items accounted for" in out.lower()

    assert main(["import", "status", "--base", base, "--engagement", "eng1"]) == 0
    assert main(["inventory", "assets", "--base", base, "--engagement", "eng1"]) == 0
    assert main(["inventory", "services", "--base", base, "--engagement", "eng1"]) == 0
    assert main(["findings", "list", "--base", base, "--engagement", "eng1"]) == 0
    listing = capsys.readouterr().out
    assert "finding(s)" in listing


def test_cli_import_with_parse_failures_fails_closed(tmp_path: Path, capsys) -> None:
    base = str(tmp_path / "engagements")
    main(["engagement", "create", "--base", base, "--id", "eng1"])

    good = report_item(plugin_id="1", plugin_name="Good", port=443, protocol="tcp", severity=2)
    bad = report_item(plugin_id="2", plugin_name="Bad", raw_port="xyz", protocol="tcp", severity=2)
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"),
                       items=[good, bad])
    scan = tmp_path / "scan.nessus"
    scan.write_text(nessus_document(hosts=[host]), encoding="utf-8")

    # Without acknowledgement, the import fails closed (exit 1).
    assert main(["import", "--base", base, "--engagement", "eng1", str(scan)]) == 1
    # With explicit acknowledgement, it succeeds (exit 0) but the failure is recorded.
    assert main(["import", "--base", base, "--engagement", "eng1", str(scan),
                 "--allow-parse-failures"]) == 0


def test_cli_security_scan(tmp_path: Path) -> None:
    # A clean sanitized tree passes.
    (tmp_path / ".gitignore").write_text("profiles/private/\n", encoding="utf-8")
    (tmp_path / "profiles" / "examples").mkdir(parents=True)
    (tmp_path / "profiles" / "examples" / "e.yaml").write_text(
        "cidr: 192.0.2.0/24\n", encoding="utf-8"
    )
    assert main(["security", "scan", "--root", str(tmp_path)]) == 0
