"""PoC document export tests.

The PoC document is the report-ready deliverable, so its guardrails matter as
much as its content: it must never let an empty or unreviewed capture read as
proof, and it must always carry the method's limitations alongside the evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.evidence import Evidence
from vapt_verify.reconciliation import reconcile
from vapt_verify.reporting.poc import PocBuilder, poc_index_markdown
from vapt_verify.workspace import EngagementWorkspace

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "sample_small.nessus"


def _workspace(tmp_path: Path) -> EngagementWorkspace:
    ws = EngagementWorkspace.create(tmp_path / "e1", Engagement(engagement_id="e1"))
    result = NessusImporter(engagement_id="e1").import_file(SAMPLE)
    ws.persist_import(source_path=SAMPLE, result=result, reconciliation=reconcile(result))
    return ws


def _tls_finding_id(ws: EngagementWorkspace) -> str:
    return next(f["finding_id"] for f in ws.load_findings() if f["plugin_id"] == "57582")


def _attach_evidence(ws: EngagementWorkspace, finding_id: str, **overrides: object) -> str:
    row = next(f for f in ws.load_findings() if f["finding_id"] == finding_id)
    evidence = Evidence(
        evidence_id="ev-test-0001",
        finding_id=finding_id,
        engagement_id="e1",
        asset_id=row["asset_id"],
        adapter="openssl",
        tool_name="openssl",
        command_args=["openssl", "s_client", "-connect", "192.0.2.10:443"],
        sanitized_command="openssl s_client -connect 192.0.2.10:443",
        operator="tester",
        start_timestamp="2026-07-28T10:00:00+00:00",
        end_timestamp="2026-07-28T10:00:01+00:00",
        exit_code=0,
        stderr="verify error:num=18:self-signed certificate\nCONNECTION ESTABLISHED",
        parsed_observations={"self_signed_indicated": True},
        sha256="a" * 64,
        raw_evidence_path="/evidence/x.txt",
    )
    for key, value in overrides.items():
        setattr(evidence, key, value)
    ws.append_evidence(evidence.to_dict())
    return evidence.evidence_id


# --- guardrail: no evidence is never a proof -------------------------------

def test_finding_without_evidence_exports_as_evidence_request(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    document = PocBuilder(ws).build(_tls_finding_id(ws))
    assert document is not None
    assert document.has_evidence is False
    assert "EVIDENCE REQUEST" in document.status_line
    assert "not a proof" in document.status_line
    markdown = document.to_markdown()
    assert "**No verification evidence has been captured for this finding.**" in markdown


def test_evidence_request_lists_what_is_required(tmp_path: Path) -> None:
    """A local-check finding must state the credentialed/administrative evidence."""
    ws = _workspace(tmp_path)
    patch_id = next(f["finding_id"] for f in ws.load_findings() if f["plugin_id"] == "123456")
    document = PocBuilder(ws).build(patch_id)
    assert document is not None
    assert document.required_evidence
    joined = " ".join(document.required_evidence).lower()
    assert "credentialed" in joined or "administrative" in joined


# --- guardrail: captured but unreviewed is stated, not implied -------------

def test_evidence_without_verdict_is_marked_not_reviewed(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    finding_id = _tls_finding_id(ws)
    _attach_evidence(ws, finding_id)
    document = PocBuilder(ws).build(finding_id)
    assert document is not None
    assert document.has_evidence is True
    assert document.is_reviewed is False
    assert "NOT REVIEWED" in document.status_line
    markdown = document.to_markdown()
    assert "does not constitute a verdict" in markdown


def test_reviewed_finding_shows_verdict_and_rationale(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    finding_id = _tls_finding_id(ws)
    _attach_evidence(ws, finding_id)
    ws.append_decision({
        "finding_id": finding_id, "verdict": "confirmed", "reviewer": "alice",
        "reviewer_rationale": "openssl reproduced the self-signed chain.",
        "timestamp": "2026-07-28T11:00:00+00:00",
    })
    document = PocBuilder(ws).build(finding_id)
    assert document is not None
    assert document.is_reviewed is True
    assert document.verdict == "confirmed"
    markdown = document.to_markdown()
    assert "REVIEWED - verdict: confirmed" in markdown
    assert "openssl reproduced the self-signed chain." in markdown
    assert "alice" in markdown


# --- content completeness --------------------------------------------------

def test_document_pairs_scanner_claim_with_capture(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    finding_id = _tls_finding_id(ws)
    _attach_evidence(ws, finding_id)
    markdown = PocBuilder(ws).build(finding_id).to_markdown()
    # 1. the scanner's original claim, traceable to its source file
    assert "## 1. Original scanner claim" in markdown
    assert "sample_small.nessus" in markdown
    assert "self-signed" in markdown.lower()
    # 2. the exact command run, and the captured output
    assert "openssl s_client -connect 192.0.2.10:443" in markdown
    assert "CONNECTION ESTABLISHED" in markdown
    # 3/4. assessment and limitations always present
    assert "## 3. Assessment" in markdown
    assert "## 4. Limitations of this verification" in markdown


def test_document_always_carries_method_limitations(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    markdown = PocBuilder(ws).build(_tls_finding_id(ws)).to_markdown()
    assert "Absence of a reproduction is not proof of absence" in markdown


def test_evidence_integrity_is_recorded(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    finding_id = _tls_finding_id(ws)
    _attach_evidence(ws, finding_id)
    document = PocBuilder(ws).build(finding_id)
    block = document.evidence[0]
    assert block.sha256 == "a" * 64
    assert block.operator == "tester"
    assert "a" * 64 in document.to_markdown()


def test_long_output_is_truncated_but_flagged(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    finding_id = _tls_finding_id(ws)
    _attach_evidence(ws, finding_id, stdout="\n".join(f"line {i}" for i in range(500)))
    document = PocBuilder(ws).build(finding_id, max_output_lines=10)
    block = document.evidence[0]
    assert block.truncated is True
    assert len(block.output.splitlines()) == 10
    assert "truncated" in document.to_markdown()


def test_html_export_is_self_contained(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    finding_id = _tls_finding_id(ws)
    _attach_evidence(ws, finding_id)
    doc_html = PocBuilder(ws).build(finding_id).to_html()
    assert doc_html.startswith("<!doctype html>")
    assert "http://" not in doc_html and "https://" not in doc_html


def test_unknown_finding_returns_none(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    assert PocBuilder(ws).build("find-does-not-exist") is None


def test_index_states_requests_are_not_proofs(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    documents = [PocBuilder(ws).build(f["finding_id"]) for f in ws.load_findings()]
    index = poc_index_markdown([d for d in documents if d])
    assert "evidence requests, not as proofs" in index


# --- CLI -------------------------------------------------------------------

def test_cli_poc_export_writes_all_formats(tmp_path: Path, capsys) -> None:
    ws = _workspace(tmp_path)
    finding_id = _tls_finding_id(ws)
    _attach_evidence(ws, finding_id)
    capsys.readouterr()
    rc = main(["poc", "export", "--base", str(tmp_path), "--engagement", "e1",
               "--finding", finding_id, "--format", "all"])
    assert rc == 0
    out_dir = ws.root / "reports" / "poc"
    stem = finding_id.replace("find-", "poc-")
    assert (out_dir / f"{stem}.md").exists()
    assert (out_dir / f"{stem}.html").exists()
    payload = json.loads((out_dir / "poc.json").read_text(encoding="utf-8"))
    assert payload[0]["finding_id"] == finding_id
    assert payload[0]["has_evidence"] is True


def test_cli_with_evidence_only_filters(tmp_path: Path, capsys) -> None:
    ws = _workspace(tmp_path)
    _attach_evidence(ws, _tls_finding_id(ws))
    capsys.readouterr()
    rc = main(["poc", "export", "--base", str(tmp_path), "--engagement", "e1",
               "--with-evidence-only"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Exported 1 PoC document(s)" in out


def test_cli_reports_evidence_requests_separately(tmp_path: Path, capsys) -> None:
    _workspace(tmp_path)  # no evidence attached at all
    capsys.readouterr()
    rc = main(["poc", "export", "--base", str(tmp_path), "--engagement", "e1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "NOT as proofs" in out
