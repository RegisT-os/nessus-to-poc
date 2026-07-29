"""Evidence redaction and integrity-verification tests (v2.2).

Two invariants matter here:

* Redaction masks sensitive spans in the **exported document only**; the stored
  evidence file keeps its original bytes and stays hash-verifiable.
* Integrity verification detects modification or loss of a stored evidence file
  and fails closed, so a broken chain of custody can never pass silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.evidence import Evidence
from vapt_verify.reconciliation import reconcile
from vapt_verify.reporting.poc import PocBuilder
from vapt_verify.security.integrity import IntegrityStatus, verify_evidence
from vapt_verify.security.redaction import Redactor
from vapt_verify.utilities.hashing import sha256_file
from vapt_verify.workspace import EngagementWorkspace

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "sample_small.nessus"

SECRETS = """snmpwalk -v 2c -c S3cr3tC0mmunity 192.0.2.10
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop
curl https://admin:P@ssw0rd123@intranet.example/api
Set-Cookie: JSESSIONID=9F8A7B6C5D4E3F2A1B; Path=/
password = SuperSecret123
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAx7Zq
-----END RSA PRIVATE KEY-----"""


# --- redaction rules -------------------------------------------------------

@pytest.mark.parametrize(
    "secret",
    [
        "S3cr3tC0mmunity",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
        "P@ssw0rd123",
        "9F8A7B6C5D4E3F2A1B",
        "SuperSecret123",
        "AKIAIOSFODNN7EXAMPLE",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "MIIEowIBAAKCAQEAx7Zq",
    ],
)
def test_each_secret_is_masked(secret: str) -> None:
    result = Redactor().redact(SECRETS)
    assert secret not in result.text, f"{secret!r} survived redaction"


def test_benign_content_is_preserved() -> None:
    """Redaction must not destroy the evidence's usable content."""
    text = ("openssl s_client -connect 192.0.2.10:443 -brief\n"
            "verify error:num=18:self-signed certificate\n"
            "Peer certificate: CN = demo-target.test")
    result = Redactor().redact(text)
    assert result.total == 0
    assert result.text == text


def test_snmp_flag_does_not_match_inside_a_word() -> None:
    """'-c' must start a token, or 'Set-Cookie' gets mangled."""
    result = Redactor().redact("Set-Cookie: SESSION=abc123; Path=/")
    assert result.text.startswith("Set-Cookie:")


def test_password_containing_at_sign_is_fully_masked() -> None:
    result = Redactor().redact("https://admin:P@ssw0rd@host.example/x")
    assert "P@ssw0rd" not in result.text
    assert "host.example" in result.text  # host survives


def test_redaction_counts_are_reported() -> None:
    result = Redactor().redact(SECRETS)
    assert result.applied is True
    assert result.total >= 8
    assert "snmp_community" in result.by_rule


def test_profile_can_add_custom_patterns() -> None:
    redactor = Redactor.from_profile([
        {"name": "internal_ref", "pattern": r"REF-(\d{6})", "description": "internal ref"}
    ])
    result = redactor.redact("ticket REF-123456 raised")
    assert "123456" not in result.text
    # Built-in rules still apply.
    assert redactor.redact("password = hunter2").total == 1


def test_invalid_custom_pattern_does_not_disable_redaction() -> None:
    redactor = Redactor.from_profile([{"name": "bad", "pattern": "([unclosed"}])
    assert redactor.redact("password = hunter2").total == 1


# --- redaction is presentation-only ---------------------------------------

def _workspace_with_secret_evidence(tmp_path: Path) -> tuple[EngagementWorkspace, str, Path]:
    ws = EngagementWorkspace.create(tmp_path / "e1", Engagement(engagement_id="e1"))
    result = NessusImporter(engagement_id="e1").import_file(SAMPLE)
    ws.persist_import(source_path=SAMPLE, result=result, reconciliation=reconcile(result))
    finding_id = next(f["finding_id"] for f in ws.load_findings() if f["plugin_id"] == "57582")
    row = next(f for f in ws.load_findings() if f["finding_id"] == finding_id)

    evidence_file = tmp_path / "capture.txt"
    evidence_file.write_text(SECRETS, encoding="utf-8")
    ws.append_evidence(Evidence(
        evidence_id="ev-secret", finding_id=finding_id, engagement_id="e1",
        asset_id=row["asset_id"], adapter="snmp", tool_name="snmpwalk",
        sanitized_command="snmpwalk -v 2c -c S3cr3tC0mmunity 192.0.2.10",
        operator="tester", exit_code=0, stdout=SECRETS,
        raw_evidence_path=str(evidence_file), sha256=sha256_file(evidence_file),
    ).to_dict())
    return ws, finding_id, evidence_file


def test_exported_document_is_redacted(tmp_path: Path) -> None:
    ws, finding_id, _ = _workspace_with_secret_evidence(tmp_path)
    document = PocBuilder(ws, redactor=Redactor()).build(finding_id)
    markdown = document.to_markdown()
    assert "S3cr3tC0mmunity" not in markdown
    assert "SuperSecret123" not in markdown
    assert document.redacted is True
    assert document.sanitization_status == "redacted"
    assert "masked" in document.redaction_note


def test_stored_evidence_file_is_never_modified_by_redaction(tmp_path: Path) -> None:
    """The whole point: the capture stays intact and hash-verifiable."""
    ws, finding_id, evidence_file = _workspace_with_secret_evidence(tmp_path)
    before = sha256_file(evidence_file)
    PocBuilder(ws, redactor=Redactor()).build(finding_id).to_markdown()
    assert evidence_file.read_text(encoding="utf-8") == SECRETS
    assert sha256_file(evidence_file) == before
    assert verify_evidence(ws.load_evidence()).is_intact is True


def test_unredacted_export_says_so(tmp_path: Path) -> None:
    ws, finding_id, _ = _workspace_with_secret_evidence(tmp_path)
    document = PocBuilder(ws, redactor=None).build(finding_id)
    assert document.redacted is False
    assert document.sanitization_status == "unsanitized"
    assert "NOT applied" in document.redaction_note
    assert "S3cr3tC0mmunity" in document.to_markdown()  # raw, as requested


def test_cli_redacts_by_default(tmp_path: Path, capsys) -> None:
    ws, finding_id, _ = _workspace_with_secret_evidence(tmp_path)
    capsys.readouterr()
    assert main(["poc", "export", "--base", str(tmp_path), "--engagement", "e1",
                 "--finding", finding_id]) == 0
    assert "redaction applied" in capsys.readouterr().out
    written = list((ws.root / "reports" / "poc").glob("*.md"))
    assert len(written) == 1, written
    assert "S3cr3tC0mmunity" not in written[0].read_text(encoding="utf-8")


def test_cli_no_redact_warns(tmp_path: Path, capsys) -> None:
    _, finding_id, _ = _workspace_with_secret_evidence(tmp_path)
    capsys.readouterr()
    assert main(["poc", "export", "--base", str(tmp_path), "--engagement", "e1",
                 "--finding", finding_id, "--no-redact"]) == 0
    assert "NOT APPLIED" in capsys.readouterr().out


# --- integrity verification ------------------------------------------------

def test_intact_evidence_verifies(tmp_path: Path) -> None:
    ws, _, _ = _workspace_with_secret_evidence(tmp_path)
    report = verify_evidence(ws.load_evidence())
    assert report.is_intact is True
    assert len(report.of_status(IntegrityStatus.VERIFIED)) == 1


def test_modified_evidence_is_detected(tmp_path: Path) -> None:
    ws, _, evidence_file = _workspace_with_secret_evidence(tmp_path)
    evidence_file.write_text(SECRETS + "\ntampered", encoding="utf-8")
    report = verify_evidence(ws.load_evidence())
    assert report.is_intact is False
    modified = report.of_status(IntegrityStatus.MODIFIED)
    assert len(modified) == 1
    assert modified[0].recorded_sha256 != modified[0].computed_sha256


def test_missing_evidence_is_detected(tmp_path: Path) -> None:
    ws, _, evidence_file = _workspace_with_secret_evidence(tmp_path)
    evidence_file.unlink()
    report = verify_evidence(ws.load_evidence())
    assert report.is_intact is False
    assert len(report.of_status(IntegrityStatus.MISSING)) == 1


def test_evidence_without_stored_file_is_not_recorded(tmp_path: Path) -> None:
    ws = EngagementWorkspace.create(tmp_path / "e1", Engagement(engagement_id="e1"))
    ws.append_evidence(Evidence(
        evidence_id="ev-none", finding_id="f", engagement_id="e1", asset_id="a",
        adapter="manual", tool_name="manual",
    ).to_dict())
    report = verify_evidence(ws.load_evidence())
    assert len(report.of_status(IntegrityStatus.NOT_RECORDED)) == 1
    assert report.is_intact is True  # nothing claimed, nothing broken


def test_cli_evidence_verify_fails_closed_on_tampering(tmp_path: Path, capsys) -> None:
    _, _, evidence_file = _workspace_with_secret_evidence(tmp_path)
    evidence_file.write_text("replaced", encoding="utf-8")
    capsys.readouterr()
    rc = main(["evidence", "verify", "--base", str(tmp_path), "--engagement", "e1"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "MODIFIED" in out
    assert "Chain of custody is broken" in out
