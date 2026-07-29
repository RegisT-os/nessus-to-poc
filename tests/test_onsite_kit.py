"""Windows-to-Kali validation-kit workflow."""

from __future__ import annotations

import json
from pathlib import Path

from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.kit import OnsiteEvidenceImporter, OnsiteKitBuilder
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation import reconcile
from vapt_verify.reporting.poc import PocBuilder
from vapt_verify.utilities.hashing import sha256_file
from vapt_verify.workspace import EngagementWorkspace

SAMPLE = Path(__file__).parent / "fixtures" / "sample_small.nessus"


def _workspace(tmp_path: Path) -> EngagementWorkspace:
    ws = EngagementWorkspace.create(tmp_path / "e1", Engagement(engagement_id="e1"))
    result = NessusImporter(engagement_id="e1").import_file(SAMPLE)
    ws.persist_import(source_path=SAMPLE, result=result, reconciliation=reconcile(result))
    return ws


def test_kit_builds_kali_scripts_for_every_finding(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(ws).build(kit)

    manifest = json.loads((kit / "manifest.json").read_text(encoding="utf-8"))
    assert result.finding_count == 6
    assert manifest["finding_count"] == 6
    assert result.executable_count > 0
    assert (kit / "run-all.sh").exists()
    assert (kit / "commands.md").exists()

    scripts = list((kit / "scripts").glob("*.sh"))
    assert len(scripts) == result.executable_count
    for script in [kit / "run-all.sh", kit / "lib" / "capture.sh", *scripts]:
        raw = script.read_bytes()
        assert raw.startswith(b"#!/usr/bin/env bash\n")
        assert b"\r\n" not in raw
        assert b"powershell" not in raw.lower()


def test_kit_uses_protocol_tools_and_keeps_patch_finding_manual(tmp_path: Path) -> None:
    result = OnsiteKitBuilder(_workspace(tmp_path)).build(tmp_path / "kit")

    tls = [s for s in result.steps if s.plugin_id == "51192" and s.executable]
    assert any(s.command_args[0] == "openssl" for s in tls)
    assert any(s.command_args[0] == "nmap" and "ssl-cert" in s.command_args for s in tls)

    ssh = [s for s in result.steps if s.plugin_id == "90317" and s.executable]
    assert any(s.command_args[0] == "ssh-audit" for s in ssh)
    assert any("ssh2-enum-algos" in s.command_args for s in ssh)

    patch = [s for s in result.steps if s.plugin_id == "123456"]
    assert patch
    assert all(not s.executable for s in patch)
    assert all(s.adapter != "nmap" for s in patch)
    assert any("dpkg-query" in s.description for s in patch)

    snmp = [s for s in result.steps if s.plugin_id == "41028" and s.executable]
    assert len(snmp) == 1
    assert "public" in snmp[0].command_args


def test_force_refresh_preserves_evidence_and_removes_stale_scripts(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    OnsiteKitBuilder(ws).build(kit)
    evidence = kit / "evidence" / "keep.txt"
    evidence.write_text("captured", encoding="utf-8")
    stale = kit / "scripts" / "stale.sh"
    stale.write_text("old", encoding="utf-8")

    OnsiteKitBuilder(ws).build(kit, force=True)
    assert evidence.read_text(encoding="utf-8") == "captured"
    assert not stale.exists()


def test_returned_kali_capture_imports_and_feeds_poc(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    built = OnsiteKitBuilder(ws).build(kit)
    step = next(s for s in built.steps if s.plugin_id == "51192" and s.adapter == "openssl")

    output = kit / "evidence" / "capture-1.txt"
    output.write_text(
        "CONNECTION ESTABLISHED\nVerification error: self-signed certificate\n",
        encoding="utf-8",
    )
    metadata = {
        "kit_schema_version": "1",
        "capture_id": "capture-1",
        "step_id": step.step_id,
        "finding_id": step.finding_id,
        "asset_id": step.asset_id,
        "adapter": step.adapter,
        "tool_name": step.tool,
        "tool_version": "OpenSSL test",
        "target": step.target,
        "port": step.port,
        "transport": step.transport,
        "operator": "kali-user",
        "start_timestamp": "2026-07-29T01:00:00Z",
        "end_timestamp": "2026-07-29T01:00:01Z",
        "exit_code": 0,
        "timed_out": False,
        "command_args": step.command_args,
        "output_file": "evidence/capture-1.txt",
        "sha256": sha256_file(output),
    }
    (kit / "evidence" / "capture-1.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )

    summary = OnsiteEvidenceImporter(ws).import_kit(kit)
    assert summary.imported == 1
    assert not summary.errors
    evidence = ws.load_evidence()[0]
    assert evidence["operator"] == "kali-user"
    assert evidence["parsed_observations"]["connected"] is True

    document = PocBuilder(ws).build(step.finding_id)
    assert document is not None
    assert document.has_evidence
    assert "CONNECTION ESTABLISHED" in document.to_markdown()

    duplicate = OnsiteEvidenceImporter(ws).import_kit(kit)
    assert duplicate.imported == 0
    assert duplicate.skipped_duplicates == 1


def test_import_rejects_tampered_capture(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    built = OnsiteKitBuilder(ws).build(kit)
    step = next(s for s in built.steps if s.executable)
    output = kit / "evidence" / "tampered.txt"
    output.write_text("changed", encoding="utf-8")
    metadata = {
        "kit_schema_version": "1",
        "capture_id": "capture-tampered",
        "step_id": step.step_id,
        "finding_id": step.finding_id,
        "asset_id": step.asset_id,
        "adapter": step.adapter,
        "output_file": "evidence/tampered.txt",
        "sha256": "0" * 64,
        "command_args": step.command_args,
    }
    (kit / "evidence" / "tampered.json").write_text(json.dumps(metadata), encoding="utf-8")
    summary = OnsiteEvidenceImporter(ws).import_kit(kit)
    assert summary.imported == 0
    assert any("SHA-256" in error for error in summary.errors)


def test_prepare_is_the_simple_one_command_entry_point(tmp_path: Path) -> None:
    base = tmp_path / "engagements"
    kit = tmp_path / "client-kali-kit"
    rc = main(
        [
            "prepare",
            str(SAMPLE),
            "--base",
            str(base),
            "--engagement",
            "client1",
            "--output",
            str(kit),
        ]
    )
    assert rc == 0
    assert (base / "client1" / "engagement.yaml").exists()
    assert (kit / "run-all.sh").exists()
