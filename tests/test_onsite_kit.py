"""Windows-to-Kali validation-kit workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shell_probe import posix_shell
from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.kit import (
    SCOPE_IN_SCOPE,
    SCOPE_OUT_OF_SCOPE,
    SCOPE_UNCONFIGURED,
    SCOPE_UNUSABLE_TARGET,
    OnsiteEvidenceImporter,
    OnsiteKitBuilder,
)
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation import reconcile
from vapt_verify.reporting.poc import PocBuilder
from vapt_verify.utilities.hashing import sha256_file
from vapt_verify.workspace import EngagementWorkspace

SAMPLE = Path(__file__).parent / "fixtures" / "sample_small.nessus"


def _workspace(
    tmp_path: Path,
    engagement: Engagement | None = None,
    source: Path = SAMPLE,
) -> EngagementWorkspace:
    engagement = engagement or Engagement(engagement_id="e1")
    ws = EngagementWorkspace.create(tmp_path / engagement.engagement_id, engagement)
    result = NessusImporter(engagement_id=engagement.engagement_id).import_file(source)
    ws.persist_import(source_path=source, result=result, reconciliation=reconcile(result))
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


def test_prepare_no_kit_imports_without_generating_a_kit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The report-only path: findings without a Kali machine in the loop.

    `--no-kit` must still produce a fully imported, readable engagement --
    the kit is the only thing it skips. If the import were skipped too there
    would be nothing to report on, and the flag would just be a slower way of
    creating an empty directory.
    """
    base = tmp_path / "engagements"
    kit = tmp_path / "client-kali-kit"
    rc = main(
        ["prepare", str(SAMPLE), "--base", str(base), "--engagement", "client1",
         "--output", str(kit), "--no-kit"]
    )
    assert rc == 0

    # imported and readable ...
    assert (base / "client1" / "engagement.yaml").exists()
    assert list((base / "client1" / "normalized").glob("*.jsonl"))
    # ... but nothing was generated to carry to Kali.
    assert not kit.exists()
    assert not (base / "client1" / "kali-kit").exists()

    out = capsys.readouterr().out
    assert "poc export" in out, "the report-only path must say where to go next"


def test_prepare_no_kit_does_not_claim_a_poc_is_a_proof(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Skipping verification must not quietly downgrade what a PoC asserts.

    An operator who never runs a kit still gets PoC documents, and the one
    thing they must not conclude is that those documents prove anything. The
    export already labels them; `prepare` has to say so at the point the
    decision is made, not leave it to be discovered in the deliverable.
    """
    base = tmp_path / "engagements"
    main(
        ["prepare", str(SAMPLE), "--base", str(base), "--engagement", "client1", "--no-kit"]
    )
    out = capsys.readouterr().out.lower()
    assert "evidence request" in out
    assert "not a proof" in out


def test_prepare_creates_nothing_when_an_input_is_unusable(tmp_path: Path) -> None:
    """A failed prepare must not become the obstacle to the next one.

    prepare used to create the engagement and *then* validate the scan file,
    so pointing it at a directory left a half-built engagement behind. The
    retry -- with a correct path -- was then refused with "already exists",
    and the advice given was to run `kit build`, which had nothing to build
    from. One typo cost an engagement id.
    """
    base = tmp_path / "engagements"
    empty = tmp_path / "no-scans-here"
    empty.mkdir()

    rc = main(["prepare", str(empty), "--base", str(base), "--engagement", "acme", "--no-kit"])
    assert rc != 0
    assert not base.exists(), "a failed prepare left an engagement behind"

    # The whole point: the same id is still usable.
    rc = main(["prepare", str(SAMPLE), "--base", str(base), "--engagement", "acme", "--no-kit"])
    assert rc == 0
    assert (base / "acme" / "engagement.yaml").exists()


def test_prepare_reports_every_bad_input_not_just_the_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Eight paths, two mistyped: learn about both now, not one per run."""
    base = tmp_path / "engagements"
    rc = main(
        ["prepare", str(tmp_path / "nope.nessus"), str(SAMPLE), str(tmp_path / "gone.nessus"),
         "--base", str(base), "--engagement", "acme", "--no-kit"]
    )
    assert rc != 0
    out = capsys.readouterr().out
    assert "nope.nessus" in out
    assert "gone.nessus" in out
    assert not base.exists()


def test_prepare_imports_a_whole_directory_into_one_engagement(tmp_path: Path) -> None:
    """A client assessment arrives as a folder of per-system exports.

    Importing them one command at a time is how one silently gets missed, so
    a directory is a valid input and every scan in it lands in the same
    engagement -- one coverage view for the client, not eight.
    """
    scans = tmp_path / "scans"
    scans.mkdir()
    for name in ("b2b", "ddmf", "eft"):
        (scans / (name + ".nessus")).write_bytes(SAMPLE.read_bytes())
    # A non-scan file in the same folder must be ignored, not fail the run.
    (scans / "notes.txt").write_text("client notes", encoding="utf-8")

    base = tmp_path / "engagements"
    rc = main(["prepare", str(scans), "--base", str(base), "--engagement", "acme", "--no-kit"])
    assert rc == 0

    manifests = list((base / "acme" / "imports" / "manifests").glob("*.json"))
    assert len(manifests) == 3, "every scan in the directory should be imported once"


def test_prepare_does_not_import_the_same_file_twice(tmp_path: Path) -> None:
    """Naming a file and the folder holding it is one scan, not two.

    Without this, a double import inflates every count the coverage report
    totals back to, and `coverage` is the metric an operator trusts to prove
    nothing was dropped.
    """
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "b2b.nessus").write_bytes(SAMPLE.read_bytes())

    base = tmp_path / "engagements"
    rc = main(
        ["prepare", str(scans), str(scans / "b2b.nessus"),
         "--base", str(base), "--engagement", "acme", "--no-kit"]
    )
    assert rc == 0
    manifests = list((base / "acme" / "imports" / "manifests").glob("*.json"))
    assert len(manifests) == 1


def test_import_accepts_a_directory_like_prepare_does(tmp_path: Path) -> None:
    """The command that adds a scan should not be fussier than the one that
    created the engagement."""
    scans = tmp_path / "more"
    scans.mkdir()
    for name in ("extra1", "extra2"):
        (scans / (name + ".nessus")).write_bytes(SAMPLE.read_bytes())

    base = tmp_path / "engagements"
    assert main(
        ["prepare", str(SAMPLE), "--base", str(base), "--engagement", "acme", "--no-kit"]
    ) == 0
    assert main(["import", str(scans), "--base", str(base), "--engagement", "acme"]) == 0

    manifests = list((base / "acme" / "imports" / "manifests").glob("*.json"))
    assert len(manifests) == 3, "one from prepare, two from the directory import"


def test_kit_script_names_are_readable_not_hashes(tmp_path: Path) -> None:
    """`find-37c3608975b2529abc91d78b__01_openssl.sh` tells an operator nothing.

    Scrolling `scripts/` should show what each script checks and how badly it
    matters. The finding id lives inside the file, which is what the import
    matches on, so readability costs no traceability.
    """
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    OnsiteKitBuilder(ws).build(kit)

    names = sorted(p.name for p in (kit / "scripts").glob("*.sh"))
    assert names
    for name in names:
        assert not name.startswith("find-"), name
        assert name.split("-")[0] in {"1", "2", "3", "4", "5"}, name
    assert any("SSL-Certificate-Cannot-Be-Trusted" in n for n in names)
    # Worst-first when the directory is listed.
    assert names == sorted(names)
    # Traceability is preserved inside the script.
    for script in (kit / "scripts").glob("*.sh"):
        assert "VAPT_FINDING_ID=find-" in script.read_text(encoding="utf-8")


def test_kit_does_not_scan_informational_findings_but_still_lists_them(
    tmp_path: Path,
) -> None:
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    OnsiteKitBuilder(ws).build(kit)

    manifest = json.loads((kit / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["retained_informational_count"] >= 1
    retained_ids = {r["finding_id"] for r in manifest["retained_informational"]}
    assert retained_ids
    # No step -- and so no script -- is generated for them...
    assert not [s for s in manifest["steps"] if s["finding_id"] in retained_ids]
    for script in (kit / "scripts").glob("*.sh"):
        assert not script.name.startswith("5-INFORMATIONAL"), script.name
    # ...but the operator is told they exist and why they were not scanned.
    commands = (kit / "commands.md").read_text(encoding="utf-8")
    assert "Retained, not scanned" in commands
    for row in manifest["retained_informational"]:
        assert row["title"] in commands
    assert "still require a disposition" in commands
    assert "informational finding(s)" in (kit / "README.md").read_text(encoding="utf-8")


def test_kit_include_informational_generates_their_scripts(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    OnsiteKitBuilder(ws).build(kit, include_informational=True)

    manifest = json.loads((kit / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["retained_informational_count"] == 0
    assert [s for s in manifest["steps"] if s["severity"] == "INFORMATIONAL"]


# --- scope labels a step; it never deletes one -------------------------------
#
# Ported from the runbook generator, which was the only one enforcing these.
# The kit is prepared on a machine that never touches a target, so scope cannot
# gate generation the way it gates execution -- it labels each step, and the
# generated script refuses to run anything explicitly out of scope.


def _scoped(tmp_path: Path, cidr: str, engagement_id: str) -> EngagementWorkspace:
    return _workspace(
        tmp_path,
        Engagement(
            engagement_id=engagement_id,
            approved_cidrs=[cidr],
            authorisation_reference="AUTH-2026-001",
        ),
    )


def test_in_scope_targets_are_labelled_and_scripts_have_no_guard(tmp_path: Path) -> None:
    ws = _scoped(tmp_path, "192.0.2.0/24", "eng-scoped")
    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(ws).build(kit)

    assert result.scope_configured
    assert result.out_of_scope_count == 0
    assert result.unusable_target_count == 0
    assert all(s.scope_status == SCOPE_IN_SCOPE for s in result.steps)
    assert all(s.authorised for s in result.steps)
    for script in (kit / "scripts").glob("*.sh"):
        body = script.read_text(encoding="utf-8")
        assert f"VAPT_SCOPE_STATUS={SCOPE_IN_SCOPE}" in body
        assert "REFUSED (out of scope)" not in body


def test_unconfigured_scope_still_produces_a_usable_kit(tmp_path: Path) -> None:
    """The regression the runbook was built to avoid, now pinned on the kit.

    An engagement whose scope has not been filled in yet must still yield a kit
    an operator can run -- generating a command is not executing one. What it
    must not do is imply the tool checked authorisation when it could not.
    """
    ws = _workspace(tmp_path)
    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(ws).build(kit)

    assert not result.scope_configured
    assert result.executable_count > 0, "an unscoped engagement must still yield commands"
    assert all(s.scope_status == SCOPE_UNCONFIGURED for s in result.steps)
    assert all(s.authorised for s in result.steps)
    for script in (kit / "scripts").glob("*.sh"):
        body = script.read_text(encoding="utf-8")
        assert "cannot confirm this" in body
        assert "REFUSED (out of scope)" not in body
    commands = (kit / "commands.md").read_text(encoding="utf-8")
    assert "declares no approved scope" in commands


def test_out_of_scope_target_is_generated_labelled_and_refused_at_run_time(
    tmp_path: Path,
) -> None:
    ws = _scoped(tmp_path, "198.51.100.0/24", "eng-elsewhere")
    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(ws).build(kit)

    assert result.scope_configured
    assert result.out_of_scope_count == len(result.steps) > 0
    assert all(s.scope_status == SCOPE_OUT_OF_SCOPE for s in result.steps)
    assert not any(s.authorised for s in result.steps)

    # The command is still visible with its reason -- nothing is hidden from
    # the reviewer -- but running the script exits before the tool is invoked.
    scripts = list((kit / "scripts").glob("*.sh"))
    assert scripts
    for script in scripts:
        body = script.read_text(encoding="utf-8")
        assert f"VAPT_SCOPE_STATUS={SCOPE_OUT_OF_SCOPE}" in body
        assert "REFUSED (out of scope)" in body
        assert "VAPT_ALLOW_OUT_OF_SCOPE" in body
        assert body.index("REFUSED (out of scope)") < body.index("capture_step")
    commands = (kit / "commands.md").read_text(encoding="utf-8")
    assert "OUT OF SCOPE" in commands
    assert "openssl" in commands


def test_out_of_scope_script_exits_without_running_the_tool(tmp_path: Path) -> None:
    """Proof by execution: the guard is real bash, not a comment."""
    import subprocess

    ws = _scoped(tmp_path, "198.51.100.0/24", "eng-elsewhere")
    kit = tmp_path / "kit"
    OnsiteKitBuilder(ws).build(kit)
    script = next((kit / "scripts").glob("*.sh"))

    proc = subprocess.run(
        [posix_shell("bash"), str(script)], capture_output=True, text=True, timeout=30,
        check=False,
    )
    assert proc.returncode == 0
    assert "REFUSED (out of scope)" in proc.stdout
    assert not list((kit / "evidence").glob("*.json")), "no capture may be written"


def test_unusable_scanner_address_never_reaches_a_script(tmp_path: Path) -> None:
    """A scan field that is not an address must not be pasted into a root shell."""
    source = tmp_path / "mangled.nessus"
    source.write_text(
        """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Mangled">
    <ReportHost name="not a host; rm -rf /">
      <HostProperties>
        <tag name="host-ip">not a host; rm -rf /</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="2"
                  pluginID="51192" pluginName="SSL Certificate Cannot Be Trusted"
                  pluginFamily="General">
        <synopsis>The certificate cannot be trusted.</synopsis>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
""",
        encoding="utf-8",
    )
    ws = _workspace(tmp_path, Engagement(engagement_id="eng-mangled"), source=source)
    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(ws).build(kit)

    assert result.steps
    assert all(s.scope_status == SCOPE_UNUSABLE_TARGET for s in result.steps)
    assert result.unusable_target_count == len(result.steps)
    # No command was built, so no script exists to run.
    assert result.executable_count == 0
    assert not list((kit / "scripts").glob("*.sh"))
    assert not any("rm -rf" in arg for s in result.steps for arg in s.command_args)
    # The operator is told why, rather than the finding quietly vanishing.
    commands = (kit / "commands.md").read_text(encoding="utf-8")
    assert "NO COMMAND GENERATED" in commands
    assert "not a valid IP address or hostname" in commands


def test_scope_labels_reach_the_manifest(tmp_path: Path) -> None:
    ws = _scoped(tmp_path, "198.51.100.0/24", "eng-elsewhere")
    kit = tmp_path / "kit"
    OnsiteKitBuilder(ws).build(kit)

    manifest = json.loads((kit / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["scope_configured"] is True
    assert manifest["out_of_scope_step_count"] == len(manifest["steps"])
    for step in manifest["steps"]:
        assert step["scope_status"] == SCOPE_OUT_OF_SCOPE
        assert step["authorised"] is False
        assert step["scope_reason"]
