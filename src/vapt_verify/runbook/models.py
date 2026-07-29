"""Runbook data model.

A runbook is the operator-facing form of a verification plan: instead of prose
("retrieve the certificate using SNI"), it carries the **exact argument array**
the adapter would execute, the file the output must land in, and what the
operator should look for in that output.

Two invariants shape this model:

* **Nothing is dropped.** Every finding produces exactly one
  :class:`RunbookEntry`. An entry that has no runnable command carries at least
  one :class:`RunbookManualTask` instead -- never nothing.
* **A command is text, not an execution.** Generating a command does not run
  it, so scope does not *gate* generation. It does *label* it: every command
  records its scope status, and the renderers comment out anything the
  engagement has not authorised.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vapt_verify import __version__


class CommandStatus(Enum):
    """Whether a generated command is safe and authorised to run as written."""

    #: Target is inside the engagement's approved scope. Run it.
    READY = "ready"
    #: The engagement declares no scope at all, so nothing can be confirmed as
    #: authorised. The command is still emitted -- an unconfigured workspace
    #: must not silently produce an empty runbook -- but the operator has to
    #: confirm authorisation before running it.
    SCOPE_UNCONFIRMED = "scope_unconfirmed"
    #: The engagement declares a scope and this target is outside it. The
    #: command is emitted commented-out so the authorisation signal survives.
    OUT_OF_SCOPE = "out_of_scope"
    #: The target is not a valid IP or hostname (e.g. a mangled scanner field).
    #: No command is generated; it becomes a manual task instead.
    UNSAFE_TARGET = "unsafe_target"
    #: The finding carries no usable port, so a port-specific probe cannot be
    #: addressed. Host-level findings normally land here.
    NO_TARGET_PORT = "no_target_port"


@dataclass
class RunbookCommand:
    """One command the operator runs by hand, and where its output goes."""

    step_id: str
    finding_id: str
    asset_id: str
    adapter: str
    tool: str
    description: str
    argv: list[str]
    target: str
    port: int
    transport: str
    output_file: str
    status: CommandStatus
    scope_reason: str = ""
    safety_class: str = ""
    optional: bool = False
    timeout: int = 120
    #: True when the adapter wants stdin closed immediately (openssl s_client).
    stdin_empty: bool = False
    #: Whether the tool was found on the machine that *generated* the runbook.
    #: Advisory only: runbooks are routinely generated on Windows and run on
    #: Kali, so a missing tool here never suppresses a command.
    tool_present_locally: bool = False
    params: dict[str, Any] = field(default_factory=dict)
    look_for: list[str] = field(default_factory=list)

    @property
    def runnable(self) -> bool:
        """Whether the renderers emit this command in active (uncommented) form."""
        return self.status in {CommandStatus.READY, CommandStatus.SCOPE_UNCONFIRMED}

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "adapter": self.adapter,
            "tool": self.tool,
            "description": self.description,
            "argv": list(self.argv),
            "target": self.target,
            "port": self.port,
            "transport": self.transport,
            "output_file": self.output_file,
            "status": self.status.value,
            "scope_reason": self.scope_reason,
            "safety_class": self.safety_class,
            "optional": self.optional,
            "timeout": self.timeout,
            "stdin_empty": self.stdin_empty,
            "tool_present_locally": self.tool_present_locally,
            "params": dict(self.params),
            "look_for": list(self.look_for),
            "runnable": self.runnable,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunbookCommand:
        return cls(
            step_id=data["step_id"],
            finding_id=data["finding_id"],
            asset_id=data.get("asset_id", ""),
            adapter=data.get("adapter", ""),
            tool=data.get("tool", ""),
            description=data.get("description", ""),
            argv=list(data.get("argv", [])),
            target=data.get("target", ""),
            port=int(data.get("port", 0)),
            transport=data.get("transport", "tcp"),
            output_file=data.get("output_file", ""),
            status=CommandStatus(data.get("status", "ready")),
            scope_reason=data.get("scope_reason", ""),
            safety_class=data.get("safety_class", ""),
            optional=bool(data.get("optional", False)),
            timeout=int(data.get("timeout", 120)),
            stdin_empty=bool(data.get("stdin_empty", False)),
            tool_present_locally=bool(data.get("tool_present_locally", False)),
            params=dict(data.get("params", {})),
            look_for=list(data.get("look_for", [])),
        )


@dataclass
class RunbookManualTask:
    """Evidence a human must obtain; no command can stand in for it."""

    task_id: str
    finding_id: str
    asset_id: str
    adapter: str
    instruction: str
    reason: str = ""
    #: Where the operator should save whatever they collect, so that
    #: ``evidence import`` picks it up alongside command output.
    output_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "adapter": self.adapter,
            "instruction": self.instruction,
            "reason": self.reason,
            "output_file": self.output_file,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunbookManualTask:
        return cls(
            task_id=data["task_id"],
            finding_id=data["finding_id"],
            asset_id=data.get("asset_id", ""),
            adapter=data.get("adapter", ""),
            instruction=data.get("instruction", ""),
            reason=data.get("reason", ""),
            output_file=data.get("output_file", ""),
        )


@dataclass
class RunbookEntry:
    """Everything the operator needs for one finding."""

    finding_id: str
    asset_id: str
    plugin_id: str
    plugin_name: str
    severity: str
    target: str
    port: int
    transport: str
    service: str
    recipe_id: str
    recipe_title: str
    disposition: str
    nmap_role: str
    objective: str
    commands: list[RunbookCommand] = field(default_factory=list)
    manual_tasks: list[RunbookManualTask] = field(default_factory=list)
    confirming_evidence: list[str] = field(default_factory=list)
    refuting_evidence: list[str] = field(default_factory=list)
    inconclusive_conditions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    sni_requirements: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def has_runnable_command(self) -> bool:
        return any(c.runnable for c in self.commands)

    @property
    def is_accounted_for(self) -> bool:
        """The per-finding half of the no-finding-disappears guarantee.

        An entry is accounted for when it gives the operator *something* to do:
        a command, or an explicit manual evidence task. An entry with neither
        would be a silently dropped finding.
        """
        return bool(self.commands) or bool(self.manual_tasks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "severity": self.severity,
            "target": self.target,
            "port": self.port,
            "transport": self.transport,
            "service": self.service,
            "recipe_id": self.recipe_id,
            "recipe_title": self.recipe_title,
            "disposition": self.disposition,
            "nmap_role": self.nmap_role,
            "objective": self.objective,
            "commands": [c.to_dict() for c in self.commands],
            "manual_tasks": [t.to_dict() for t in self.manual_tasks],
            "confirming_evidence": list(self.confirming_evidence),
            "refuting_evidence": list(self.refuting_evidence),
            "inconclusive_conditions": list(self.inconclusive_conditions),
            "limitations": list(self.limitations),
            "sni_requirements": list(self.sni_requirements),
            "notes": list(self.notes),
            "has_runnable_command": self.has_runnable_command,
            "is_accounted_for": self.is_accounted_for,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunbookEntry:
        return cls(
            finding_id=data["finding_id"],
            asset_id=data.get("asset_id", ""),
            plugin_id=data.get("plugin_id", ""),
            plugin_name=data.get("plugin_name", ""),
            severity=data.get("severity", ""),
            target=data.get("target", ""),
            port=int(data.get("port", 0)),
            transport=data.get("transport", "tcp"),
            service=data.get("service", ""),
            recipe_id=data.get("recipe_id", ""),
            recipe_title=data.get("recipe_title", ""),
            disposition=data.get("disposition", ""),
            nmap_role=data.get("nmap_role", ""),
            objective=data.get("objective", ""),
            commands=[RunbookCommand.from_dict(c) for c in data.get("commands", [])],
            manual_tasks=[RunbookManualTask.from_dict(t) for t in data.get("manual_tasks", [])],
            confirming_evidence=list(data.get("confirming_evidence", [])),
            refuting_evidence=list(data.get("refuting_evidence", [])),
            inconclusive_conditions=list(data.get("inconclusive_conditions", [])),
            limitations=list(data.get("limitations", [])),
            sni_requirements=list(data.get("sni_requirements", [])),
            notes=list(data.get("notes", [])),
        )


@dataclass
class RunbookCoverage:
    """Does the runbook account for every finding it was asked to cover?"""

    findings_considered: int
    entries: int
    with_runnable_command: int
    manual_only: int
    unaccounted: list[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Fail-closed check, mirroring the import reconciliation gate."""
        return (
            self.entries == self.findings_considered
            and not self.unaccounted
            and self.with_runnable_command + self.manual_only == self.entries
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings_considered": self.findings_considered,
            "entries": self.entries,
            "with_runnable_command": self.with_runnable_command,
            "manual_only": self.manual_only,
            "unaccounted": list(self.unaccounted),
            "is_complete": self.is_complete,
        }


@dataclass
class Runbook:
    """A complete manual-capture runbook for one engagement."""

    engagement_id: str
    client_alias: str = ""
    authorisation_reference: str = ""
    generated_at: str = field(default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat())
    tool_version: str = __version__
    #: Relative directory the operator's captures are written under.
    capture_dir: str = "capture"
    scope_configured: bool = False
    scope_summary: list[str] = field(default_factory=list)
    entries: list[RunbookEntry] = field(default_factory=list)

    # -- derived views ------------------------------------------------------

    @property
    def commands(self) -> list[RunbookCommand]:
        return [c for e in self.entries for c in e.commands]

    @property
    def manual_tasks(self) -> list[RunbookManualTask]:
        return [t for e in self.entries for t in e.manual_tasks]

    def required_tools(self) -> list[str]:
        return sorted({c.tool for c in self.commands if c.tool})

    def coverage(self, findings_considered: int | None = None) -> RunbookCoverage:
        considered = len(self.entries) if findings_considered is None else findings_considered
        with_cmd = sum(1 for e in self.entries if e.has_runnable_command)
        accounted = [e for e in self.entries if e.is_accounted_for]
        return RunbookCoverage(
            findings_considered=considered,
            entries=len(self.entries),
            with_runnable_command=with_cmd,
            manual_only=len(accounted) - with_cmd,
            unaccounted=[e.finding_id for e in self.entries if not e.is_accounted_for],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "vapt-verify/runbook/1",
            "engagement_id": self.engagement_id,
            "client_alias": self.client_alias,
            "authorisation_reference": self.authorisation_reference,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "capture_dir": self.capture_dir,
            "scope_configured": self.scope_configured,
            "scope_summary": list(self.scope_summary),
            "coverage": self.coverage().to_dict(),
            "required_tools": self.required_tools(),
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Runbook:
        return cls(
            engagement_id=data.get("engagement_id", ""),
            client_alias=data.get("client_alias", ""),
            authorisation_reference=data.get("authorisation_reference", ""),
            generated_at=data.get("generated_at", ""),
            tool_version=data.get("tool_version", ""),
            capture_dir=data.get("capture_dir", "capture"),
            scope_configured=bool(data.get("scope_configured", False)),
            scope_summary=list(data.get("scope_summary", [])),
            entries=[RunbookEntry.from_dict(e) for e in data.get("entries", [])],
        )
