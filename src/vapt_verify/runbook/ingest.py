"""Import manually captured tool output back into the workspace.

This closes the loop the runbook opens. The operator runs the commands
somewhere the targets are reachable; this reads what came back, parses it with
the *same adapter that generated the command*, and records it as evidence with
a hash, so a manual capture is exactly as reviewable and as verifiable as one
``run`` produced itself.

Deliberate properties:

* **The captured file is never modified.** It is copied into the workspace and
  hashed; the copy is what the integrity checker later re-verifies.
* **Re-import is idempotent.** A capture already recorded under the same digest
  for the same step is skipped, not duplicated, so an operator can re-run
  ``evidence import`` after capturing a few more steps.
* **Nothing missing is glossed over.** Steps with no capture file are reported
  as outstanding, and a skipped step (tool absent on the operator's machine) is
  reported as a capability gap -- never as evidence of absence.
* **No verdict is set here.** The adapter's parse yields observations and at
  most a *suggested* verdict; the reviewer still decides.
"""

from __future__ import annotations

import datetime as _dt
import re
import shutil
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from vapt_verify.adapters import get_adapter
from vapt_verify.adapters.base import ExecutionContext, RawResult
from vapt_verify.models.evidence import Evidence
from vapt_verify.runbook.models import Runbook, RunbookCommand
from vapt_verify.utilities.hashing import sha256_file

_EXIT_RE = re.compile(r"^# exit_code:\s*(\S+)\s*$", re.MULTILINE)
_HEADER_RE = re.compile(r"^# (step|command|started|finished|exit_code):.*$", re.MULTILINE)


class IngestStatus(Enum):
    IMPORTED = "imported"
    #: Already recorded with the same digest; re-importing changes nothing.
    ALREADY_IMPORTED = "already_imported"
    #: The operator has not captured this step yet.
    NOT_CAPTURED = "not_captured"
    #: The tool was not installed on the operator's machine. A capability gap,
    #: not evidence that the condition is absent.
    TOOL_SKIPPED = "tool_skipped"
    #: The capture file exists but is empty.
    EMPTY_CAPTURE = "empty_capture"


@dataclass
class IngestItem:
    step_id: str
    finding_id: str
    adapter: str
    status: IngestStatus
    source_path: str = ""
    stored_path: str = ""
    evidence_id: str = ""
    sha256: str = ""
    exit_code: int | None = None
    suggested_verdict: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "finding_id": self.finding_id,
            "adapter": self.adapter,
            "status": self.status.value,
            "source_path": self.source_path,
            "stored_path": self.stored_path,
            "evidence_id": self.evidence_id,
            "sha256": self.sha256,
            "exit_code": self.exit_code,
            "suggested_verdict": self.suggested_verdict,
            "note": self.note,
        }


@dataclass
class IngestReport:
    items: list[IngestItem] = field(default_factory=list)
    #: Findings that still have no evidence of any kind after this import.
    findings_without_evidence: list[str] = field(default_factory=list)
    #: Manual tasks whose evidence file the operator has not supplied.
    outstanding_manual_tasks: list[str] = field(default_factory=list)

    def of_status(self, status: IngestStatus) -> list[IngestItem]:
        return [i for i in self.items if i.status is status]

    @property
    def counts(self) -> dict[str, int]:
        return {s.value: len(self.of_status(s)) for s in IngestStatus}

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts,
            "items": [i.to_dict() for i in self.items],
            "findings_without_evidence": list(self.findings_without_evidence),
            "outstanding_manual_tasks": list(self.outstanding_manual_tasks),
        }


def split_capture(text: str) -> tuple[str, int | None]:
    """Separate the wrapper the runbook script writes from the tool's own output.

    The script frames each capture with ``# step:``/``# command:``/``# exit_code:``
    lines. Those are metadata, not tool output, and must not reach the parser --
    a ``# command:`` line quoting ``-brief`` should never be mistaken for a
    handshake. A hand-saved file with no wrapper passes through unchanged.
    """
    exit_match = _EXIT_RE.search(text)
    exit_code: int | None = None
    if exit_match:
        try:
            exit_code = int(exit_match.group(1))
        except ValueError:
            exit_code = None
    body = _HEADER_RE.sub("", text).strip("\n")
    return body, exit_code


class RunbookIngestor:
    """Reads captures listed in a runbook manifest into workspace evidence."""

    def __init__(self, workspace: Any, *, operator: str = "unknown") -> None:
        self.ws = workspace
        self.operator = operator

    def ingest(
        self,
        *,
        runbook: Runbook,
        capture_dir: Path,
        engagement_id: str,
    ) -> IngestReport:
        existing = self.ws.load_evidence()
        seen = {
            (e.get("parsed_observations", {}) or {}).get("runbook_step_id", ""): e
            for e in existing
        }
        seen_digests = {e.get("sha256", "") for e in existing}
        report = IngestReport()

        for entry in runbook.entries:
            for command in entry.commands:
                report.items.append(
                    self._ingest_command(
                        command=command,
                        capture_dir=capture_dir,
                        engagement_id=engagement_id,
                        seen=seen,
                        seen_digests=seen_digests,
                    )
                )
            for task in entry.manual_tasks:
                if not task.output_file:
                    continue
                path = capture_dir / task.output_file
                if not path.exists():
                    report.outstanding_manual_tasks.append(
                        f"{task.finding_id}: {task.instruction}"
                    )

        # Which findings STILL have nothing? Reported explicitly, because an
        # import that quietly leaves findings bare is how evidence gaps hide.
        with_evidence = {e.get("finding_id") for e in self.ws.load_evidence()}
        report.findings_without_evidence = [
            e.finding_id for e in runbook.entries if e.finding_id not in with_evidence
        ]
        return report

    # -- one command --------------------------------------------------------

    def _ingest_command(
        self,
        *,
        command: RunbookCommand,
        capture_dir: Path,
        engagement_id: str,
        seen: dict[str, dict[str, Any]],
        seen_digests: set[str],
    ) -> IngestItem:
        skipped = capture_dir / f"{command.output_file}.skipped"
        path = capture_dir / command.output_file
        if not path.exists():
            if skipped.exists():
                return IngestItem(
                    step_id=command.step_id,
                    finding_id=command.finding_id,
                    adapter=command.adapter,
                    status=IngestStatus.TOOL_SKIPPED,
                    source_path=str(skipped),
                    note=(
                        f"'{command.tool}' was not installed where the runbook ran. This is a "
                        "capability gap; it is not evidence that the condition is absent."
                    ),
                )
            return IngestItem(
                step_id=command.step_id,
                finding_id=command.finding_id,
                adapter=command.adapter,
                status=IngestStatus.NOT_CAPTURED,
                source_path=str(path),
                note="No capture file yet for this step.",
            )

        # utf-8-sig, not utf-8: PowerShell's Out-File writes a BOM, and a BOM
        # glued to the first "# step:" line would defeat the header stripper.
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        body, exit_code = split_capture(text)
        if not body.strip():
            return IngestItem(
                step_id=command.step_id,
                finding_id=command.finding_id,
                adapter=command.adapter,
                status=IngestStatus.EMPTY_CAPTURE,
                source_path=str(path),
                note=(
                    "The capture file is empty. An empty capture is not a result: re-run the "
                    "step, or record why it produced nothing."
                ),
            )

        digest = sha256_file(path)
        if digest in seen_digests and command.step_id in seen:
            return IngestItem(
                step_id=command.step_id,
                finding_id=command.finding_id,
                adapter=command.adapter,
                status=IngestStatus.ALREADY_IMPORTED,
                source_path=str(path),
                sha256=digest,
                evidence_id=str(seen[command.step_id].get("evidence_id", "")),
                note="Identical capture already imported; nothing changed.",
            )

        adapter = get_adapter(command.adapter)
        ctx = ExecutionContext(
            finding_id=command.finding_id,
            asset_id=command.asset_id,
            engagement_id=engagement_id,
            target=command.target,
            port=command.port,
            transport=command.transport,
            params=dict(command.params),
            operator=self.operator,
            timeout=float(command.timeout),
        )
        if adapter is not None:
            parsed = adapter.parse(ctx, RawResult(exit_code=exit_code, stdout=body))
            observations = dict(parsed.observations)
            suggested = parsed.suggested_verdict.value if parsed.suggested_verdict else None
            note = parsed.note
        else:
            observations = {}
            suggested = None
            note = f"No adapter named '{command.adapter}' is registered; output stored verbatim."

        observations["runbook_step_id"] = command.step_id
        observations["capture_source"] = "manual_runbook_capture"

        evidence_id = uuid.uuid4().hex
        dest_dir = Path(self.ws.evidence_dir) / _safe(command.asset_id) / _safe(command.finding_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%S_%f")
        dest = dest_dir / f"{stamp}_runbook_{command.adapter}_{evidence_id[:8]}.txt"
        shutil.copy2(path, dest)

        evidence = Evidence(
            evidence_id=evidence_id,
            finding_id=command.finding_id,
            engagement_id=engagement_id,
            asset_id=command.asset_id,
            adapter=command.adapter,
            tool_name=command.tool,
            command_args=list(command.argv),
            sanitized_command=" ".join(command.argv),
            operator=self.operator,
            start_timestamp=_extract(text, "# started:"),
            end_timestamp=_extract(text, "# finished:"),
            exit_code=exit_code,
            stdout=body[:20000],
            parsed_observations=observations,
            raw_evidence_path=str(dest),
            # Hash the stored copy: that is the artefact `evidence verify` checks.
            sha256=sha256_file(dest),
            sanitization_status="operator_supplied",
            review_notes=note,
        )
        self.ws.append_evidence(evidence.to_dict())
        self.ws.append_audit_event({
            "event": "evidence_import",
            "finding_id": command.finding_id,
            "step_id": command.step_id,
            "adapter": command.adapter,
            "evidence_id": evidence_id,
            "source_path": str(path),
            "sha256": evidence.sha256,
            "operator": self.operator,
        })
        seen[command.step_id] = evidence.to_dict()
        seen_digests.add(evidence.sha256)

        return IngestItem(
            step_id=command.step_id,
            finding_id=command.finding_id,
            adapter=command.adapter,
            status=IngestStatus.IMPORTED,
            source_path=str(path),
            stored_path=str(dest),
            evidence_id=evidence_id,
            sha256=evidence.sha256,
            exit_code=exit_code,
            suggested_verdict=suggested,
            note=note,
        )


def _extract(text: str, marker: str) -> str:
    for line in text.splitlines():
        if line.startswith(marker):
            return line[len(marker):].strip()
    return ""


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")[:64] or "unknown"
