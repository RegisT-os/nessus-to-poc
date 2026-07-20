"""The verification execution engine (task section 19).

Guarantees enforced here:

* **Dry-run by default.** Nothing executes unless ``dry_run=False`` is passed
  (the CLI requires an explicit ``--approve``).
* **Scope first.** An out-of-scope target is blocked before anything runs, and
  the finding is retained (never removed).
* **Capability gaps are gaps.** A missing binary is reported as a capability
  gap; the finding is retained.
* **No shell, ever.** Commands run as argument arrays via the injected
  ``CommandRunner``; a hostile hostname is a single argv element and cannot
  inject a command.
* **Exit code is not a verdict.** The suggested verdict comes from the adapter's
  parse of the *content*; a zero exit never confirms and a non-zero exit never
  erases a finding.
* **Evidence integrity.** Output is written to a uniquely named, timestamped
  file (never overwritten) and hashed with SHA-256.
"""

from __future__ import annotations

import datetime as _dt
import shlex
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from vapt_verify.adapters.base import (
    Adapter,
    AdapterKind,
    CommandRunner,
    Connector,
    ExecutionContext,
    RealCommandRunner,
    RealConnector,
)
from vapt_verify.classification.models import Capabilities
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.evidence import Evidence
from vapt_verify.security.scope import ScopeEnforcer
from vapt_verify.utilities.hashing import sha256_text


class OutcomeStatus(Enum):
    DRY_RUN = "dry_run"
    BLOCKED_OUT_OF_SCOPE = "blocked_out_of_scope"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    MANUAL_REQUIRED = "manual_required"
    EXECUTED = "executed"


@dataclass
class ExecutionOutcome:
    finding_id: str
    adapter: str
    status: OutcomeStatus
    planned_command: list[str] = field(default_factory=list)
    scope_decision: dict[str, Any] = field(default_factory=dict)
    evidence: Evidence | None = None
    suggested_verdict: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def finding_retained(self) -> bool:
        # A finding is NEVER removed by execution, whatever the outcome.
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "adapter": self.adapter,
            "status": self.status.value,
            "planned_command": self.planned_command,
            "scope_decision": self.scope_decision,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "suggested_verdict": self.suggested_verdict,
            "notes": self.notes,
            "finding_retained": self.finding_retained,
        }


class Executor:
    def __init__(
        self,
        *,
        command_runner: CommandRunner | None = None,
        connector: Connector | None = None,
        capabilities: Capabilities | None = None,
        evidence_root: Path | None = None,
    ) -> None:
        self.command_runner = command_runner or RealCommandRunner()
        self.connector = connector or RealConnector()
        self.capabilities = capabilities if capabilities is not None else Capabilities.detect()
        self.evidence_root = evidence_root

    def run(
        self,
        *,
        ctx: ExecutionContext,
        adapter: Adapter,
        engagement: Engagement,
        dry_run: bool = True,
    ) -> ExecutionOutcome:
        # 1. Scope enforcement — always first, always retains the finding.
        decision = ScopeEnforcer(engagement).validate(ctx.target)
        if not decision.in_scope:
            return ExecutionOutcome(
                finding_id=ctx.finding_id,
                adapter=adapter.name,
                status=OutcomeStatus.BLOCKED_OUT_OF_SCOPE,
                scope_decision=decision.to_dict(),
                notes=[
                    f"Target '{ctx.target}' is out of authorised scope: {decision.reason}. "
                    "The finding remains in the inventory; nothing was executed.",
                ],
            )

        # 2. Manual/administrative/credentialed: never executed.
        if adapter.kind is AdapterKind.MANUAL:
            return ExecutionOutcome(
                finding_id=ctx.finding_id,
                adapter=adapter.name,
                status=OutcomeStatus.MANUAL_REQUIRED,
                scope_decision=decision.to_dict(),
                notes=[adapter.evidence_request(ctx)],
            )

        # 3. Capability check — a missing binary is a gap, not a removal.
        if adapter.capability and not self.capabilities.has(adapter.capability):
            return ExecutionOutcome(
                finding_id=ctx.finding_id,
                adapter=adapter.name,
                status=OutcomeStatus.CAPABILITY_UNAVAILABLE,
                scope_decision=decision.to_dict(),
                notes=[
                    f"Required tool '{adapter.capability}' is not available. This is a capability "
                    "gap; the finding is retained and re-planning with another method is advised.",
                ],
            )

        if adapter.kind is AdapterKind.COMMAND:
            planned = adapter.build_argv(ctx)
        else:
            planned = ["<in-process>", adapter.name]

        # 4. Dry-run is the default: show the plan, execute nothing.
        if dry_run:
            return ExecutionOutcome(
                finding_id=ctx.finding_id,
                adapter=adapter.name,
                status=OutcomeStatus.DRY_RUN,
                planned_command=planned,
                scope_decision=decision.to_dict(),
                notes=["Dry-run: no command executed. Re-run with approval to execute."],
            )

        # 5. Execute (argv array; no shell) and 6. interpret content, not exit code.
        start = _now()
        if adapter.kind is AdapterKind.COMMAND:
            raw = self.command_runner.run(planned, ctx.timeout, adapter.stdin(ctx))
        else:
            raw = adapter.run_inprocess(ctx, self.connector)
        end = _now()
        parsed = adapter.parse(ctx, raw)

        evidence = self._write_evidence(ctx, adapter, planned, raw, parsed, start, end)
        notes = [parsed.note] if parsed.note else []
        if raw.timed_out:
            notes.append("Tool timed out — result is INCONCLUSIVE, not a false positive.")
        return ExecutionOutcome(
            finding_id=ctx.finding_id,
            adapter=adapter.name,
            status=OutcomeStatus.EXECUTED,
            planned_command=planned,
            scope_decision=decision.to_dict(),
            evidence=evidence,
            suggested_verdict=parsed.suggested_verdict.value if parsed.suggested_verdict else None,
            notes=notes,
        )

    # -- evidence persistence ----------------------------------------------

    def _write_evidence(
        self,
        ctx: ExecutionContext,
        adapter: Adapter,
        argv: list[str],
        raw: Any,
        parsed: Any,
        start: str,
        end: str,
    ) -> Evidence:
        evidence_id = uuid.uuid4().hex
        body = (
            f"# adapter: {adapter.name}\n# command: {shlex.join(argv)}\n"
            f"# exit_code: {raw.exit_code}  timed_out: {raw.timed_out}\n"
            f"# start: {start}  end: {end}\n\n"
            f"--- stdout ---\n{raw.stdout}\n\n--- stderr ---\n{raw.stderr}\n"
        )
        digest = sha256_text(body)

        raw_path = ""
        if self.evidence_root is not None:
            # Unique, timestamped filename — existing evidence is never overwritten.
            stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%S_%f")
            out_dir = self.evidence_root / ctx.asset_id / ctx.finding_id
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"{stamp}_{adapter.name}_{evidence_id[:8]}.txt"
            path.write_text(body, encoding="utf-8")
            raw_path = str(path)

        return Evidence(
            evidence_id=evidence_id,
            finding_id=ctx.finding_id,
            engagement_id=ctx.engagement_id,
            asset_id=ctx.asset_id,
            adapter=adapter.name,
            tool_name=adapter.capability or adapter.name,
            command_args=argv,
            sanitized_command=shlex.join(argv),
            operator=ctx.operator,
            start_timestamp=start,
            end_timestamp=end,
            exit_code=raw.exit_code,
            timed_out=raw.timed_out,
            stdout=raw.stdout[:20000],
            stderr=raw.stderr[:20000],
            parsed_observations=parsed.observations,
            raw_evidence_path=raw_path,
            sha256=digest,
        )


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat()
