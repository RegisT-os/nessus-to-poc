"""Review engine — enforces the verdict transition rules (task section 10).

Guardrails:

* Only an authorised reviewer (an "approver"/"lead" role) may assign
  ``FALSE_POSITIVE_APPROVED`` or ``RISK_ACCEPTED``.
* Terminal verdicts require a non-empty reviewer rationale.
* ``NOT_REPRODUCED`` never auto-becomes ``FALSE_POSITIVE_CANDIDATE`` — a human
  must make that call explicitly.
* Contradictory evidence is surfaced, never auto-resolved.
* A primary tool's evidence (e.g. OpenSSL) can support ``CONFIRMED`` even when
  Nmap (supporting evidence) did not reproduce the condition — Nmap's silence
  never blocks confirmation.
"""

from __future__ import annotations

from typing import Any

from vapt_verify.models.decision import Decision
from vapt_verify.models.enums import Verdict

# Verdicts that are "terminal" enough to demand a written rationale.
_TERMINAL = {
    Verdict.CONFIRMED,
    Verdict.CONFIRMED_REMEDIATED,
    Verdict.NOT_REPRODUCED,
    Verdict.FALSE_POSITIVE_CANDIDATE,
    Verdict.FALSE_POSITIVE_APPROVED,
    Verdict.RISK_ACCEPTED,
    Verdict.POSSIBLY_REMEDIATED,
}

# Verdicts only an authorised reviewer may assign.
_REQUIRE_APPROVER = {Verdict.FALSE_POSITIVE_APPROVED, Verdict.RISK_ACCEPTED}

_APPROVER_ROLES = {"approver", "lead", "engagement-lead"}

# Suggested verdicts that point "condition present" vs "condition absent".
_PRESENT = {Verdict.CONFIRMED, Verdict.LIKELY_CONFIRMED}
_ABSENT = {Verdict.NOT_REPRODUCED, Verdict.SERVICE_NOT_CURRENTLY_OBSERVED}


class ReviewError(Exception):
    """Raised when a decision violates a methodology guardrail."""


def detect_contradiction(evidence: list[dict[str, Any]]) -> tuple[bool, str]:
    """Return (contradiction?, description) over a set of evidence records.

    Contradiction means some evidence indicates the condition is present while
    other evidence indicates it is absent. It is surfaced, never resolved here.
    """
    present: list[str] = []
    absent: list[str] = []
    for ev in evidence:
        raw = ev.get("parsed_observations", {}) or {}
        suggested = raw.get("suggested_verdict") or ev.get("suggested_verdict")
        try:
            verdict = Verdict(suggested) if suggested else None
        except ValueError:
            verdict = None
        if verdict in _PRESENT:
            present.append(ev.get("adapter", "?"))
        elif verdict in _ABSENT:
            absent.append(ev.get("adapter", "?"))
    if present and absent:
        return True, (
            f"Contradictory evidence: {', '.join(present)} indicate the condition is present "
            f"while {', '.join(absent)} indicate it is absent. Reviewer assessment required."
        )
    return False, ""


class ReviewEngine:
    def record_decision(
        self,
        *,
        finding: dict[str, Any],
        verdict: str,
        reviewer: str,
        rationale: str = "",
        reviewer_roles: set[str] | None = None,
        supporting_evidence_ids: list[str] | None = None,
        contradicting_evidence_ids: list[str] | None = None,
        limitations: list[str] | None = None,
        confidence: str = "medium",
    ) -> Decision:
        roles = reviewer_roles or set()
        try:
            target = Verdict(verdict)
        except ValueError as exc:
            raise ReviewError(f"unknown verdict: {verdict!r}") from exc

        if not reviewer:
            raise ReviewError("a reviewer identity is required")
        if target in _REQUIRE_APPROVER and not (roles & _APPROVER_ROLES):
            raise ReviewError(
                f"{target.value} may only be assigned by an authorised reviewer "
                f"(one of roles: {sorted(_APPROVER_ROLES)})."
            )
        if target in _TERMINAL and not rationale.strip():
            raise ReviewError(f"{target.value} requires a non-empty reviewer rationale.")

        prior = finding.get("verdict", Verdict.UNREVIEWED.value)
        decision = Decision(
            finding_id=finding["finding_id"],
            verdict=target.value,
            reviewer=reviewer,
            reviewer_rationale=rationale,
            confidence=confidence,
            supporting_evidence_ids=supporting_evidence_ids or [],
            contradicting_evidence_ids=contradicting_evidence_ids or [],
            limitations=limitations or [],
            approval_history=[
                {"from": prior, "to": target.value, "reviewer": reviewer, "roles": sorted(roles)}
            ],
        )
        # Apply to the finding (in memory; caller persists).
        finding["verdict"] = target.value
        return decision
