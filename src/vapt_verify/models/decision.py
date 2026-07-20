"""Decision model (task section 9.7).

A decision is a reviewer's conclusion about a finding, with the evidence that
supports and contradicts it, a mandatory rationale for terminal verdicts, and an
approval history. Decisions are the only thing that assigns a final verdict — no
tool and no exit code does.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Decision:
    finding_id: str
    verdict: str
    reviewer: str
    reviewer_rationale: str = ""
    confidence: str = "medium"
    supporting_evidence_ids: list[str] = field(default_factory=list)
    contradicting_evidence_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    timestamp: str = ""
    approval_history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _dt.datetime.now(_dt.UTC).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "reviewer": self.reviewer,
            "reviewer_rationale": self.reviewer_rationale,
            "confidence": self.confidence,
            "supporting_evidence_ids": self.supporting_evidence_ids,
            "contradicting_evidence_ids": self.contradicting_evidence_ids,
            "limitations": self.limitations,
            "timestamp": self.timestamp,
            "approval_history": self.approval_history,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Decision:
        return cls(
            finding_id=data["finding_id"],
            verdict=data["verdict"],
            reviewer=data.get("reviewer", ""),
            reviewer_rationale=data.get("reviewer_rationale", ""),
            confidence=data.get("confidence", "medium"),
            supporting_evidence_ids=list(data.get("supporting_evidence_ids", [])),
            contradicting_evidence_ids=list(data.get("contradicting_evidence_ids", [])),
            limitations=list(data.get("limitations", [])),
            timestamp=data.get("timestamp", ""),
            approval_history=list(data.get("approval_history", [])),
        )
