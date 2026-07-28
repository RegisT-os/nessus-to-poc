"""Evidence integrity verification (chain of custody).

Every captured evidence file is hashed with SHA-256 at capture time and the
digest is recorded in the evidence index. This module re-reads the stored files
and re-computes those digests, so an operator can prove — at report time, at
handover, or after a restore — that the evidence backing a finding is byte-for-
byte what was captured.

Redaction never touches these files (see :mod:`vapt_verify.security.redaction`),
so a redacted deliverable and an intact, verifiable capture coexist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from vapt_verify.utilities.hashing import sha256_file


class IntegrityStatus(Enum):
    VERIFIED = "verified"
    MODIFIED = "modified"
    MISSING = "missing"
    NOT_RECORDED = "not_recorded"  # evidence has no stored path/hash (e.g. dry-run)


@dataclass
class IntegrityCheck:
    evidence_id: str
    finding_id: str
    adapter: str
    status: IntegrityStatus
    recorded_sha256: str = ""
    computed_sha256: str = ""
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "finding_id": self.finding_id,
            "adapter": self.adapter,
            "status": self.status.value,
            "recorded_sha256": self.recorded_sha256,
            "computed_sha256": self.computed_sha256,
            "path": self.path,
        }


@dataclass
class IntegrityReport:
    checks: list[IntegrityCheck] = field(default_factory=list)

    def of_status(self, status: IntegrityStatus) -> list[IntegrityCheck]:
        return [c for c in self.checks if c.status is status]

    @property
    def is_intact(self) -> bool:
        """True when nothing is modified or missing."""
        return not (
            self.of_status(IntegrityStatus.MODIFIED) or self.of_status(IntegrityStatus.MISSING)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": len(self.checks),
            "counts": {s.value: len(self.of_status(s)) for s in IntegrityStatus},
            "is_intact": self.is_intact,
            "checks": [c.to_dict() for c in self.checks],
        }


def verify_evidence(evidence_rows: list[dict[str, Any]]) -> IntegrityReport:
    """Re-hash every recorded evidence file and compare to its stored digest."""
    report = IntegrityReport()
    for row in evidence_rows:
        evidence_id = str(row.get("evidence_id", ""))
        recorded = str(row.get("sha256", ""))
        raw_path = str(row.get("raw_evidence_path", ""))
        common = {
            "evidence_id": evidence_id,
            "finding_id": str(row.get("finding_id", "")),
            "adapter": str(row.get("adapter", "")),
            "recorded_sha256": recorded,
            "path": raw_path,
        }

        if not raw_path or not recorded:
            report.checks.append(
                IntegrityCheck(status=IntegrityStatus.NOT_RECORDED, **common)
            )
            continue
        path = Path(raw_path)
        if not path.exists():
            report.checks.append(IntegrityCheck(status=IntegrityStatus.MISSING, **common))
            continue
        computed = sha256_file(path)
        status = (
            IntegrityStatus.VERIFIED if computed == recorded else IntegrityStatus.MODIFIED
        )
        report.checks.append(
            IntegrityCheck(status=status, computed_sha256=computed, **common)
        )
    return report
