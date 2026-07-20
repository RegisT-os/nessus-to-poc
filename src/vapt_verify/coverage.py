"""Coverage reporting (task section 20).

The primary success metric is **accounted-for findings / imported findings =
100%** — never the automation percentage. This module computes the disposition
and verdict breakdown and always totals back to the number of imported findings.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from vapt_verify.models.enums import Disposition, Verdict


@dataclass
class CoverageReport:
    total_imported: int
    by_disposition: dict[str, int] = field(default_factory=dict)
    by_verdict: dict[str, int] = field(default_factory=dict)
    classified: int = 0
    unreviewed: int = 0

    @property
    def accounted(self) -> int:
        return sum(self.by_disposition.values())

    @property
    def totals_balance(self) -> bool:
        return self.accounted == self.total_imported

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_imported": self.total_imported,
            "accounted": self.accounted,
            "totals_balance": self.totals_balance,
            "classified": self.classified,
            "unreviewed": self.unreviewed,
            "by_disposition": self.by_disposition,
            "by_verdict": self.by_verdict,
        }


def compute_coverage(findings: list[dict[str, Any]]) -> CoverageReport:
    by_disposition: Counter[str] = Counter()
    by_verdict: Counter[str] = Counter()
    classified = 0
    unreviewed = 0
    for f in findings:
        disposition = f.get("disposition", Disposition.PENDING_CLASSIFICATION.value)
        verdict = f.get("verdict", Verdict.UNREVIEWED.value)
        by_disposition[disposition] += 1
        by_verdict[verdict] += 1
        if disposition != Disposition.PENDING_CLASSIFICATION.value:
            classified += 1
        if verdict == Verdict.UNREVIEWED.value:
            unreviewed += 1
    return CoverageReport(
        total_imported=len(findings),
        by_disposition=dict(by_disposition),
        by_verdict=dict(by_verdict),
        classified=classified,
        unreviewed=unreviewed,
    )
