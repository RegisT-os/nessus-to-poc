"""The reconciliation gate.

This is the enforcement point for the non-negotiable invariant:

    Every imported source finding must appear in the normalized inventory and
    receive an explicit, reviewable disposition. No finding disappears silently.

The gate checks the accounting identity:

    source report items == normalized findings
                           + explicitly recorded parse failures
                           + explicitly approved suppressions

* If the identity does not hold, the status is IMBALANCED and the import must
  fail closed (non-zero exit): findings vanished without explanation.
* If it holds but there are parse failures or suppressions, the status is
  BALANCED_WITH_EXCEPTIONS: the accounting is complete, but a human must review
  the exceptions. By default this is still treated as a failure so the operator
  cannot ignore it; the CLI can acknowledge exceptions explicitly.
* If it holds with zero exceptions, the status is BALANCED_CLEAN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vapt_verify.importers.base import ImportResult
from vapt_verify.reconciliation.stats import compute_statistics


class ReconciliationStatus(Enum):
    BALANCED_CLEAN = "balanced_clean"
    BALANCED_WITH_EXCEPTIONS = "balanced_with_exceptions"
    IMBALANCED = "imbalanced"


@dataclass
class ReconciliationReport:
    import_id: str
    source_file: str
    source_file_hash: str
    source_report_item_count: int
    normalized_finding_count: int
    parse_failure_count: int
    approved_suppression_count: int
    status: ReconciliationStatus
    statistics: dict[str, Any] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)

    @property
    def accounted(self) -> int:
        return (
            self.normalized_finding_count
            + self.parse_failure_count
            + self.approved_suppression_count
        )

    @property
    def unexplained_difference(self) -> int:
        return self.source_report_item_count - self.accounted

    @property
    def is_balanced(self) -> bool:
        return self.unexplained_difference == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "import_id": self.import_id,
            "source_file": self.source_file,
            "source_file_hash": self.source_file_hash,
            "source_report_item_count": self.source_report_item_count,
            "normalized_finding_count": self.normalized_finding_count,
            "parse_failure_count": self.parse_failure_count,
            "approved_suppression_count": self.approved_suppression_count,
            "accounted": self.accounted,
            "unexplained_difference": self.unexplained_difference,
            "is_balanced": self.is_balanced,
            "status": self.status.value,
            "statistics": self.statistics,
            "messages": self.messages,
        }


def reconcile(result: ImportResult, *, approved_suppressions: int = 0) -> ReconciliationReport:
    """Compute the reconciliation report for an import result."""
    normalized = result.normalized_finding_count
    failures = result.parse_failure_count
    accounted = normalized + failures + approved_suppressions
    diff = result.source_report_item_count - accounted

    messages: list[str] = []
    if diff != 0:
        status = ReconciliationStatus.IMBALANCED
        if diff > 0:
            messages.append(
                f"CRITICAL: {diff} source report item(s) are unaccounted for. "
                "Findings disappeared without an explicit disposition. Import must not be trusted."
            )
        else:
            messages.append(
                f"CRITICAL: accounted count exceeds source by {-diff}. "
                "The importer produced more records than the source contained; this is a bug."
            )
    elif failures > 0 or approved_suppressions > 0:
        status = ReconciliationStatus.BALANCED_WITH_EXCEPTIONS
        if failures:
            messages.append(
                f"{failures} source record(s) recorded as explicit parse failures; "
                "review reconciliation/parse_failures before relying on this import."
            )
        if approved_suppressions:
            messages.append(f"{approved_suppressions} record(s) explicitly suppressed.")
    else:
        status = ReconciliationStatus.BALANCED_CLEAN
        messages.append(
            f"All {result.source_report_item_count} source report items are accounted for."
        )

    return ReconciliationReport(
        import_id=result.import_id,
        source_file=result.source_file,
        source_file_hash=result.source_file_hash,
        source_report_item_count=result.source_report_item_count,
        normalized_finding_count=normalized,
        parse_failure_count=failures,
        approved_suppression_count=approved_suppressions,
        status=status,
        statistics=compute_statistics(result),
        messages=messages,
    )
