"""Shared import result types.

An ``ImportResult`` is the lossless output of an importer. It carries the raw
source counts alongside the normalized objects so that the reconciliation gate
can prove the accounting identity:

    source report items == normalized findings
                           + explicitly recorded parse failures
                           + explicitly approved suppressions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vapt_verify.models.asset import Asset
from vapt_verify.models.finding import Finding
from vapt_verify.models.service import ServiceObservation


@dataclass
class ParseFailure:
    """An explicit record of a source item that could not be normalized.

    A parse failure is NOT a dropped finding: it is a visible, counted,
    reviewable disposition. The raw excerpt is retained so a human can recover
    the original record.
    """

    source_record_id: str
    host_key: str
    reason: str
    raw_excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_record_id": self.source_record_id,
            "host_key": self.host_key,
            "reason": self.reason,
            "raw_excerpt": self.raw_excerpt,
        }


@dataclass
class ImportResult:
    """The lossless result of importing one scanner file."""

    import_id: str
    source_scanner: str
    source_file: str
    source_file_hash: str
    import_timestamp: str
    # Raw source counts, measured directly from the source document.
    source_report_item_count: int = 0
    source_host_count: int = 0
    # Normalized objects.
    assets: list[Asset] = field(default_factory=list)
    services: list[ServiceObservation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Explicit, counted exceptions.
    parse_failures: list[ParseFailure] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def normalized_finding_count(self) -> int:
        return len(self.findings)

    @property
    def parse_failure_count(self) -> int:
        return len(self.parse_failures)
