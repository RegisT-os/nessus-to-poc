"""Correlation result types (v2.0).

The v2.0 guardrail, from docs/ROADMAP.md:

    Correlation produces *links and candidate groups*, never silent
    de-duplication. A merged view must always be decomposable back to sources.

So nothing here mutates or removes a finding. Correlation emits a separate,
additive layer: groups that *reference* finding ids, each carrying the evidence
for why the members were linked and how confident that link is. Every group can
be expanded back to its member findings, and every member keeps its own scanner
provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LinkBasis(Enum):
    """Why two records were linked. Ordered strongest-first by confidence."""

    SAME_FINGERPRINT = "same_fingerprint"
    SAME_PLUGIN_AND_LOCATION = "same_plugin_and_location"
    SHARED_CVE_AND_LOCATION = "shared_cve_and_location"
    SAME_LOCATION_AND_TITLE = "same_location_and_title"

    @property
    def confidence(self) -> str:
        return {
            LinkBasis.SAME_FINGERPRINT: "high",
            LinkBasis.SAME_PLUGIN_AND_LOCATION: "high",
            LinkBasis.SHARED_CVE_AND_LOCATION: "medium",
            LinkBasis.SAME_LOCATION_AND_TITLE: "low",
        }[self]


class AssetLinkBasis(Enum):
    SHARED_IP = "shared_ip"
    SHARED_FQDN = "shared_fqdn"
    SHARED_MAC = "shared_mac"
    SAME_PRIMARY_KEY = "same_primary_key"

    @property
    def confidence(self) -> str:
        return {
            AssetLinkBasis.SAME_PRIMARY_KEY: "high",
            AssetLinkBasis.SHARED_MAC: "high",
            AssetLinkBasis.SHARED_IP: "medium",
            AssetLinkBasis.SHARED_FQDN: "medium",
        }[self]


@dataclass
class CorrelationGroup:
    """A set of findings believed to describe the same underlying condition.

    ``member_finding_ids`` is the decomposition path back to sources: the group
    is a *view*, and the findings it references remain independent records.
    """

    group_id: str
    basis: LinkBasis
    confidence: str
    member_finding_ids: list[str] = field(default_factory=list)
    # scanner -> finding ids contributed by that scanner
    sources: dict[str, list[str]] = field(default_factory=dict)
    # Human-readable location/identity summary for the group.
    summary: str = ""
    rationale: str = ""

    @property
    def scanner_count(self) -> int:
        return len(self.sources)

    @property
    def is_cross_scanner(self) -> bool:
        return self.scanner_count > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "basis": self.basis.value,
            "confidence": self.confidence,
            "member_finding_ids": self.member_finding_ids,
            "member_count": len(self.member_finding_ids),
            "sources": self.sources,
            "scanner_count": self.scanner_count,
            "is_cross_scanner": self.is_cross_scanner,
            "summary": self.summary,
            "rationale": self.rationale,
        }


@dataclass
class AssetIdentityGroup:
    """Asset records across scanners that may be the same physical asset.

    Deliberately a *candidate* grouping: one IP is not assumed to be one
    permanent asset (see docs/ARCHITECTURE.md), so groups carry confidence and
    are never auto-merged.
    """

    identity_id: str
    basis: AssetLinkBasis
    confidence: str
    member_asset_ids: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    sources: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "basis": self.basis.value,
            "confidence": self.confidence,
            "member_asset_ids": self.member_asset_ids,
            "member_count": len(self.member_asset_ids),
            "ip_addresses": self.ip_addresses,
            "hostnames": self.hostnames,
            "sources": self.sources,
            "notes": self.notes,
        }


@dataclass
class CorrelationReport:
    """The complete correlation layer for an engagement."""

    total_findings: int
    total_assets: int
    scanners: list[str] = field(default_factory=list)
    finding_groups: list[CorrelationGroup] = field(default_factory=list)
    asset_identities: list[AssetIdentityGroup] = field(default_factory=list)
    # Findings not linked to anything else. Still fully present: being
    # uncorrelated is a state, never a reason to hide a finding.
    singleton_finding_ids: list[str] = field(default_factory=list)

    @property
    def grouped_finding_count(self) -> int:
        return sum(len(g.member_finding_ids) for g in self.finding_groups)

    @property
    def accounted_findings(self) -> int:
        """Grouped + singleton must always equal the total (no finding lost)."""
        return self.grouped_finding_count + len(self.singleton_finding_ids)

    @property
    def totals_balance(self) -> bool:
        return self.accounted_findings == self.total_findings

    @property
    def cross_scanner_groups(self) -> list[CorrelationGroup]:
        return [g for g in self.finding_groups if g.is_cross_scanner]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "total_assets": self.total_assets,
            "scanners": self.scanners,
            "counts": {
                "finding_groups": len(self.finding_groups),
                "cross_scanner_groups": len(self.cross_scanner_groups),
                "grouped_findings": self.grouped_finding_count,
                "singleton_findings": len(self.singleton_finding_ids),
                "accounted_findings": self.accounted_findings,
                "asset_identities": len(self.asset_identities),
            },
            "totals_balance": self.totals_balance,
            "finding_groups": [g.to_dict() for g in self.finding_groups],
            "asset_identities": [a.to_dict() for a in self.asset_identities],
            "singleton_finding_ids": self.singleton_finding_ids,
        }
