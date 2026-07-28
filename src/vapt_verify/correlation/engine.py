"""Cross-scanner correlation engine (v2.0).

Links findings and asset records that plausibly describe the same thing, across
one or many scanners, **without merging or removing anything**. The output is an
additive layer (see :mod:`vapt_verify.correlation.models`).

Correlation strategy, strongest signal first — the first basis that groups a
finding wins, so a weak signal never overrides a strong one:

1. ``SAME_FINGERPRINT``          identical content fingerprint (usually a re-scan)
2. ``SAME_PLUGIN_AND_LOCATION``  same plugin id on the same asset/port/transport
3. ``SHARED_CVE_AND_LOCATION``   a shared CVE on the same asset/port/transport
4. ``SAME_LOCATION_AND_TITLE``   same normalized title on the same location

Anything left over is a *singleton* — still present, still counted. The
accounting identity ``grouped + singletons == total findings`` is asserted by
:meth:`CorrelationReport.totals_balance` and by the test suite, mirroring the
import reconciliation gate: correlation must not lose a finding either.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from vapt_verify.correlation.models import (
    AssetIdentityGroup,
    AssetLinkBasis,
    CorrelationGroup,
    CorrelationReport,
    LinkBasis,
)
from vapt_verify.utilities.ids import stable_digest as _digest

_WHITESPACE = re.compile(r"\s+")
# Version-ish and date-ish noise that makes otherwise identical titles differ
# between scanners (e.g. "... (KB5005565)" or "... 1.2.3").
_TITLE_NOISE = re.compile(r"[\(\[][^)\]]*[\)\]]|\bv?\d+(?:\.\d+)+\b|\bkb\d+\b", re.IGNORECASE)


def normalize_title(title: str) -> str:
    """Normalize a finding title for cross-scanner comparison."""
    text = _TITLE_NOISE.sub(" ", title.lower())
    text = re.sub(r"[^a-z0-9 ]+", " ", text)
    return _WHITESPACE.sub(" ", text).strip()


def _location(finding: dict[str, Any]) -> tuple[str, int, str]:
    return (
        str(finding.get("asset_id", "")),
        int(finding.get("port", 0) or 0),
        str(finding.get("transport", "")),
    )


def _scanner(finding: dict[str, Any]) -> str:
    provenance = finding.get("provenance", {}) or {}
    return str(provenance.get("source_scanner", "unknown"))


def _group_id(basis: LinkBasis, key: str) -> str:
    return f"grp-{basis.value[:4]}-" + _digest([basis.value, key], length=16)


class CorrelationEngine:
    """Builds the correlation layer for a set of normalized findings/assets."""

    def correlate(
        self,
        *,
        findings: list[dict[str, Any]],
        assets: list[dict[str, Any]] | None = None,
    ) -> CorrelationReport:
        assets = assets or []
        report = CorrelationReport(
            total_findings=len(findings),
            total_assets=len(assets),
            scanners=sorted({_scanner(f) for f in findings}),
        )

        remaining = {f["finding_id"]: f for f in findings}
        groups: list[CorrelationGroup] = []

        for basis, keyfunc in (
            (LinkBasis.SAME_FINGERPRINT, self._key_fingerprint),
            (LinkBasis.SAME_PLUGIN_AND_LOCATION, self._key_plugin_location),
            (LinkBasis.SHARED_CVE_AND_LOCATION, self._key_cve_location),
            (LinkBasis.SAME_LOCATION_AND_TITLE, self._key_title_location),
        ):
            groups.extend(self._pass(remaining, basis, keyfunc))

        report.finding_groups = groups
        # Whatever survived every pass is a singleton: uncorrelated, not lost.
        report.singleton_finding_ids = sorted(remaining)
        report.asset_identities = self.correlate_assets(assets)
        return report

    # -- finding passes -----------------------------------------------------

    def _pass(
        self,
        remaining: dict[str, dict[str, Any]],
        basis: LinkBasis,
        keyfunc: Any,
    ) -> list[CorrelationGroup]:
        buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in list(remaining.values()):
            for key in keyfunc(finding):
                if key:
                    buckets[key].append(finding)

        groups: list[CorrelationGroup] = []
        for key, members in sorted(buckets.items()):
            # A member may have been claimed by an earlier key in this same pass.
            live = [m for m in members if m["finding_id"] in remaining]
            if len(live) < 2:
                continue
            for member in live:
                remaining.pop(member["finding_id"], None)
            groups.append(self._build_group(basis, key, live))
        return groups

    def _build_group(
        self, basis: LinkBasis, key: str, members: list[dict[str, Any]]
    ) -> CorrelationGroup:
        sources: dict[str, list[str]] = defaultdict(list)
        for member in members:
            sources[_scanner(member)].append(member["finding_id"])
        first = members[0]
        asset_id, port, transport = _location(first)
        location = f"{asset_id} {port}/{transport}" if port else f"{asset_id} (host-level)"
        scanners = sorted(sources)
        rationale = {
            LinkBasis.SAME_FINGERPRINT: (
                "Identical content fingerprint: same plugin, location, service and "
                "plugin-output digest. Typically the same condition seen in repeated scans."
            ),
            LinkBasis.SAME_PLUGIN_AND_LOCATION: (
                "Same scanner plugin id reported at the same asset/port/transport."
            ),
            LinkBasis.SHARED_CVE_AND_LOCATION: (
                "Different plugins reported a shared CVE at the same asset/port/transport."
            ),
            LinkBasis.SAME_LOCATION_AND_TITLE: (
                "Titles normalize to the same text at the same asset/port/transport. "
                "Weakest basis - review before treating members as one condition."
            ),
        }[basis]
        return CorrelationGroup(
            group_id=_group_id(basis, key),
            basis=basis,
            confidence=basis.confidence,
            member_finding_ids=sorted(m["finding_id"] for m in members),
            sources={k: sorted(v) for k, v in sources.items()},
            summary=f"{first.get('plugin_name', '(unnamed)')} @ {location} "
                    f"[{', '.join(scanners)}]",
            rationale=rationale,
        )

    def _key_fingerprint(self, finding: dict[str, Any]) -> list[str]:
        fingerprint = finding.get("fingerprint")
        return [f"fp:{fingerprint}"] if fingerprint else []

    def _key_plugin_location(self, finding: dict[str, Any]) -> list[str]:
        plugin_id = str(finding.get("plugin_id", "") or "")
        if not plugin_id:
            return []
        asset, port, transport = _location(finding)
        return [f"pl:{_scanner(finding)}:{plugin_id}:{asset}:{port}:{transport}"]

    def _key_cve_location(self, finding: dict[str, Any]) -> list[str]:
        cves = [str(c).strip().upper() for c in finding.get("cves", []) if str(c).strip()]
        if not cves:
            return []
        asset, port, transport = _location(finding)
        return [f"cve:{cve}:{asset}:{port}:{transport}" for cve in sorted(cves)]

    def _key_title_location(self, finding: dict[str, Any]) -> list[str]:
        title = normalize_title(str(finding.get("plugin_name", "")))
        if not title:
            return []
        asset, port, transport = _location(finding)
        return [f"ti:{title}:{asset}:{port}:{transport}"]

    # -- asset identities ---------------------------------------------------

    def correlate_assets(self, assets: list[dict[str, Any]]) -> list[AssetIdentityGroup]:
        """Group asset records that may be the same physical asset.

        Never merges: a group is a candidate identity for reviewer confirmation,
        because one IP does not always mean one permanent asset.
        """
        buckets: dict[tuple[AssetLinkBasis, str], list[dict[str, Any]]] = defaultdict(list)
        for asset in assets:
            for mac in asset.get("mac_addresses", []) or []:
                buckets[(AssetLinkBasis.SHARED_MAC, str(mac).lower())].append(asset)
            for ip in asset.get("ip_addresses", []) or []:
                buckets[(AssetLinkBasis.SHARED_IP, str(ip))].append(asset)
            for fqdn in asset.get("fqdns", []) or []:
                buckets[(AssetLinkBasis.SHARED_FQDN, str(fqdn).lower())].append(asset)

        claimed: set[str] = set()
        identities: list[AssetIdentityGroup] = []
        # Strongest basis first so a MAC match wins over a shared IP.
        order = [AssetLinkBasis.SHARED_MAC, AssetLinkBasis.SHARED_IP, AssetLinkBasis.SHARED_FQDN]
        for basis in order:
            for (bucket_basis, key), members in sorted(
                buckets.items(), key=lambda kv: (kv[0][0].value, kv[0][1])
            ):
                if bucket_basis is not basis:
                    continue
                live = [m for m in members if m["asset_id"] not in claimed]
                unique_ids = {m["asset_id"] for m in live}
                if len(unique_ids) < 2:
                    continue
                claimed |= unique_ids
                identities.append(self._build_identity(basis, key, live))
        return identities

    def _build_identity(
        self, basis: AssetLinkBasis, key: str, members: list[dict[str, Any]]
    ) -> AssetIdentityGroup:
        sources: dict[str, list[str]] = defaultdict(list)
        ips: set[str] = set()
        hostnames: set[str] = set()
        for member in members:
            for provenance in member.get("source_provenance", []) or ["unknown"]:
                scanner = str(provenance).split(":", 1)[0]
                sources[scanner].append(member["asset_id"])
            ips.update(str(i) for i in member.get("ip_addresses", []) or [])
            hostnames.update(str(h) for h in member.get("fqdns", []) or [])
            hostnames.update(str(h) for h in member.get("hostnames", []) or [])
        notes = [
            f"Candidate identity linked by {basis.value} ({key}). Not merged: confirm before "
            "treating these asset records as one asset.",
        ]
        if basis is AssetLinkBasis.SHARED_IP:
            notes.append(
                "An IP can be reassigned (DHCP/NAT/rebuild); a shared IP alone is not proof "
                "of a shared asset."
            )
        return AssetIdentityGroup(
            identity_id="ident-" + _digest([basis.value, key], length=16),
            basis=basis,
            confidence=basis.confidence,
            member_asset_ids=sorted({m["asset_id"] for m in members}),
            ip_addresses=sorted(ips),
            hostnames=sorted(hostnames),
            sources={k: sorted(set(v)) for k, v in sources.items()},
            notes=notes,
        )
