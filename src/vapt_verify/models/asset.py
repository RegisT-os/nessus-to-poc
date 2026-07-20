"""Asset model.

Task section 9.2. An asset is an identity-confidence-aware grouping of scanner
host observations. We deliberately do NOT assume that one IP always represents
one permanent asset; ``identity_confidence_notes`` records ambiguity, and the
provenance list records every source host record that contributed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Asset:
    """A normalized asset assembled from one or more scanner host records."""

    asset_id: str
    # Primary key used to derive the stable id (IP where available, else name).
    primary_key: str
    ip_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    fqdns: list[str] = field(default_factory=list)
    scanner_host_name: str = ""
    mac_addresses: list[str] = field(default_factory=list)
    environment: str = "unknown"
    site: str = ""
    os_observations: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Source provenance: which import(s)/host record(s) contributed to this asset.
    source_provenance: list[str] = field(default_factory=list)
    identity_confidence_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "primary_key": self.primary_key,
            "ip_addresses": sorted(set(self.ip_addresses)),
            "hostnames": sorted(set(self.hostnames)),
            "fqdns": sorted(set(self.fqdns)),
            "scanner_host_name": self.scanner_host_name,
            "mac_addresses": sorted(set(self.mac_addresses)),
            "environment": self.environment,
            "site": self.site,
            "os_observations": sorted(set(self.os_observations)),
            "tags": sorted(set(self.tags)),
            "source_provenance": self.source_provenance,
            "identity_confidence_notes": self.identity_confidence_notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Asset:
        return cls(
            asset_id=data["asset_id"],
            primary_key=data["primary_key"],
            ip_addresses=list(data.get("ip_addresses", [])),
            hostnames=list(data.get("hostnames", [])),
            fqdns=list(data.get("fqdns", [])),
            scanner_host_name=data.get("scanner_host_name", ""),
            mac_addresses=list(data.get("mac_addresses", [])),
            environment=data.get("environment", "unknown"),
            site=data.get("site", ""),
            os_observations=list(data.get("os_observations", [])),
            tags=list(data.get("tags", [])),
            source_provenance=list(data.get("source_provenance", [])),
            identity_confidence_notes=data.get("identity_confidence_notes", ""),
        )
