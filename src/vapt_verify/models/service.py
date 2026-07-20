"""Service observation model.

Task section 9.3. A service observation records WHAT was seen, HOW it was seen
(observation source) and WHEN. Crucially it distinguishes a scanner-referenced
port from a port that has actually been observed open (legacy failure mode
2.6). Transport and application protocol are stored separately (legacy failure
mode 2.5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vapt_verify.models.enums import ObservationSource, Transport


@dataclass
class ServiceObservation:
    """A single observation of a service on an asset at a point in time."""

    service_id: str
    asset_id: str
    port: int
    transport: Transport
    application_protocol: str = ""
    service_name: str = ""
    product: str = ""
    version: str = ""
    tls: bool = False
    vhost: str = ""  # virtual host / SNI name, when known
    observation_source: ObservationSource = ObservationSource.SCANNER_REFERENCED
    observation_timestamp: str = ""
    confidence: str = "reported"
    raw_evidence_ref: str = ""

    @property
    def is_host_level(self) -> bool:
        """True for host-level observations (port 0), which have no transport."""
        return self.port == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "asset_id": self.asset_id,
            "port": self.port,
            "transport": self.transport.value,
            "application_protocol": self.application_protocol,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "tls": self.tls,
            "vhost": self.vhost,
            "observation_source": self.observation_source.value,
            "observation_timestamp": self.observation_timestamp,
            "confidence": self.confidence,
            "raw_evidence_ref": self.raw_evidence_ref,
            "is_host_level": self.is_host_level,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServiceObservation:
        return cls(
            service_id=data["service_id"],
            asset_id=data["asset_id"],
            port=int(data["port"]),
            transport=Transport(data.get("transport", "unknown")),
            application_protocol=data.get("application_protocol", ""),
            service_name=data.get("service_name", ""),
            product=data.get("product", ""),
            version=data.get("version", ""),
            tls=bool(data.get("tls", False)),
            vhost=data.get("vhost", ""),
            observation_source=ObservationSource(
                data.get("observation_source", ObservationSource.SCANNER_REFERENCED.value)
            ),
            observation_timestamp=data.get("observation_timestamp", ""),
            confidence=data.get("confidence", "reported"),
            raw_evidence_ref=data.get("raw_evidence_ref", ""),
        )


@dataclass
class ServiceObservationDraft:
    """Mutable accumulator used by importers before ids are assigned."""

    asset_key: str
    port: int
    transport: Transport
    application_protocol: str = ""
    service_name: str = ""
    tls: bool = False
    vhost: str = ""
    sources: set[str] = field(default_factory=set)
