"""Finding model and its source provenance.

Task section 9.4. This is the heart of the lossless-import guarantee. A Finding
preserves every scrap of scanner evidence and keeps its own identity: the
importer never collapses two findings into one (legacy failure mode 2.4). The
``raw`` mapping holds every source attribute and child element verbatim, so no
scanner field is ever silently dropped, even ones this version does not model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vapt_verify.models.enums import Disposition, Severity, Transport, Verdict


@dataclass
class SourceProvenance:
    """Where a finding came from, in enough detail to trace it back to source.

    Task 2.8/9.4: provenance is what lets reconciliation prove no finding was
    invented or lost, and lets repeated scans of one finding stay distinct.
    """

    source_scanner: str = "nessus"
    source_file: str = ""
    source_file_hash: str = ""
    source_record_id: str = ""
    scan_id: str = ""
    scan_date: str = ""
    scan_start: str = ""
    scan_end: str = ""
    report_name: str = ""
    policy_name: str = ""
    import_id: str = ""
    import_timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_scanner": self.source_scanner,
            "source_file": self.source_file,
            "source_file_hash": self.source_file_hash,
            "source_record_id": self.source_record_id,
            "scan_id": self.scan_id,
            "scan_date": self.scan_date,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "report_name": self.report_name,
            "policy_name": self.policy_name,
            "import_id": self.import_id,
            "import_timestamp": self.import_timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceProvenance:
        return cls(
            source_scanner=data.get("source_scanner", "nessus"),
            source_file=data.get("source_file", ""),
            source_file_hash=data.get("source_file_hash", ""),
            source_record_id=data.get("source_record_id", ""),
            scan_id=data.get("scan_id", ""),
            scan_date=data.get("scan_date", ""),
            scan_start=data.get("scan_start", ""),
            scan_end=data.get("scan_end", ""),
            report_name=data.get("report_name", ""),
            policy_name=data.get("policy_name", ""),
            import_id=data.get("import_id", ""),
            import_timestamp=data.get("import_timestamp", ""),
        )


@dataclass
class Finding:
    """A single normalized finding with full scanner provenance preserved."""

    finding_id: str
    fingerprint: str
    asset_id: str
    provenance: SourceProvenance

    # --- Scanner classification ---
    plugin_id: str = ""
    plugin_name: str = ""
    plugin_family: str = ""
    severity: Severity = Severity.INFORMATIONAL
    risk_factor: str = ""

    # --- Scoring / references ---
    cvss: dict[str, Any] = field(default_factory=dict)
    cves: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploitability: dict[str, Any] = field(default_factory=dict)

    # --- Location. Port 0 (host-level) is a first-class value (fix for 2.2). ---
    port: int = 0
    transport: Transport = Transport.NONE
    application_protocol: str = ""
    service: str = ""

    # --- Narrative evidence ---
    synopsis: str = ""
    description: str = ""
    solution: str = ""
    plugin_output: str = ""

    # --- Host / scan context ---
    credentialed: bool | None = None
    host_properties: dict[str, Any] = field(default_factory=dict)

    # --- Lossless catch-all: every source field not explicitly modelled. ---
    raw: dict[str, Any] = field(default_factory=dict)

    # --- Identity / duplicate relationships (retained, never auto-merged) ---
    duplicate_candidate_of: list[str] = field(default_factory=list)

    # --- Verification lifecycle ---
    verification_requirements: list[str] = field(default_factory=list)
    disposition: Disposition = Disposition.PENDING_CLASSIFICATION
    verdict: Verdict = Verdict.UNREVIEWED

    @property
    def is_host_level(self) -> bool:
        """True for port-0, host-level findings (patch/policy/local checks)."""
        return self.port == 0

    @property
    def is_informational(self) -> bool:
        return self.severity is Severity.INFORMATIONAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "asset_id": self.asset_id,
            "provenance": self.provenance.to_dict(),
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "plugin_family": self.plugin_family,
            "severity": self.severity.value,
            "severity_label": self.severity.name,
            "risk_factor": self.risk_factor,
            "cvss": self.cvss,
            "cves": self.cves,
            "cpes": self.cpes,
            "references": self.references,
            "exploitability": self.exploitability,
            "port": self.port,
            "transport": self.transport.value,
            "application_protocol": self.application_protocol,
            "service": self.service,
            "is_host_level": self.is_host_level,
            "synopsis": self.synopsis,
            "description": self.description,
            "solution": self.solution,
            "plugin_output": self.plugin_output,
            "credentialed": self.credentialed,
            "host_properties": self.host_properties,
            "raw": self.raw,
            "duplicate_candidate_of": self.duplicate_candidate_of,
            "verification_requirements": self.verification_requirements,
            "disposition": self.disposition.value,
            "verdict": self.verdict.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            finding_id=data["finding_id"],
            fingerprint=data["fingerprint"],
            asset_id=data["asset_id"],
            provenance=SourceProvenance.from_dict(data.get("provenance", {})),
            plugin_id=data.get("plugin_id", ""),
            plugin_name=data.get("plugin_name", ""),
            plugin_family=data.get("plugin_family", ""),
            severity=Severity(data.get("severity", 0)),
            risk_factor=data.get("risk_factor", ""),
            cvss=dict(data.get("cvss", {})),
            cves=list(data.get("cves", [])),
            cpes=list(data.get("cpes", [])),
            references=list(data.get("references", [])),
            exploitability=dict(data.get("exploitability", {})),
            port=int(data.get("port", 0)),
            transport=Transport(data.get("transport", Transport.NONE.value)),
            application_protocol=data.get("application_protocol", ""),
            service=data.get("service", ""),
            synopsis=data.get("synopsis", ""),
            description=data.get("description", ""),
            solution=data.get("solution", ""),
            plugin_output=data.get("plugin_output", ""),
            credentialed=data.get("credentialed"),
            host_properties=dict(data.get("host_properties", {})),
            raw=dict(data.get("raw", {})),
            duplicate_candidate_of=list(data.get("duplicate_candidate_of", [])),
            verification_requirements=list(data.get("verification_requirements", [])),
            disposition=Disposition(
                data.get("disposition", Disposition.PENDING_CLASSIFICATION.value)
            ),
            verdict=Verdict(data.get("verdict", Verdict.UNREVIEWED.value)),
        )
