"""Nessus / Tenable CSV importer.

Maps the common Tenable CSV export columns into normalized records. Each data
row becomes one finding; nothing is dropped. Column matching is
case-insensitive and tolerant of the header variations Tenable products emit.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from vapt_verify.importers.base import ImportResult
from vapt_verify.importers.common import normalize_records
from vapt_verify.utilities.hashing import sha256_file

_RISK_TO_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "info": 0}


def _get(row: dict[str, str], *names: str) -> str:
    lowered = {k.lower().strip(): v for k, v in row.items() if k}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()] is not None:
            return lowered[name.lower()].strip()
    return ""


class NessusCsvImporter:
    source_scanner = "nessus-csv"

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id

    def import_file(self, path: str | Path) -> ImportResult:
        source = Path(path)
        file_hash = sha256_file(source)
        records: list[dict[str, Any]] = []
        with open(source, newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                records.append(self._to_record(row))
        return normalize_records(
            engagement_id=self.engagement_id,
            source_scanner=self.source_scanner,
            source_file=source.name,
            source_file_hash=file_hash,
            records=records,
        )

    def _to_record(self, row: dict[str, str]) -> dict[str, Any]:
        risk = _get(row, "Risk", "Risk Factor").lower()
        severity_raw = _get(row, "Severity")
        severity = severity_raw if severity_raw else _RISK_TO_SEVERITY.get(risk, 0)
        cve = _get(row, "CVE")
        cves = [c.strip() for c in cve.replace(";", ",").split(",") if c.strip()]
        port_raw = _get(row, "Port")
        return {
            "host_ip": _get(row, "Host", "IP Address", "IP"),
            "host_name": _get(row, "DNS Name", "NetBIOS Name", "FQDN"),
            "port": int(port_raw) if port_raw.isdigit() else 0,
            "transport": _get(row, "Protocol") or "tcp",
            "service": _get(row, "Service", "Service Name"),
            "plugin_id": _get(row, "Plugin ID", "Plugin"),
            "plugin_name": _get(row, "Name", "Plugin Name"),
            "plugin_family": _get(row, "Family", "Plugin Family"),
            "severity": severity,
            "risk_factor": _get(row, "Risk", "Risk Factor"),
            "cves": cves,
            "synopsis": _get(row, "Synopsis"),
            "description": _get(row, "Description"),
            "solution": _get(row, "Solution"),
            "plugin_output": _get(row, "Plugin Output", "Plugin Text"),
            "references": [r for r in _get(row, "See Also").splitlines() if r],
            "source_scanner": self.source_scanner,
            "raw": dict(row),
        }
