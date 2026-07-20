"""Shared normalization for all importers.

Every importer parses its own format into a list of plain record dicts and hands
them here. This keeps scanner-specific schemas out of the core finding model
(task section 23, v0.8): the canonical Finding/Asset/Service shape is built in
exactly one place, with the same provenance, fingerprinting and duplicate-
candidate handling as the Nessus XML importer.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any

from vapt_verify.importers.base import ImportResult
from vapt_verify.models.asset import Asset
from vapt_verify.models.enums import ObservationSource, Severity, Transport
from vapt_verify.models.finding import Finding, SourceProvenance
from vapt_verify.models.service import ServiceObservation
from vapt_verify.utilities.hashing import sha256_text
from vapt_verify.utilities.ids import asset_id as make_asset_id
from vapt_verify.utilities.ids import finding_fingerprint, finding_id, service_id

_TLS_SERVICES = {"https", "smtps", "imaps", "pop3s", "ldaps", "ftps", "ssl", "tls"}


def normalize_records(
    *,
    engagement_id: str,
    source_scanner: str,
    source_file: str,
    source_file_hash: str,
    records: list[dict[str, Any]],
) -> ImportResult:
    """Build a full ImportResult from generic record dicts.

    Recognised record keys (all optional except a host identifier): host_ip,
    host_name, hostnames, fqdns, os, port, transport, service, plugin_id,
    plugin_name, plugin_family, severity (int), risk_factor, cves, cpes,
    references, synopsis, description, solution, plugin_output, credentialed,
    host_properties, raw, source_record_id.
    """
    import_id = uuid.uuid4().hex
    now = _dt.datetime.now(_dt.UTC).isoformat()
    result = ImportResult(
        import_id=import_id,
        source_scanner=source_scanner,
        source_file=source_file,
        source_file_hash=source_file_hash,
        import_timestamp=now,
    )
    result.source_report_item_count = len(records)

    assets: dict[str, Asset] = {}
    host_seen: set[str] = set()
    host_occurrence: dict[str, int] = {}
    service_keys: dict[tuple[str, int, str], str] = {}
    services: list[ServiceObservation] = []

    for record in records:
        host_key = _host_key(record)
        if host_key not in host_seen:
            host_seen.add(host_key)
            result.source_host_count += 1
        asset = _ensure_asset(assets, engagement_id, host_key, record)
        occurrence = host_occurrence.get(host_key, 0)
        host_occurrence[host_key] = occurrence + 1

        port = int(record.get("port", 0) or 0)
        transport = Transport.from_nessus(record.get("transport"), port=port)
        service_name = str(record.get("service", "") or "")
        plugin_output = str(record.get("plugin_output", "") or "")
        cves = [str(c) for c in record.get("cves", []) if c]
        output_digest = sha256_text(plugin_output)[:16] if plugin_output else "no-output"
        plugin_id = str(record.get("plugin_id", "") or "")
        plugin_name = str(record.get("plugin_name", "") or "")

        fingerprint = finding_fingerprint(
            plugin_id=plugin_id or plugin_name,
            host_key=host_key,
            port=port,
            transport=transport.value,
            service=service_name,
            plugin_output_digest=output_digest,
            cves=cves,
        )
        fid = finding_id(
            source_file_hash=source_file_hash, host_key=host_key,
            occurrence=occurrence, fingerprint=fingerprint,
        )
        provenance = SourceProvenance(
            source_scanner=source_scanner, source_file=source_file,
            source_file_hash=source_file_hash, import_id=import_id, import_timestamp=now,
            source_record_id=str(record.get("source_record_id", f"{host_key}#{occurrence}")),
        )
        finding = Finding(
            finding_id=fid, fingerprint=fingerprint, asset_id=asset.asset_id,
            provenance=provenance,
            plugin_id=plugin_id, plugin_name=plugin_name,
            plugin_family=str(record.get("plugin_family", "") or ""),
            severity=Severity.from_nessus(record.get("severity")),
            risk_factor=str(record.get("risk_factor", "") or ""),
            cves=cves, cpes=[str(c) for c in record.get("cpes", []) if c],
            references=[str(r) for r in record.get("references", []) if r],
            port=port, transport=transport,
            service=service_name,
            synopsis=str(record.get("synopsis", "") or ""),
            description=str(record.get("description", "") or ""),
            solution=str(record.get("solution", "") or ""),
            plugin_output=plugin_output,
            credentialed=record.get("credentialed"),
            host_properties=dict(record.get("host_properties", {})),
            raw=dict(record.get("raw", {})),
        )
        result.findings.append(finding)

        if port > 0:
            key = (host_key, port, transport.value)
            if key not in service_keys:
                sid = service_id(asset.asset_id, port=port, transport=transport.value)
                service_keys[key] = sid
                services.append(ServiceObservation(
                    service_id=sid, asset_id=asset.asset_id, port=port, transport=transport,
                    service_name=service_name, tls=service_name.lower() in _TLS_SERVICES,
                    observation_source=ObservationSource.SCANNER_REFERENCED,
                    observation_timestamp=now, confidence="scanner_referenced",
                ))

    result.assets = list(assets.values())
    result.services = services
    _mark_duplicates(result.findings)
    return result


def _host_key(record: dict[str, Any]) -> str:
    for key in ("host_ip", "host_name"):
        value = record.get(key)
        if value:
            return str(value)
    hostnames = record.get("hostnames") or []
    if hostnames:
        return str(hostnames[0])
    return "unknown-host"


def _ensure_asset(
    assets: dict[str, Asset], engagement_id: str, host_key: str, record: dict[str, Any]
) -> Asset:
    if host_key in assets:
        return assets[host_key]
    ips = [str(record["host_ip"])] if record.get("host_ip") else []
    asset = Asset(
        asset_id=make_asset_id(engagement_id, primary_key=host_key),
        primary_key=host_key,
        ip_addresses=ips,
        hostnames=[str(h) for h in record.get("hostnames", []) if h],
        fqdns=[str(f) for f in record.get("fqdns", []) if f],
        scanner_host_name=str(record.get("host_name", "") or ""),
        os_observations=[str(o) for o in record.get("os", []) if o],
        source_provenance=[f"{record.get('source_scanner', 'import')}:{host_key}"],
    )
    assets[host_key] = asset
    return asset


def _mark_duplicates(findings: list[Finding]) -> None:
    by_fp: dict[str, list[Finding]] = {}
    for f in findings:
        by_fp.setdefault(f.fingerprint, []).append(f)
    for group in by_fp.values():
        if len(group) < 2:
            continue
        ids = [f.finding_id for f in group]
        for f in group:
            f.duplicate_candidate_of = [i for i in ids if i != f.finding_id]
