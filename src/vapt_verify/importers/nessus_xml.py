"""Nessus ``.nessus`` (NessusClientData_v2) importer.

Design goals, in priority order:

1. **Losslessness.** Every ``<ReportItem>`` becomes exactly one normalized
   finding, or one explicitly recorded :class:`ParseFailure`. Nothing is
   silently dropped. In particular:
     * port-zero / host-level findings are retained (fixes legacy 2.2);
     * transport (tcp/udp/...) is retained separately from the port (fixes 2.5);
     * the full plugin output, synopsis, description, solution, CVEs, CPEs,
       CVSS vectors and every unmodelled source element are preserved in
       ``Finding.raw`` (fixes 2.1/2.3/2.4).
2. **Safety.** Parsing uses ``defusedxml`` with entity expansion and external
   entity resolution forbidden, so a hostile scan file cannot trigger XML
   entity-expansion or SSRF attacks.
3. **Streaming.** Parsing uses ``iterparse`` and clears each host subtree after
   processing, so large exports do not have to be held in memory at once.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import iterparse

from vapt_verify.importers.base import ImportResult, ParseFailure
from vapt_verify.models.asset import Asset
from vapt_verify.models.enums import ObservationSource, Severity, Transport
from vapt_verify.models.finding import Finding, SourceProvenance
from vapt_verify.models.service import ServiceObservation, ServiceObservationDraft
from vapt_verify.utilities.hashing import sha256_file, sha256_text
from vapt_verify.utilities.ids import (
    asset_id as make_asset_id,
)
from vapt_verify.utilities.ids import (
    finding_fingerprint,
    finding_id,
    service_id,
)

# Multi-valued elements (there can be several per ReportItem).
_CVE_TAG = "cve"
_CPE_TAG = "cpe"
_REFERENCE_TAGS = {"see_also", "xref", "bid", "cert", "iava", "iavb", "osvdb", "cwe"}
_EXPLOIT_TAGS = {
    "exploit_available",
    "exploitability_ease",
    "exploit_framework_canvas",
    "exploit_framework_core",
    "exploit_framework_metasploit",
    "exploit_framework_d2_elliot",
    "metasploit_name",
    "canvas_package",
    "d2_elliot_name",
    "in_the_news",
    "unsupported_by_vendor",
}
# Service names that imply TLS/SSL wrapping.
_TLS_SERVICES = {
    "https",
    "smtps",
    "imaps",
    "pop3s",
    "ldaps",
    "ftps",
    "ssl",
    "tls",
    "rdp",
    "nntps",
    "telnets",
}


def _localname(tag: str) -> str:
    """Strip any XML namespace, returning the local element/attribute name."""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _text(value: str | None) -> str:
    return value.strip() if value else ""


class NessusImporter:
    """Streaming, lossless importer for Nessus ``.nessus`` XML files."""

    source_scanner = "nessus"

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id

    def import_file(self, path: str | Path) -> ImportResult:
        source_path = Path(path)
        file_hash = sha256_file(source_path)
        import_id = uuid.uuid4().hex
        now = _dt.datetime.now(_dt.UTC).isoformat()

        result = ImportResult(
            import_id=import_id,
            source_scanner=self.source_scanner,
            source_file=source_path.name,
            source_file_hash=file_hash,
            import_timestamp=now,
        )

        # Report/policy-level provenance captured as we stream.
        report_name = ""
        policy_name = ""

        # Per-host state.
        current_host_name = ""
        current_host_props: dict[str, Any] = {}
        host_item_index = 0
        # asset_key -> Asset (built lazily, one per host record group).
        assets: dict[str, Asset] = {}
        # (asset_key, port, transport, vhost) -> service draft
        service_drafts: dict[tuple[str, int, str, str], ServiceObservationDraft] = {}

        context = iterparse(str(source_path), events=("start", "end"))
        for event, elem in context:
            tag = _localname(elem.tag)

            if event == "start":
                if tag == "Report":
                    report_name = elem.get("name", "")
                elif tag == "ReportHost":
                    current_host_name = elem.get("name", "")
                    current_host_props = {}
                    host_item_index = 0
                continue

            # event == "end"
            if tag == "policyName":
                policy_name = _text(elem.text)
            elif tag == "HostProperties":
                current_host_props = self._parse_host_properties(elem)
            elif tag == "ReportItem":
                result.source_report_item_count += 1
                host_key = self._host_key(current_host_name, current_host_props)
                asset = self._ensure_asset(assets, host_key, current_host_name, current_host_props)
                try:
                    finding = self._build_finding(
                        elem=elem,
                        host_key=host_key,
                        asset_id_value=asset.asset_id,
                        occurrence=host_item_index,
                        host_props=current_host_props,
                        provenance_base=SourceProvenance(
                            source_scanner=self.source_scanner,
                            source_file=source_path.name,
                            source_file_hash=file_hash,
                            report_name=report_name,
                            policy_name=policy_name,
                            import_id=import_id,
                            import_timestamp=now,
                            scan_start=str(current_host_props.get("HOST_START", "")),
                            scan_end=str(current_host_props.get("HOST_END", "")),
                            scan_date=str(current_host_props.get("HOST_START", "")),
                        ),
                    )
                except _MalformedRecord as exc:
                    result.parse_failures.append(
                        ParseFailure(
                            source_record_id=exc.source_record_id,
                            host_key=host_key,
                            reason=exc.reason,
                            raw_excerpt=exc.raw_excerpt,
                        )
                    )
                else:
                    result.findings.append(finding)
                    self._accumulate_service(service_drafts, finding, host_key)
                host_item_index += 1
            elif tag == "ReportHost":
                result.source_host_count += 1
                # Free the processed host subtree to keep memory bounded.
                elem.clear()

        result.assets = list(assets.values())
        result.services = self._finalize_services(service_drafts, now)
        self._mark_duplicate_candidates(result.findings)
        return result

    # -- host parsing -------------------------------------------------------

    def _parse_host_properties(self, elem: Any) -> dict[str, Any]:
        props: dict[str, Any] = {}
        for child in elem:
            if _localname(child.tag) != "tag":
                continue
            name = child.get("name", "")
            value = _text(child.text)
            if not name:
                continue
            if name in props:
                existing = props[name]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    props[name] = [existing, value]
            else:
                props[name] = value
        return props

    def _host_key(self, host_name: str, props: dict[str, Any]) -> str:
        """Best stable key for the asset: prefer host-ip, then name, then fqdn."""
        for candidate in (
            props.get("host-ip"),
            host_name,
            props.get("host-fqdn"),
            props.get("host-rdns"),
            props.get("netbios-name"),
        ):
            if isinstance(candidate, list):
                candidate = candidate[0] if candidate else ""
            if candidate:
                return str(candidate)
        return host_name or "unknown-host"

    def _ensure_asset(
        self,
        assets: dict[str, Asset],
        host_key: str,
        host_name: str,
        props: dict[str, Any],
    ) -> Asset:
        if host_key in assets:
            return assets[host_key]

        def as_list(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, list):
                return [str(v) for v in value if v]
            return [str(value)] if value else []

        ips = as_list(props.get("host-ip"))
        fqdns = as_list(props.get("host-fqdn"))
        hostnames = as_list(props.get("netbios-name")) + as_list(props.get("host-rdns"))
        os_obs = as_list(props.get("operating-system")) + as_list(props.get("os"))
        macs = as_list(props.get("mac-address"))

        confidence = ""
        if not ips:
            confidence = (
                "No host-ip reported by scanner; asset identity derived from "
                f"'{host_key}'. One IP is not assumed to be one permanent asset."
            )

        asset = Asset(
            asset_id=make_asset_id(self.engagement_id, primary_key=host_key),
            primary_key=host_key,
            ip_addresses=ips,
            hostnames=hostnames,
            fqdns=fqdns,
            scanner_host_name=host_name,
            mac_addresses=macs,
            os_observations=os_obs,
            source_provenance=[f"nessus:{host_name}"],
            identity_confidence_notes=confidence,
        )
        assets[host_key] = asset
        return asset

    # -- finding parsing ----------------------------------------------------

    def _build_finding(
        self,
        *,
        elem: Any,
        host_key: str,
        asset_id_value: str,
        occurrence: int,
        host_props: dict[str, Any],
        provenance_base: SourceProvenance,
    ) -> Finding:
        attrs = {_localname(k): v for k, v in elem.attrib.items()}
        plugin_id = _text(attrs.get("pluginID"))
        plugin_name = _text(attrs.get("pluginName"))
        protocol_raw = _text(attrs.get("protocol"))
        svc_name = _text(attrs.get("svc_name"))
        port_raw = attrs.get("port")

        source_record_id = (
            f"{host_key}::plugin={plugin_id or '?'}::"
            f"{port_raw if port_raw is not None else '?'}/{protocol_raw or '?'}::#{occurrence}"
        )

        # The single deterministic "malformed" condition: a present but
        # non-integer port. Without a valid port we cannot place the finding, so
        # we fail *explicitly* (counted + recoverable) rather than mangling it.
        if port_raw is not None and not _is_int(port_raw):
            raise _MalformedRecord(
                source_record_id=source_record_id,
                reason=f"port attribute {port_raw!r} is not an integer",
                raw_excerpt=_excerpt(elem),
            )
        port = int(port_raw) if port_raw is not None else 0
        transport = Transport.from_nessus(protocol_raw or None, port=port)

        # Gather child elements, preserving everything in raw.
        elements: dict[str, Any] = {}
        cves: list[str] = []
        cpes: list[str] = []
        references: list[str] = []
        exploitability: dict[str, Any] = {}
        cvss: dict[str, Any] = {}
        for child in elem:
            ctag = _localname(child.tag)
            cval = _text(child.text)
            self._collect_element(elements, ctag, cval)
            if ctag == _CVE_TAG and cval:
                cves.append(cval)
            elif ctag == _CPE_TAG and cval:
                cpes.append(cval)
            elif ctag in _REFERENCE_TAGS and cval:
                references.append(cval)
            elif ctag in _EXPLOIT_TAGS and cval:
                exploitability[ctag] = cval
            elif ctag.startswith("cvss") or ctag.startswith("vpr"):
                cvss[ctag] = cval

        plugin_output = str(elements.get("plugin_output", "") or "")
        output_digest = sha256_text(plugin_output)[:16] if plugin_output else "no-output"

        fingerprint = finding_fingerprint(
            plugin_id=plugin_id or plugin_name,
            host_key=host_key,
            port=port,
            transport=transport.value,
            service=svc_name,
            plugin_output_digest=output_digest,
            cves=cves,
        )
        fid = finding_id(
            source_file_hash=provenance_base.source_file_hash,
            host_key=host_key,
            occurrence=occurrence,
            fingerprint=fingerprint,
        )

        provenance = SourceProvenance(**{**provenance_base.to_dict()})
        provenance.source_record_id = source_record_id

        credentialed = self._credentialed(host_props)

        finding = Finding(
            finding_id=fid,
            fingerprint=fingerprint,
            asset_id=asset_id_value,
            provenance=provenance,
            plugin_id=plugin_id,
            plugin_name=plugin_name,
            plugin_family=_text(attrs.get("pluginFamily")),
            severity=Severity.from_nessus(attrs.get("severity")),
            risk_factor=str(elements.get("risk_factor", "") or ""),
            cvss=cvss,
            cves=_dedupe(cves),
            cpes=_dedupe(cpes),
            references=_dedupe(references),
            exploitability=exploitability,
            port=port,
            transport=transport,
            application_protocol=self._application_protocol(svc_name),
            service=svc_name,
            synopsis=str(elements.get("synopsis", "") or ""),
            description=str(elements.get("description", "") or ""),
            solution=str(elements.get("solution", "") or ""),
            plugin_output=plugin_output,
            credentialed=credentialed,
            host_properties=host_props,
            raw={"attributes": attrs, "elements": elements},
        )
        return finding

    def _collect_element(self, elements: dict[str, Any], tag: str, value: str) -> None:
        """Store an element value, promoting to a list on repeats (lossless)."""
        if tag in elements:
            existing = elements[tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                elements[tag] = [existing, value]
        else:
            elements[tag] = value

    def _application_protocol(self, svc_name: str) -> str:
        name = svc_name.lower()
        if name in {"www", "http", "http-proxy", "http-alt"}:
            return "http"
        if name == "https":
            return "http"  # HTTP over TLS
        if name in {"smtp", "smtps"}:
            return "smtp"
        return name if name and name != "general" else ""

    def _credentialed(self, props: dict[str, Any]) -> bool | None:
        raw = props.get("Credentialed_Scan")
        if raw is None:
            return None
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if raw is None:
            return None
        return str(raw).strip().lower() in {"true", "1", "yes"}

    # -- services -----------------------------------------------------------

    def _accumulate_service(
        self,
        drafts: dict[tuple[str, int, str, str], ServiceObservationDraft],
        finding: Finding,
        host_key: str,
    ) -> None:
        # Host-level (port 0) findings do not create a service observation.
        if finding.port == 0:
            return
        vhost = ""
        key = (host_key, finding.port, finding.transport.value, vhost)
        draft = drafts.get(key)
        if draft is None:
            draft = ServiceObservationDraft(
                asset_key=finding.asset_id,
                port=finding.port,
                transport=finding.transport,
                application_protocol=finding.application_protocol,
                service_name=finding.service,
                tls=finding.service.lower() in _TLS_SERVICES,
                vhost=vhost,
            )
            drafts[key] = draft
        draft.sources.add(finding.finding_id)
        if not draft.service_name and finding.service:
            draft.service_name = finding.service

    def _finalize_services(
        self,
        drafts: dict[tuple[str, int, str, str], ServiceObservationDraft],
        timestamp: str,
    ) -> list[ServiceObservation]:
        services: list[ServiceObservation] = []
        for (_host_key, port, transport_value, vhost), draft in drafts.items():
            sid = service_id(draft.asset_key, port=port, transport=transport_value, vhost=vhost)
            services.append(
                ServiceObservation(
                    service_id=sid,
                    asset_id=draft.asset_key,
                    port=port,
                    transport=Transport(transport_value),
                    application_protocol=draft.application_protocol,
                    service_name=draft.service_name,
                    tls=draft.tls,
                    vhost=vhost,
                    # Crucial distinction (legacy 2.6): the scanner *referenced*
                    # this port. That is NOT proof it is currently open.
                    observation_source=ObservationSource.SCANNER_REFERENCED,
                    observation_timestamp=timestamp,
                    confidence="scanner_referenced",
                )
            )
        return services

    # -- duplicate candidates ----------------------------------------------

    def _mark_duplicate_candidates(self, findings: list[Finding]) -> None:
        """Link findings that share a fingerprint. They are retained separately.

        Duplicate *candidates* are surfaced for reviewer attention; they are
        never merged automatically (legacy failure mode 2.4).
        """
        by_fingerprint: dict[str, list[Finding]] = {}
        for finding in findings:
            by_fingerprint.setdefault(finding.fingerprint, []).append(finding)
        for group in by_fingerprint.values():
            if len(group) < 2:
                continue
            ids = [f.finding_id for f in group]
            for finding in group:
                finding.duplicate_candidate_of = [i for i in ids if i != finding.finding_id]


class _MalformedRecord(Exception):
    """Internal signal that a source item cannot be normalized."""

    def __init__(self, *, source_record_id: str, reason: str, raw_excerpt: str) -> None:
        super().__init__(reason)
        self.source_record_id = source_record_id
        self.reason = reason
        self.raw_excerpt = raw_excerpt


def _is_int(value: Any) -> bool:
    try:
        int(value)
    except (TypeError, ValueError):
        return False
    return True


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _excerpt(elem: Any, limit: int = 500) -> str:
    attrs = " ".join(f'{_localname(k)}="{v}"' for k, v in elem.attrib.items())
    return f"<ReportItem {attrs}>...".strip()[:limit]
