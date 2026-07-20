"""Import statistics (task section 14).

These counts are informational and are stored in the import manifest and
coverage reports. Every count is derived from the normalized objects, so they
always describe exactly what was imported.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from vapt_verify.importers.base import ImportResult
from vapt_verify.models.enums import Transport

# Element tags the importer surfaces as first-class finding attributes. Any
# other element is preserved in Finding.raw but flagged here as "unmodelled" so
# reviewers can see what extra scanner detail exists (transparency, not loss).
_MODELLED_ELEMENT_TAGS = {
    "synopsis",
    "description",
    "solution",
    "plugin_output",
    "risk_factor",
    "cve",
    "cpe",
    "see_also",
    "xref",
}


def compute_statistics(result: ImportResult) -> dict[str, Any]:
    findings = result.findings

    by_severity: Counter[str] = Counter()
    by_family: Counter[str] = Counter()
    by_plugin: Counter[str] = Counter()
    by_host: Counter[str] = Counter()
    by_port: Counter[str] = Counter()
    unmodelled_tags: set[str] = set()

    port_zero = 0
    tcp = 0
    udp = 0
    no_cve = 0
    no_output = 0
    credentialed = 0
    informational = 0
    duplicate_candidates = 0

    for f in findings:
        by_severity[f.severity.name] += 1
        by_family[f.plugin_family or "(none)"] += 1
        by_plugin[f.plugin_id or "(none)"] += 1
        by_host[f.asset_id] += 1
        by_port[f"{f.port}/{f.transport.value}"] += 1
        if f.port == 0:
            port_zero += 1
        if f.transport is Transport.TCP:
            tcp += 1
        elif f.transport is Transport.UDP:
            udp += 1
        if not f.cves:
            no_cve += 1
        if not f.plugin_output:
            no_output += 1
        if f.credentialed:
            credentialed += 1
        if f.is_informational:
            informational += 1
        if f.duplicate_candidate_of:
            duplicate_candidates += 1
        for tag in f.raw.get("elements", {}):
            if tag not in _MODELLED_ELEMENT_TAGS:
                unmodelled_tags.add(tag)

    return {
        "source_host_count": result.source_host_count,
        "source_report_item_count": result.source_report_item_count,
        "normalized_finding_count": len(findings),
        "findings_by_severity": dict(by_severity),
        "findings_by_plugin_family": dict(by_family),
        "distinct_plugin_ids": len(by_plugin),
        "findings_by_host": dict(by_host),
        "distinct_ports": len(by_port),
        "findings_by_port": dict(by_port),
        "port_zero_findings": port_zero,
        "tcp_findings": tcp,
        "udp_findings": udp,
        "findings_with_no_cve": no_cve,
        "findings_with_no_plugin_output": no_output,
        "credentialed_findings": credentialed,
        "informational_findings": informational,
        "parsing_failures": result.parse_failure_count,
        # Unmodelled fields are *preserved* (in Finding.raw), never dropped;
        # listing them keeps the "no silent loss" promise auditable.
        "unmodelled_element_tags": sorted(unmodelled_tags),
        "duplicate_candidates": duplicate_candidates,
        "suppressed_records": 0,
    }
