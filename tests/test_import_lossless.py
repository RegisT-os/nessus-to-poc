"""Regression tests for the lossless-import invariant.

These map directly onto the mandatory regression tests in the task brief
(section 22). Each test pins a legacy failure mode that must never recur.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nessus_builder import (
    default_host_props,
    nessus_document,
    report_host,
    report_item,
)
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.enums import Severity, Transport

FIXTURES = Path(__file__).parent / "fixtures"


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _import(tmp_path: Path, doc: str, name: str = "scan.nessus") -> object:
    path = _write(tmp_path, name, doc)
    return NessusImporter(engagement_id="eng-test").import_file(path)


def test_100_report_items_produce_100_findings(tmp_path: Path) -> None:
    """Task 22.1 — a file with 100 report items produces 100 findings."""
    items = [
        report_item(
            plugin_id=str(10000 + i),
            plugin_name=f"Synthetic Finding {i}",
            port=(0 if i % 7 == 0 else 1000 + i),
            protocol=("udp" if i % 5 == 0 else "tcp"),
            severity=i % 5,
            plugin_output=(None if i % 3 == 0 else f"evidence line {i}"),
        )
        for i in range(100)
    ]
    # Spread across four hosts to exercise per-host indexing.
    hosts = []
    for h in range(4):
        chunk = items[h * 25 : (h + 1) * 25]
        hosts.append(
            report_host(
                name=f"192.0.2.{10 + h}",
                props=default_host_props(f"192.0.2.{10 + h}"),
                items=chunk,
            )
        )
    result = _import(tmp_path, nessus_document(hosts=hosts))
    assert result.source_report_item_count == 100
    assert result.normalized_finding_count == 100
    assert len(result.parse_failures) == 0


def test_finding_absent_from_legacy_mapping_is_retained(tmp_path: Path) -> None:
    """Task 22.2 — a finding not in the legacy VULNERABILITIES list survives."""
    item = report_item(
        plugin_id="99999",
        plugin_name="Totally Novel Application Misconfiguration",
        port=8443,
        protocol="tcp",
        severity=3,
    )
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.normalized_finding_count == 1
    assert result.findings[0].plugin_name == "Totally Novel Application Misconfiguration"


def test_port_zero_findings_are_retained(tmp_path: Path) -> None:
    """Task 22.3 — port-0 host-level findings remain present."""
    item = report_item(
        plugin_id="123456",
        plugin_name="Missing OS Patch",
        port=0,
        protocol="tcp",
        severity=3,
        cves=["CVE-2026-0001"],
    )
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.normalized_finding_count == 1
    finding = result.findings[0]
    assert finding.port == 0
    assert finding.is_host_level is True
    assert finding.transport is Transport.NONE
    # A port-0 finding must NOT create a "service observation".
    assert result.services == []


def test_udp_findings_retain_udp(tmp_path: Path) -> None:
    """Task 22.4 — UDP findings retain UDP transport."""
    item = report_item(
        plugin_id="41028", plugin_name="SNMP Default Community", port=161, protocol="udp", severity=2
    )
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.findings[0].transport is Transport.UDP
    assert result.services[0].transport is Transport.UDP


def test_plugin_output_is_preserved(tmp_path: Path) -> None:
    """Task 22.5 — plugin output remains attached."""
    output = "Remote package installed : openssl_1.1.1\nShould be : openssl_1.1.1-9"
    item = report_item(
        plugin_id="123456", plugin_name="Patch", port=0, plugin_output=output, severity=3
    )
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.findings[0].plugin_output == output


def test_multiple_findings_on_one_host_and_port_stay_distinct(tmp_path: Path) -> None:
    """Task 22.6 — multiple plugins on one host/port remain distinct findings."""
    items = [
        report_item(plugin_id="51192", plugin_name="SSL Cert Cannot Be Trusted", port=443,
                    protocol="tcp", severity=2, plugin_output="cert A"),
        report_item(plugin_id="57582", plugin_name="SSL Self-Signed Certificate", port=443,
                    protocol="tcp", severity=1, plugin_output="cert B"),
    ]
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=items)
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.normalized_finding_count == 2
    ids = {f.finding_id for f in result.findings}
    assert len(ids) == 2
    # One shared service observation for the port; two distinct findings.
    assert len(result.services) == 1


def test_multiple_scans_retain_separate_provenance(tmp_path: Path) -> None:
    """Task 22.7 — the same finding from two scans keeps separate provenance."""
    item = report_item(plugin_id="51192", plugin_name="SSL Cert Cannot Be Trusted", port=443,
                       protocol="tcp", severity=2, plugin_output="cert A")

    def make(scan_start: str) -> str:
        props = default_host_props("192.0.2.10")
        props["HOST_START"] = scan_start
        host = report_host(name="192.0.2.10", props=props, items=[item])
        return nessus_document(hosts=[host])

    first = _import(tmp_path, make("Mon Jul 20 09:00:00 2026"), name="scan1.nessus")
    second = _import(tmp_path, make("Tue Jul 21 09:00:00 2026"), name="scan2.nessus")
    assert first.source_file_hash != second.source_file_hash
    assert first.findings[0].finding_id != second.findings[0].finding_id
    assert first.findings[0].provenance.import_id != second.findings[0].provenance.import_id


def test_case_variation_in_plugin_name_does_not_cause_loss(tmp_path: Path) -> None:
    """Task 22.8 — lowercase plugin name (legacy would miss it) is retained."""
    item = report_item(plugin_id="51192", plugin_name="ssl certificate cannot be trusted",
                       port=443, protocol="tcp", severity=2)
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.normalized_finding_count == 1


def test_missing_cve_does_not_cause_loss(tmp_path: Path) -> None:
    """Task 22.9 — a finding with no CVE is retained."""
    item = report_item(plugin_id="55555", plugin_name="No CVE Finding", port=80, protocol="tcp")
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.normalized_finding_count == 1
    assert result.findings[0].cves == []


def test_missing_plugin_output_does_not_cause_loss(tmp_path: Path) -> None:
    """Task 22.10 — a finding with no plugin output is retained."""
    item = report_item(plugin_id="55556", plugin_name="No Output Finding", port=80, protocol="tcp")
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.normalized_finding_count == 1
    assert result.findings[0].plugin_output == ""


def test_informational_findings_are_retained(tmp_path: Path) -> None:
    """Task 22.11 — informational (severity 0) findings remain present."""
    item = report_item(plugin_id="10940", plugin_name="RDP Enabled (info)", port=3389,
                       protocol="tcp", severity=0)
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.findings[0].severity is Severity.INFORMATIONAL
    assert result.findings[0].is_informational is True


def test_credentialed_status_is_captured(tmp_path: Path) -> None:
    """Task 22.12 — credentialed scan status is preserved for classification."""
    item = report_item(plugin_id="123456", plugin_name="Local Check", port=0, severity=2)
    host = report_host(
        name="192.0.2.10",
        props=default_host_props("192.0.2.10", credentialed=True),
        items=[item],
    )
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.findings[0].credentialed is True


def test_duplicate_candidates_are_linked_not_merged(tmp_path: Path) -> None:
    """Task 22.23 — identical items are retained separately as duplicate candidates."""
    item = report_item(plugin_id="51192", plugin_name="SSL Cert", port=443, protocol="tcp",
                       severity=2, plugin_output="identical output")
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"),
                       items=[item, item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.normalized_finding_count == 2
    a, b = result.findings
    assert a.finding_id != b.finding_id
    assert b.finding_id in a.duplicate_candidate_of
    assert a.finding_id in b.duplicate_candidate_of


def test_unmodelled_source_elements_are_preserved_in_raw(tmp_path: Path) -> None:
    """No silent field loss — unknown elements survive in Finding.raw."""
    item = report_item(
        plugin_id="70000", plugin_name="Rich Finding", port=443, protocol="tcp", severity=2,
        extra_elements={"exotic_scanner_field": "keep-me", "plugin_type": "remote"},
    )
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    elements = result.findings[0].raw["elements"]
    assert elements["exotic_scanner_field"] == "keep-me"
    assert elements["plugin_type"] == "remote"


def test_committed_sample_fixture_imports_losslessly(tmp_path: Path) -> None:
    result = NessusImporter(engagement_id="eng-test").import_file(FIXTURES / "sample_small.nessus")
    assert result.source_report_item_count == result.normalized_finding_count == 6
    assert any(f.port == 0 for f in result.findings)  # host-level patch finding
    assert any(f.transport is Transport.UDP for f in result.findings)  # SNMP/udp
    assert any(f.is_informational for f in result.findings)  # RDP info


@pytest.mark.parametrize("proto", ["tcp", "udp", "icmp", "sctp"])
def test_transport_round_trips(tmp_path: Path, proto: str) -> None:
    item = report_item(plugin_id="1", plugin_name="p", port=123, protocol=proto, severity=1)
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=[item])
    result = _import(tmp_path, nessus_document(hosts=[host]))
    assert result.findings[0].transport is Transport(proto)
