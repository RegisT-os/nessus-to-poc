"""Contrast tests: prove the legacy script loses findings the new importer keeps.

These lock in the exact finding-loss mechanisms documented in
docs/LEGACY_FAILURE_ANALYSIS.md so we can prove the regression is fixed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.importers.nessus_xml import NessusImporter

_LEGACY_PATH = Path(__file__).resolve().parents[1] / "legacy" / "nmap_legacy.py"


def _load_legacy() -> object:
    spec = importlib.util.spec_from_file_location("nmap_legacy", _LEGACY_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mixed_scan(tmp_path: Path) -> Path:
    items = [
        # Covered by legacy mapping, non-zero port -> legacy keeps this one.
        report_item(plugin_id="51192", plugin_name="SSL Certificate Cannot Be Trusted",
                    port=443, protocol="tcp", severity=2),
        # Host-level (port 0) patch finding -> legacy DROPS (failure mode 2.2).
        report_item(plugin_id="123456", plugin_name="Missing OS Patch", port=0,
                    protocol="tcp", severity=3, cves=["CVE-2026-0001"]),
        # Not in legacy mapping -> legacy DROPS (failure mode 2.1).
        report_item(plugin_id="99999", plugin_name="Novel App Misconfiguration",
                    port=8080, protocol="tcp", severity=3),
        # Lowercase name -> legacy DROPS (failure mode 2.3, case-sensitive).
        report_item(plugin_id="51192", plugin_name="ssl certificate cannot be trusted",
                    port=8443, protocol="tcp", severity=2),
        # UDP finding -> legacy keeps port but forgets transport (failure mode 2.5).
        report_item(plugin_id="41028", plugin_name="SNMP Default Community",
                    port=161, protocol="udp", severity=2),
    ]
    host = report_host(name="192.0.2.10", props=default_host_props("192.0.2.10"), items=items)
    path = tmp_path / "mixed.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    return path


def test_new_importer_keeps_everything_legacy_drops(tmp_path: Path) -> None:
    scan = _mixed_scan(tmp_path)

    # New importer: all five report items become findings.
    new = NessusImporter(engagement_id="e").import_file(scan)
    assert new.source_report_item_count == 5
    assert new.normalized_finding_count == 5

    # Legacy: collapses to name -> host -> {ports}, dropping port-0, the
    # unsupported plugin and the lowercase-named one.
    legacy = _load_legacy()
    results, all_open_ports = legacy.parse_nessus(str(scan))  # type: ignore[attr-defined]

    kept_vuln_names = set(results.keys())
    # Only the exact-case, non-zero-port, mapped finding survives.
    assert kept_vuln_names == {"SSL Certificate Cannot Be Trusted"}

    # Port-0 finding never even reaches the legacy "open ports" set.
    assert "0" not in all_open_ports.get("192.0.2.10", set())

    # The new inventory contains the findings legacy lost.
    plugin_names = {f.plugin_name for f in new.findings}
    assert "Missing OS Patch" in plugin_names
    assert "Novel App Misconfiguration" in plugin_names
    assert "ssl certificate cannot be trusted" in plugin_names


def test_legacy_loses_transport_but_new_keeps_it(tmp_path: Path) -> None:
    scan = _mixed_scan(tmp_path)
    new = NessusImporter(engagement_id="e").import_file(scan)
    udp_findings = [f for f in new.findings if f.service == "" or f.transport.value == "udp"]
    assert any(f.transport.value == "udp" for f in new.findings)

    legacy = _load_legacy()
    # Legacy build_commands always emits TCP SYN scans, regardless of transport.
    results, _ = legacy.parse_nessus(str(scan))  # type: ignore[attr-defined]
    commands = legacy.build_commands(results)  # type: ignore[attr-defined]
    for _name, _host, cmd in commands:
        assert "-sU" not in cmd  # legacy never scans UDP correctly
    assert udp_findings  # but the new model retained the UDP finding
