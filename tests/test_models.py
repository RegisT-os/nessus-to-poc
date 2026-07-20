"""Model serialization and enum-mapping tests."""

from __future__ import annotations

from vapt_verify.models.asset import Asset
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.enums import Disposition, Severity, Transport, Verdict
from vapt_verify.models.finding import Finding, SourceProvenance
from vapt_verify.models.service import ServiceObservation


def test_severity_from_nessus_is_lossless_and_safe() -> None:
    assert Severity.from_nessus("0") is Severity.INFORMATIONAL
    assert Severity.from_nessus("4") is Severity.CRITICAL
    assert Severity.from_nessus(None) is Severity.INFORMATIONAL
    assert Severity.from_nessus("garbage") is Severity.INFORMATIONAL
    assert Severity.from_nessus("9") is Severity.CRITICAL  # clamped, not dropped


def test_transport_defaults_to_none_for_port_zero() -> None:
    assert Transport.from_nessus(None, port=0) is Transport.NONE
    assert Transport.from_nessus("tcp", port=443) is Transport.TCP
    assert Transport.from_nessus("weird", port=443) is Transport.UNKNOWN


def test_finding_round_trip() -> None:
    finding = Finding(
        finding_id="find-1",
        fingerprint="fp-1",
        asset_id="asset-1",
        provenance=SourceProvenance(source_file="s.nessus", source_file_hash="abc"),
        plugin_id="51192",
        plugin_name="SSL Cert",
        severity=Severity.MEDIUM,
        port=443,
        transport=Transport.TCP,
        cves=["CVE-2026-0001"],
        plugin_output="evidence",
        disposition=Disposition.PENDING_CLASSIFICATION,
        verdict=Verdict.UNREVIEWED,
        raw={"attributes": {"pluginID": "51192"}, "elements": {"x": "y"}},
    )
    restored = Finding.from_dict(finding.to_dict())
    assert restored == finding


def test_service_round_trip() -> None:
    svc = ServiceObservation(
        service_id="svc-1", asset_id="asset-1", port=161, transport=Transport.UDP,
        service_name="snmp",
    )
    assert ServiceObservation.from_dict(svc.to_dict()) == svc


def test_asset_round_trip() -> None:
    asset = Asset(asset_id="asset-1", primary_key="192.0.2.10", ip_addresses=["192.0.2.10"])
    assert Asset.from_dict(asset.to_dict()) == asset


def test_engagement_yaml_round_trip() -> None:
    eng = Engagement(
        engagement_id="e1", client_alias="ExampleBank", engagement_type="internal",
        approved_cidrs=["192.0.2.0/24"], credential_references=["vault://x"],
    )
    restored = Engagement.from_yaml(eng.to_yaml())
    assert restored == eng
    # Ensure no plaintext secret sneaks in via credential handling.
    assert restored.credential_references == ["vault://x"]
