"""Cross-scanner correlation tests (v2.0).

The v2.0 guardrails, from docs/ROADMAP.md:

* Correlation produces links and candidate groups, **never** silent
  de-duplication; a merged view must always decompose back to its sources.
* "No longer reported" is a **state**, never a deletion.
* One IP is not assumed to be one permanent asset.
"""

from __future__ import annotations

from typing import Any

from vapt_verify.correlation import (
    ChangeKind,
    CorrelationEngine,
    LinkBasis,
    diff_import_sets,
    normalize_title,
)


def _finding(
    fid: str,
    *,
    scanner: str = "nessus",
    plugin_id: str = "",
    name: str = "Finding",
    asset: str = "asset-1",
    port: int = 443,
    transport: str = "tcp",
    cves: list[str] | None = None,
    fingerprint: str = "",
    severity: str = "MEDIUM",
) -> dict[str, Any]:
    return {
        "finding_id": fid,
        "fingerprint": fingerprint or f"fp-{fid}",
        "asset_id": asset,
        "plugin_id": plugin_id,
        "plugin_name": name,
        "port": port,
        "transport": transport,
        "cves": cves or [],
        "severity_label": severity,
        "provenance": {"source_scanner": scanner},
    }


# --- core guardrail: nothing is lost or merged -----------------------------

def test_grouped_plus_singletons_equals_total() -> None:
    findings = [
        _finding("a", plugin_id="51192"),
        _finding("b", plugin_id="51192", scanner="qualys"),
        _finding("c", plugin_id="99999", name="Lonely Finding"),
    ]
    report = CorrelationEngine().correlate(findings=findings)
    assert report.total_findings == 3
    assert report.accounted_findings == 3
    assert report.totals_balance is True


def test_group_decomposes_back_to_member_findings() -> None:
    findings = [
        _finding("a", plugin_id="51192", scanner="nessus"),
        _finding("b", plugin_id="51192", scanner="nessus"),
    ]
    report = CorrelationEngine().correlate(findings=findings)
    group = report.finding_groups[0]
    # The group references its members; it does not replace them.
    assert set(group.member_finding_ids) == {"a", "b"}
    assert sum(len(ids) for ids in group.sources.values()) == 2


def test_correlation_does_not_mutate_input_findings() -> None:
    findings = [_finding("a", plugin_id="51192"), _finding("b", plugin_id="51192")]
    before = [dict(f) for f in findings]
    CorrelationEngine().correlate(findings=findings)
    assert findings == before  # inputs untouched: no merge, no rewrite


def test_uncorrelated_finding_remains_as_singleton() -> None:
    findings = [_finding("solo", plugin_id="123", name="Only One")]
    report = CorrelationEngine().correlate(findings=findings)
    assert report.finding_groups == []
    assert report.singleton_finding_ids == ["solo"]
    assert report.totals_balance is True


# --- link bases ------------------------------------------------------------

def test_identical_fingerprints_group_with_high_confidence() -> None:
    findings = [
        _finding("a", fingerprint="fp-same", plugin_id="1"),
        _finding("b", fingerprint="fp-same", plugin_id="1"),
    ]
    report = CorrelationEngine().correlate(findings=findings)
    group = report.finding_groups[0]
    assert group.basis is LinkBasis.SAME_FINGERPRINT
    assert group.confidence == "high"


def test_cross_scanner_shared_cve_is_linked() -> None:
    """Two scanners, different plugin ids, same CVE and location."""
    findings = [
        _finding("n1", scanner="nessus", plugin_id="51192", name="Nessus Name",
                 cves=["CVE-2026-1111"]),
        _finding("q1", scanner="qualys", plugin_id="38765", name="Qualys Name",
                 cves=["CVE-2026-1111"]),
    ]
    report = CorrelationEngine().correlate(findings=findings)
    cross = report.cross_scanner_groups
    assert len(cross) == 1
    assert cross[0].basis is LinkBasis.SHARED_CVE_AND_LOCATION
    assert cross[0].is_cross_scanner
    assert set(cross[0].sources) == {"nessus", "qualys"}


def test_cross_scanner_title_match_is_low_confidence() -> None:
    findings = [
        _finding("n1", scanner="nessus", plugin_id="1",
                 name="SSL Certificate Cannot Be Trusted (KB5005565)"),
        _finding("o1", scanner="openvas", plugin_id="2",
                 name="SSL certificate cannot be trusted 1.2.3"),
    ]
    report = CorrelationEngine().correlate(findings=findings)
    group = report.finding_groups[0]
    assert group.basis is LinkBasis.SAME_LOCATION_AND_TITLE
    assert group.confidence == "low"
    assert "review" in group.rationale.lower()


def test_stronger_basis_wins_over_weaker() -> None:
    """A fingerprint match must not be re-grouped by a weaker title match."""
    findings = [
        _finding("a", fingerprint="same", plugin_id="1", name="Same Title"),
        _finding("b", fingerprint="same", plugin_id="1", name="Same Title"),
    ]
    report = CorrelationEngine().correlate(findings=findings)
    assert len(report.finding_groups) == 1
    assert report.finding_groups[0].basis is LinkBasis.SAME_FINGERPRINT


def test_different_ports_are_not_correlated() -> None:
    findings = [
        _finding("a", plugin_id="51192", port=443),
        _finding("b", plugin_id="51192", port=8443),
    ]
    report = CorrelationEngine().correlate(findings=findings)
    assert report.finding_groups == []
    assert len(report.singleton_finding_ids) == 2


def test_normalize_title_strips_version_and_kb_noise() -> None:
    assert normalize_title("Foo Bar (KB5005565)") == "foo bar"
    assert normalize_title("Foo Bar 1.2.3") == "foo bar"
    assert normalize_title("Foo  Bar!") == "foo bar"


# --- asset identities ------------------------------------------------------

def _asset(aid: str, *, ips: list[str] | None = None, fqdns: list[str] | None = None,
           macs: list[str] | None = None, scanner: str = "nessus") -> dict[str, Any]:
    return {
        "asset_id": aid,
        "primary_key": (ips or ["x"])[0],
        "ip_addresses": ips or [],
        "fqdns": fqdns or [],
        "hostnames": [],
        "mac_addresses": macs or [],
        "source_provenance": [f"{scanner}:{aid}"],
    }


def test_assets_sharing_an_ip_become_a_candidate_not_a_merge() -> None:
    assets = [
        _asset("a1", ips=["192.0.2.10"], scanner="nessus"),
        _asset("a2", ips=["192.0.2.10"], scanner="nmap"),
    ]
    identities = CorrelationEngine().correlate_assets(assets)
    assert len(identities) == 1
    identity = identities[0]
    assert set(identity.member_asset_ids) == {"a1", "a2"}
    assert identity.confidence == "medium"  # shared IP is not proof
    assert any("not proof" in n.lower() for n in identity.notes)
    assert any("confirm" in n.lower() for n in identity.notes)


def test_mac_match_outranks_ip_match() -> None:
    assets = [
        _asset("a1", ips=["192.0.2.10"], macs=["00:11:22:33:44:55"]),
        _asset("a2", ips=["192.0.2.10"], macs=["00:11:22:33:44:55"]),
    ]
    identities = CorrelationEngine().correlate_assets(assets)
    assert len(identities) == 1
    assert identities[0].confidence == "high"


def test_unique_assets_produce_no_identity_groups() -> None:
    assets = [_asset("a1", ips=["192.0.2.10"]), _asset("a2", ips=["192.0.2.20"])]
    assert CorrelationEngine().correlate_assets(assets) == []


# --- import-set diff -------------------------------------------------------

def test_no_longer_reported_is_a_state_not_a_deletion() -> None:
    baseline = [
        _finding("b1", plugin_id="51192", name="TLS Issue"),
        _finding("b2", plugin_id="99999", name="Gone Next Time", port=22),
    ]
    latest = [_finding("l1", plugin_id="51192", name="TLS Issue")]
    result = diff_import_sets(baseline=baseline, latest=latest)

    gone = result.of_kind(ChangeKind.NO_LONGER_REPORTED)
    assert len(gone) == 1
    assert gone[0].baseline_finding_ids == ["b2"]
    # The record is retained and explicitly NOT called a false positive.
    assert "not evidence of remediation" in gone[0].note
    assert "not a false positive" in gone[0].note
    payload = result.to_dict()
    assert "NOT evidence of remediation" in payload["interpretation_note"]


def test_diff_accounts_for_every_finding_on_both_sides() -> None:
    baseline = [_finding("b1", plugin_id="1"), _finding("b2", plugin_id="2", port=22)]
    latest = [_finding("l1", plugin_id="1"), _finding("l3", plugin_id="3", port=80)]
    result = diff_import_sets(baseline=baseline, latest=latest)
    assert result.accounted_baseline == 2
    assert result.accounted_latest == 2
    assert result.totals_balance is True


def test_diff_detects_severity_change() -> None:
    baseline = [_finding("b1", plugin_id="1", severity="MEDIUM")]
    latest = [_finding("l1", plugin_id="1", severity="CRITICAL")]
    result = diff_import_sets(baseline=baseline, latest=latest)
    changed = result.of_kind(ChangeKind.SEVERITY_CHANGED)
    assert len(changed) == 1
    assert changed[0].baseline_severity == "MEDIUM"
    assert changed[0].latest_severity == "CRITICAL"


def test_diff_matches_across_scanners_by_cve() -> None:
    baseline = [_finding("b1", scanner="nessus", plugin_id="51192", cves=["CVE-2026-1"])]
    latest = [_finding("l1", scanner="qualys", plugin_id="777", cves=["CVE-2026-1"])]
    result = diff_import_sets(baseline=baseline, latest=latest)
    assert len(result.of_kind(ChangeKind.STILL_REPORTED)) == 1
    assert result.of_kind(ChangeKind.NO_LONGER_REPORTED) == []
