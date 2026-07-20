"""Profile, environment-mapping and retest tests (task section 13)."""

from __future__ import annotations

from pathlib import Path

from vapt_verify.profiles.environments import EnvironmentMapper, EnvironmentRule
from vapt_verify.profiles.loader import load_profile
from vapt_verify.retest import compare

EXAMPLE = Path(__file__).resolve().parents[1] / "profiles" / "examples" / "banking-enterprise"


def _mapper() -> EnvironmentMapper:
    return EnvironmentMapper([
        EnvironmentRule(name="production", cidrs=["192.0.2.0/25"],
                        hostname_patterns=["prd"], critical=True),
        EnvironmentRule(name="uat", cidrs=["203.0.113.0/24"],
                        hostname_patterns=["uat"], critical=False),
    ])


def test_explicit_engagement_env_wins() -> None:
    a = _mapper().assign(ips=["192.0.2.10"], hostnames=["prd-web"], engagement_env="staging")
    assert a.environment == "staging"
    assert a.confidence == "explicit"


def test_ip_range_gives_high_confidence() -> None:
    a = _mapper().assign(ips=["203.0.113.9"], hostnames=[])
    assert a.environment == "uat"
    assert a.confidence == "high"
    assert a.method == "ip_range"


def test_noncritical_hostname_assigns_low_confidence() -> None:
    a = _mapper().assign(ips=[], hostnames=["uat-app01"])
    assert a.environment == "uat"
    assert a.confidence == "low"
    assert a.method == "hostname"


def test_critical_env_not_assigned_from_hostname_alone() -> None:
    """A critical environment is never assigned from a weak hostname guess."""
    a = _mapper().assign(ips=["10.0.0.5"], hostnames=["prd-db01"])  # ip not in any rule
    assert a.environment == "unknown"
    assert a.candidate == "production"
    assert any("critical" in n.lower() for n in a.notes)


def test_critical_env_confirmed_by_ip() -> None:
    a = _mapper().assign(ips=["192.0.2.5"], hostnames=["prd-db01"])
    assert a.environment == "production"
    assert a.confidence == "high"


def test_load_example_profile_merges_scope() -> None:
    profile = load_profile(EXAMPLE)
    assert profile.engagement.client_alias == "ExampleBank"
    # scope.yaml merged into the engagement
    assert "192.0.2.0/24" in profile.engagement.approved_cidrs
    assert "192.0.2.254" in profile.engagement.excluded_targets
    # environment rules loaded, with a critical production rule
    names = {r.name for r in profile.environment_rules}
    assert "production" in names
    assert any(r.critical for r in profile.environment_rules)


def test_retest_retains_no_longer_reported() -> None:
    baseline = [
        {"fingerprint": "fp-a", "finding_id": "1", "plugin_name": "A", "severity_label": "HIGH"},
        {"fingerprint": "fp-b", "finding_id": "2", "plugin_name": "B", "severity_label": "LOW"},
    ]
    latest = [
        {"fingerprint": "fp-a", "finding_id": "3", "plugin_name": "A", "severity_label": "HIGH"},
        {"fingerprint": "fp-c", "finding_id": "4", "plugin_name": "C", "severity_label": "MEDIUM"},
    ]
    result = compare(baseline=baseline, latest=latest)
    still = {x["fingerprint"] for x in result.still_reported}
    gone = {x["fingerprint"] for x in result.no_longer_reported}
    new = {x["fingerprint"] for x in result.newly_reported}
    assert still == {"fp-a"}
    assert gone == {"fp-b"}  # retained in the report, not deleted
    assert new == {"fp-c"}
