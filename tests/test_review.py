"""Review/decision workflow tests (task section 10; mandatory test 15)."""

from __future__ import annotations

import pytest

from vapt_verify.models.enums import Verdict
from vapt_verify.review.engine import ReviewEngine, ReviewError, detect_contradiction


def _finding() -> dict:
    return {"finding_id": "find-1", "plugin_name": "SSL Certificate Cannot Be Trusted",
            "verdict": Verdict.UNREVIEWED.value}


def test_false_positive_approved_requires_authorised_reviewer() -> None:
    engine = ReviewEngine()
    with pytest.raises(ReviewError):
        engine.record_decision(finding=_finding(), verdict="false_positive_approved",
                               reviewer="alice", rationale="looks fine", reviewer_roles={"operator"})
    # A lead may approve.
    d = engine.record_decision(finding=_finding(), verdict="false_positive_approved",
                               reviewer="lead1", rationale="confirmed benign after review",
                               reviewer_roles={"lead"})
    assert d.verdict == Verdict.FALSE_POSITIVE_APPROVED.value


def test_terminal_verdict_requires_rationale() -> None:
    engine = ReviewEngine()
    with pytest.raises(ReviewError):
        engine.record_decision(finding=_finding(), verdict="confirmed", reviewer="alice",
                               rationale="")


def test_not_reproduced_does_not_autoflip_to_false_positive() -> None:
    engine = ReviewEngine()
    finding = _finding()
    d = engine.record_decision(finding=finding, verdict="not_reproduced", reviewer="alice",
                               rationale="Nmap did not reproduce; service reachable though.")
    assert d.verdict == Verdict.NOT_REPRODUCED.value
    assert finding["verdict"] == Verdict.NOT_REPRODUCED.value
    # It must NOT have become a false-positive candidate automatically.
    assert finding["verdict"] != Verdict.FALSE_POSITIVE_CANDIDATE.value


def test_contradiction_is_detected_not_resolved() -> None:
    evidence = [
        {"adapter": "openssl", "parsed_observations": {"suggested_verdict": "confirmed"}},
        {"adapter": "tcp", "parsed_observations": {"suggested_verdict": "service_not_currently_observed"}},
    ]
    contradiction, desc = detect_contradiction(evidence)
    assert contradiction is True
    assert "openssl" in desc and "tcp" in desc


def test_tls_confirmed_by_openssl_despite_nmap_not_reproducing() -> None:
    """Task 22.15 — OpenSSL evidence can CONFIRM even when Nmap did not reproduce."""
    engine = ReviewEngine()
    finding = _finding()
    # Nmap (supporting) did not reproduce; OpenSSL (primary) confirmed the condition.
    decision = engine.record_decision(
        finding=finding,
        verdict="confirmed",
        reviewer="alice",
        rationale="OpenSSL presented the self-signed certificate; Nmap ssl-cert did not run "
                  "but is only supporting evidence.",
        supporting_evidence_ids=["ev-openssl"],
        contradicting_evidence_ids=["ev-nmap-not-reproduced"],
    )
    assert decision.verdict == Verdict.CONFIRMED.value
    assert finding["verdict"] == Verdict.CONFIRMED.value
    # Nmap's non-reproduction is recorded but did not block confirmation.
    assert "ev-nmap-not-reproduced" in decision.contradicting_evidence_ids


def test_unknown_verdict_is_rejected() -> None:
    with pytest.raises(ReviewError):
        ReviewEngine().record_decision(finding=_finding(), verdict="totally-made-up",
                                       reviewer="alice", rationale="x")
