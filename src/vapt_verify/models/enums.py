"""Controlled vocabularies for the verification platform.

These enums are foundational and are referenced by the documentation, the
reconciliation gate and (from v0.2) the classification engine. They encode the
methodology's non-negotiable distinctions: tool execution status, verification
disposition and human verdict are kept strictly separate.
"""

from __future__ import annotations

from enum import Enum


class Severity(Enum):
    """Normalized severity, aligned with the Nessus 0-4 scale.

    Informational findings (severity 0) are first-class and MUST be retained;
    see docs/METHODOLOGY.md section on informational findings.
    """

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_nessus(cls, raw: str | int | None) -> Severity:
        """Map a raw Nessus severity value to a Severity, never raising.

        Unknown or missing values default to INFORMATIONAL rather than being
        dropped, so a malformed severity can never remove a finding.
        """
        if raw is None or raw == "":
            return cls.INFORMATIONAL
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return cls.INFORMATIONAL
        try:
            return cls(value)
        except ValueError:
            # Clamp out-of-range values into the scale rather than losing them.
            return cls.CRITICAL if value > 4 else cls.INFORMATIONAL


class Transport(Enum):
    """Transport-layer protocol, kept separate from the application protocol.

    Legacy failure mode 2.5: the old parser read the protocol but stored only
    the port, producing TCP Nmap scans for UDP/non-TCP services. Transport is
    now retained as a first-class attribute.
    """

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    SCTP = "sctp"
    # Host-level / local-check findings do not map to a transport at all.
    NONE = "none"
    UNKNOWN = "unknown"

    @classmethod
    def from_nessus(cls, raw: str | None, *, port: int) -> Transport:
        """Map a raw Nessus protocol attribute to a Transport.

        A port-zero finding (legacy failure mode 2.2) is host-level and has no
        meaningful transport, so it is always NONE regardless of the scanner's
        protocol attribute (Nessus commonly defaults host-level items to
        ``protocol="tcp"``). The scanner's raw value is still preserved verbatim
        in ``Finding.raw`` — nothing is lost.
        """
        if port == 0:
            return cls.NONE
        if raw:
            try:
                return cls(raw.strip().lower())
            except ValueError:
                return cls.UNKNOWN
        return cls.UNKNOWN


class Disposition(Enum):
    """Explicit verification disposition assigned to every imported finding.

    This is the enforcement point of the non-negotiable invariant (task
    section 6): an imported finding is only "accounted for" once it carries one
    of these dispositions. v0.1 imports every finding as ``PENDING_CLASSIFICATION``;
    the v0.2 classification engine replaces that with a concrete disposition.
    Reconciliation treats any of these — including the "unsupported" and
    "blocked" values — as an explicit, reviewable outcome.
    """

    # v0.1 placeholder: imported but not yet classified. Still visible and
    # counted; it is an explicit state, not a silent drop.
    PENDING_CLASSIFICATION = "pending_classification"

    AUTOMATED_VERIFICATION_AVAILABLE = "automated_verification_available"
    ASSISTED_VERIFICATION_AVAILABLE = "assisted_verification_available"
    MANUAL_VALIDATION_REQUIRED = "manual_validation_required"
    CREDENTIALED_VALIDATION_REQUIRED = "credentialed_validation_required"
    ADMINISTRATIVE_EVIDENCE_REQUIRED = "administrative_evidence_required"
    SCANNER_SPECIFIC_VALIDATION_REQUIRED = "scanner_specific_validation_required"
    ENVIRONMENT_BLOCKED = "environment_blocked"
    NETWORK_PATH_BLOCKED = "network_path_blocked"
    AUTHENTICATION_UNAVAILABLE = "authentication_unavailable"
    TOOL_CAPABILITY_UNAVAILABLE = "tool_capability_unavailable"
    UNSUPPORTED_BUT_RETAINED = "unsupported_but_retained"
    OUT_OF_AUTHORISED_SCOPE = "out_of_authorised_scope"
    DUPLICATE_CANDIDATE_RETAINED = "duplicate_candidate_retained"
    INFORMATIONAL_RETAINED = "informational_retained"
    NO_ACTIVE_VALIDATION_APPROPRIATE = "no_active_validation_appropriate"


class Verdict(Enum):
    """Human/review verdict taxonomy (task section 10).

    A verdict is never assigned automatically from a tool exit code. State
    transitions are governed by explicit rules documented in
    docs/METHODOLOGY.md (e.g. NOT_REPRODUCED never auto-promotes to
    FALSE_POSITIVE_CANDIDATE; only an authorised reviewer may assign
    FALSE_POSITIVE_APPROVED).
    """

    UNREVIEWED = "unreviewed"
    PLANNED = "planned"
    VERIFICATION_IN_PROGRESS = "verification_in_progress"
    CONFIRMED = "confirmed"
    LIKELY_CONFIRMED = "likely_confirmed"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    SERVICE_NOT_CURRENTLY_OBSERVED = "service_not_currently_observed"
    POSSIBLY_REMEDIATED = "possibly_remediated"
    CONFIRMED_REMEDIATED = "confirmed_remediated"
    ENVIRONMENT_BLOCKED = "environment_blocked"
    NETWORK_PATH_BLOCKED = "network_path_blocked"
    AUTHENTICATION_REQUIRED = "authentication_required"
    CREDENTIALS_UNAVAILABLE = "credentials_unavailable"
    ADMINISTRATIVE_EVIDENCE_REQUIRED = "administrative_evidence_required"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    SCANNER_SPECIFIC_VALIDATION_REQUIRED = "scanner_specific_validation_required"
    UNSUPPORTED_VALIDATION = "unsupported_validation"
    OUT_OF_SCOPE = "out_of_scope"
    CONTRADICTORY_EVIDENCE = "contradictory_evidence"
    FALSE_POSITIVE_CANDIDATE = "false_positive_candidate"
    FALSE_POSITIVE_APPROVED = "false_positive_approved"
    RISK_ACCEPTED = "risk_accepted"


class ObservationSource(Enum):
    """How a service observation was obtained.

    Legacy failure mode 2.6: a scanner report item referencing a port does not
    prove the port is currently open. These values keep that distinction
    explicit — only VERIFICATION_OBSERVED_OPEN means an active check confirmed
    the port open from the validation source.
    """

    SCANNER_REFERENCED = "scanner_referenced"
    SCANNER_OBSERVED_OPEN = "scanner_observed_open"
    VERIFICATION_OBSERVED_OPEN = "verification_observed_open"
    HISTORICALLY_OBSERVED = "historically_observed"
    CURRENTLY_UNREACHABLE = "currently_unreachable"
