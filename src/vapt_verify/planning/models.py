"""Verification plan model (task section 17)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class VerificationPlan:
    finding_id: str
    finding_summary: str
    original_scanner_evidence: str
    asset_id: str
    environment: str
    port: int
    transport: str
    credentialed: bool | None
    verification_objective: str
    primary_validation_method: str
    supporting_validation_methods: list[str] = field(default_factory=list)
    manual_fallback: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    required_credentials: str = "none"
    required_network_position: str = "any"
    sni_vhost_requirements: list[str] = field(default_factory=list)
    expected_confirming_evidence: list[str] = field(default_factory=list)
    expected_contradictory_evidence: list[str] = field(default_factory=list)
    inconclusive_conditions: list[str] = field(default_factory=list)
    safety_classification: str = "passive"
    scope_decision: str = "pending_scope_validation"
    evidence_output_path: str = ""
    reviewer_checklist: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_summary": self.finding_summary,
            "original_scanner_evidence": self.original_scanner_evidence,
            "asset_id": self.asset_id,
            "environment": self.environment,
            "port": self.port,
            "transport": self.transport,
            "credentialed": self.credentialed,
            "verification_objective": self.verification_objective,
            "primary_validation_method": self.primary_validation_method,
            "supporting_validation_methods": self.supporting_validation_methods,
            "manual_fallback": self.manual_fallback,
            "required_tools": self.required_tools,
            "required_credentials": self.required_credentials,
            "required_network_position": self.required_network_position,
            "sni_vhost_requirements": self.sni_vhost_requirements,
            "expected_confirming_evidence": self.expected_confirming_evidence,
            "expected_contradictory_evidence": self.expected_contradictory_evidence,
            "inconclusive_conditions": self.inconclusive_conditions,
            "safety_classification": self.safety_classification,
            "scope_decision": self.scope_decision,
            "evidence_output_path": self.evidence_output_path,
            "reviewer_checklist": self.reviewer_checklist,
        }
