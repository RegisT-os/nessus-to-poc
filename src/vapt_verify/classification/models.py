"""Classification output types."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any

# Tools the platform can use. Availability is checked but NEVER used to drop a
# finding — only to choose between automated and assisted dispositions.
KNOWN_TOOLS = [
    "nmap",
    "openssl",
    "testssl.sh",
    "sslscan",
    "ssh-audit",
    "dig",
    "curl",
    "httpx",
    "snmpget",
    "snmpwalk",
    "smbclient",
    "rpcclient",
    "ldapsearch",
    "swaks",
    "nuclei",
]


@dataclass
class Capabilities:
    """The set of verification tools available in the current environment."""

    available: set[str] = field(default_factory=set)

    def has(self, capability: str) -> bool:
        return capability == "" or capability in self.available

    def missing(self, capabilities: set[str]) -> set[str]:
        return {c for c in capabilities if c and c not in self.available}

    @classmethod
    def detect(cls) -> Capabilities:
        return cls(available={t for t in KNOWN_TOOLS if shutil.which(t) is not None})


@dataclass
class RejectedRecipe:
    recipe_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"recipe_id": self.recipe_id, "reason": self.reason}


@dataclass
class Classification:
    """Explainable classification result for one finding (task section 11)."""

    finding_id: str
    family: str
    selected_recipe_id: str
    selected_recipe_title: str
    selection_layer: int
    selection_rationale: str
    nmap_role: str
    auth_requirement: str
    network_position: str
    safety_class: str
    disposition: str
    required_capabilities: list[str] = field(default_factory=list)
    optional_capabilities: list[str] = field(default_factory=list)
    missing_capabilities: list[str] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
    expected_confirming_evidence: list[str] = field(default_factory=list)
    expected_contradictory_evidence: list[str] = field(default_factory=list)
    known_limitations: list[str] = field(default_factory=list)
    verification_requirements: list[str] = field(default_factory=list)
    rejected_recipes: list[RejectedRecipe] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "family": self.family,
            "selected_recipe_id": self.selected_recipe_id,
            "selected_recipe_title": self.selected_recipe_title,
            "selection_layer": self.selection_layer,
            "selection_rationale": self.selection_rationale,
            "nmap_role": self.nmap_role,
            "auth_requirement": self.auth_requirement,
            "network_position": self.network_position,
            "safety_class": self.safety_class,
            "disposition": self.disposition,
            "required_capabilities": self.required_capabilities,
            "optional_capabilities": self.optional_capabilities,
            "missing_capabilities": self.missing_capabilities,
            "missing_information": self.missing_information,
            "expected_confirming_evidence": self.expected_confirming_evidence,
            "expected_contradictory_evidence": self.expected_contradictory_evidence,
            "known_limitations": self.known_limitations,
            "verification_requirements": self.verification_requirements,
            "rejected_recipes": [r.to_dict() for r in self.rejected_recipes],
        }
