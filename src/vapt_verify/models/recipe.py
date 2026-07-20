"""Verification recipe model (task section 9.5).

A recipe is a *declarative* description of how to verify a class of findings. It
contains no executable Python: steps reference adapter capabilities by name and
carry structured parameters only. The classification engine selects a recipe;
the planner turns it into a concrete plan; the execution engine runs the
adapters named by its steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VerificationFamily(Enum):
    """Vulnerability verification families (task section 12)."""

    PORT_SERVICE_EXPOSURE = "port_service_exposure"
    TLS_CERTIFICATE = "tls_certificate"
    SSH = "ssh"
    RDP = "rdp"
    HTTP_WEB = "http_web"
    APPLICATION_SECURITY = "application_security"
    SMB_WINDOWS = "smb_windows"
    DNS = "dns"
    SNMP = "snmp"
    LDAP_AD = "ldap_ad"
    DATABASE = "database"
    MAIL = "mail"
    HYPERVISOR = "hypervisor"
    PATCH_LOCAL_CONFIG = "patch_local_config"
    NETWORK_DEVICE = "network_device"
    INFORMATIONAL = "informational"
    GENERIC = "generic"


class NmapRole(Enum):
    """How useful Nmap is for a given recipe (task section 12.1, 15.4)."""

    PRIMARY = "primary"
    SUPPORTING = "supporting"
    DISCOVERY_ONLY = "discovery_only"
    INAPPROPRIATE = "inappropriate"


class SafetyClass(Enum):
    PASSIVE = "passive"
    ACTIVE_NONINTRUSIVE = "active_nonintrusive"
    ACTIVE_INTRUSIVE = "active_intrusive"
    MANUAL = "manual"


class AuthRequirement(Enum):
    NONE = "none"
    CREDENTIALED = "credentialed"
    ADMINISTRATIVE = "administrative"


class NetworkPosition(Enum):
    ANY = "any"
    VALIDATION_SOURCE = "validation_source"
    SAME_SEGMENT = "same_segment"
    INTERNAL = "internal"
    EXTERNAL = "external"


class StepMode(Enum):
    AUTOMATED = "automated"
    ASSISTED = "assisted"
    MANUAL = "manual"


class SelectionLayer(Enum):
    """Layered recipe selection (task section 11)."""

    PLUGIN_SPECIFIC = 1
    CATEGORY_SPECIFIC = 2
    PLUGIN_FAMILY = 3
    SERVICE_GENERIC = 4
    CAPABILITY_ASSISTED = 5
    MANUAL_FALLBACK = 6


@dataclass
class RecipeStep:
    """A single declarative verification step (no executable code)."""

    mode: StepMode
    adapter: str  # capability/adapter name, e.g. "openssl", "nmap", "manual"
    description: str
    params: dict[str, Any] = field(default_factory=dict)
    capability: str = ""  # required tool/binary; "" means no external tool
    optional: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "adapter": self.adapter,
            "description": self.description,
            "params": self.params,
            "capability": self.capability,
            "optional": self.optional,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecipeStep:
        return cls(
            mode=StepMode(data.get("mode", "manual")),
            adapter=data["adapter"],
            description=data.get("description", ""),
            params=dict(data.get("params", {})),
            capability=data.get("capability", ""),
            optional=bool(data.get("optional", False)),
        )


@dataclass
class Recipe:
    """A declarative verification recipe."""

    recipe_id: str
    version: str
    family: VerificationFamily
    title: str = ""
    categories: list[str] = field(default_factory=list)
    plugin_ids: list[str] = field(default_factory=list)
    plugin_families: list[str] = field(default_factory=list)
    name_indicators: list[str] = field(default_factory=list)  # case-insensitive substrings
    text_indicators: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    transports: list[str] = field(default_factory=list)
    required_capabilities: list[str] = field(default_factory=list)
    optional_capabilities: list[str] = field(default_factory=list)
    auth_requirement: AuthRequirement = AuthRequirement.NONE
    network_position: NetworkPosition = NetworkPosition.ANY
    safety_class: SafetyClass = SafetyClass.PASSIVE
    nmap_role: NmapRole = NmapRole.SUPPORTING
    preconditions: list[str] = field(default_factory=list)
    automated_steps: list[RecipeStep] = field(default_factory=list)
    assisted_steps: list[RecipeStep] = field(default_factory=list)
    manual_steps: list[RecipeStep] = field(default_factory=list)
    positive_evidence: list[str] = field(default_factory=list)
    negative_evidence: list[str] = field(default_factory=list)
    inconclusive_conditions: list[str] = field(default_factory=list)
    known_limitations: list[str] = field(default_factory=list)
    verdict_suggestions: dict[str, str] = field(default_factory=dict)
    cleanup_requirements: list[str] = field(default_factory=list)
    # The layer this recipe participates in (also affects selection ordering).
    selection_layer: SelectionLayer = SelectionLayer.SERVICE_GENERIC

    def to_dict(self) -> dict[str, Any]:
        return {
            "recipe_id": self.recipe_id,
            "version": self.version,
            "family": self.family.value,
            "title": self.title,
            "categories": self.categories,
            "plugin_ids": self.plugin_ids,
            "plugin_families": self.plugin_families,
            "name_indicators": self.name_indicators,
            "text_indicators": self.text_indicators,
            "services": self.services,
            "transports": self.transports,
            "required_capabilities": self.required_capabilities,
            "optional_capabilities": self.optional_capabilities,
            "auth_requirement": self.auth_requirement.value,
            "network_position": self.network_position.value,
            "safety_class": self.safety_class.value,
            "nmap_role": self.nmap_role.value,
            "preconditions": self.preconditions,
            "automated_steps": [s.to_dict() for s in self.automated_steps],
            "assisted_steps": [s.to_dict() for s in self.assisted_steps],
            "manual_steps": [s.to_dict() for s in self.manual_steps],
            "positive_evidence": self.positive_evidence,
            "negative_evidence": self.negative_evidence,
            "inconclusive_conditions": self.inconclusive_conditions,
            "known_limitations": self.known_limitations,
            "verdict_suggestions": self.verdict_suggestions,
            "cleanup_requirements": self.cleanup_requirements,
            "selection_layer": self.selection_layer.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Recipe:
        def steps(key: str) -> list[RecipeStep]:
            return [RecipeStep.from_dict(s) for s in data.get(key, [])]

        return cls(
            recipe_id=data["recipe_id"],
            version=str(data.get("version", "1")),
            family=VerificationFamily(data.get("family", "generic")),
            title=data.get("title", ""),
            categories=list(data.get("categories", [])),
            plugin_ids=[str(p) for p in data.get("plugin_ids", [])],
            plugin_families=list(data.get("plugin_families", [])),
            name_indicators=list(data.get("name_indicators", [])),
            text_indicators=list(data.get("text_indicators", [])),
            services=list(data.get("services", [])),
            transports=list(data.get("transports", [])),
            required_capabilities=list(data.get("required_capabilities", [])),
            optional_capabilities=list(data.get("optional_capabilities", [])),
            auth_requirement=AuthRequirement(data.get("auth_requirement", "none")),
            network_position=NetworkPosition(data.get("network_position", "any")),
            safety_class=SafetyClass(data.get("safety_class", "passive")),
            nmap_role=NmapRole(data.get("nmap_role", "supporting")),
            preconditions=list(data.get("preconditions", [])),
            automated_steps=steps("automated_steps"),
            assisted_steps=steps("assisted_steps"),
            manual_steps=steps("manual_steps"),
            positive_evidence=list(data.get("positive_evidence", [])),
            negative_evidence=list(data.get("negative_evidence", [])),
            inconclusive_conditions=list(data.get("inconclusive_conditions", [])),
            known_limitations=list(data.get("known_limitations", [])),
            verdict_suggestions=dict(data.get("verdict_suggestions", {})),
            cleanup_requirements=list(data.get("cleanup_requirements", [])),
            selection_layer=SelectionLayer(int(data.get("selection_layer", 4))),
        )

    def all_required_capabilities(self) -> set[str]:
        caps = set(self.required_capabilities)
        for step in self.automated_steps:
            if step.capability and not step.optional:
                caps.add(step.capability)
        return caps
