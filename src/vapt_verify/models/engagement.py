"""Engagement model.

Task section 9.1. An engagement carries the authorisation and scope context for
verification work. Scope *enforcement* arrives in v0.3; v0.1 only needs the
engagement to define the workspace and to record authorisation metadata. Two
rules already hold here:

* Plaintext passwords are never stored. ``credential_references`` holds opaque
  labels/pointers (e.g. a vault path), never a secret value.
* The generic engine holds no permanent client-specific assumptions; real
  client detail lives only in private profiles under ``profiles/private/``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TestingWindow:
    start: str = ""
    end: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end}

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> TestingWindow:
        data = data or {}
        return cls(start=data.get("start", ""), end=data.get("end", ""))


@dataclass
class Engagement:
    """Authorisation and scope context for a verification engagement."""

    engagement_id: str
    client_alias: str = ""
    engagement_type: str = ""  # e.g. internal, external, web, cloud, config, retest
    assessment_type: str = ""
    authorisation_reference: str = ""
    rules_of_engagement_reference: str = ""
    testing_window: TestingWindow = field(default_factory=TestingWindow)
    timezone: str = "UTC"
    approved_targets: list[str] = field(default_factory=list)
    approved_cidrs: list[str] = field(default_factory=list)
    approved_hostnames: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    permitted_protocols: list[str] = field(default_factory=list)
    permitted_validation_modes: list[str] = field(default_factory=list)
    rate_limits: dict[str, Any] = field(default_factory=dict)
    # References only — NEVER plaintext credentials.
    credential_references: list[str] = field(default_factory=list)
    environment_mappings: dict[str, Any] = field(default_factory=dict)
    evidence_root: str = ""
    data_classification: str = "restricted"

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "client_alias": self.client_alias,
            "engagement_type": self.engagement_type,
            "assessment_type": self.assessment_type,
            "authorisation_reference": self.authorisation_reference,
            "rules_of_engagement_reference": self.rules_of_engagement_reference,
            "testing_window": self.testing_window.to_dict(),
            "timezone": self.timezone,
            "approved_targets": self.approved_targets,
            "approved_cidrs": self.approved_cidrs,
            "approved_hostnames": self.approved_hostnames,
            "excluded_targets": self.excluded_targets,
            "permitted_protocols": self.permitted_protocols,
            "permitted_validation_modes": self.permitted_validation_modes,
            "rate_limits": self.rate_limits,
            "credential_references": self.credential_references,
            "environment_mappings": self.environment_mappings,
            "evidence_root": self.evidence_root,
            "data_classification": self.data_classification,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Engagement:
        return cls(
            engagement_id=data["engagement_id"],
            client_alias=data.get("client_alias", ""),
            engagement_type=data.get("engagement_type", ""),
            assessment_type=data.get("assessment_type", ""),
            authorisation_reference=data.get("authorisation_reference", ""),
            rules_of_engagement_reference=data.get("rules_of_engagement_reference", ""),
            testing_window=TestingWindow.from_dict(data.get("testing_window")),
            timezone=data.get("timezone", "UTC"),
            approved_targets=list(data.get("approved_targets", [])),
            approved_cidrs=list(data.get("approved_cidrs", [])),
            approved_hostnames=list(data.get("approved_hostnames", [])),
            excluded_targets=list(data.get("excluded_targets", [])),
            permitted_protocols=list(data.get("permitted_protocols", [])),
            permitted_validation_modes=list(data.get("permitted_validation_modes", [])),
            rate_limits=dict(data.get("rate_limits", {})),
            credential_references=list(data.get("credential_references", [])),
            environment_mappings=dict(data.get("environment_mappings", {})),
            evidence_root=data.get("evidence_root", ""),
            data_classification=data.get("data_classification", "restricted"),
        )

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False, default_flow_style=False)

    @classmethod
    def from_yaml(cls, text: str) -> Engagement:
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("engagement.yaml must contain a mapping")
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: str | Path) -> Engagement:
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_yaml(), encoding="utf-8")
