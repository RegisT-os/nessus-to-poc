"""Profile loading.

A profile directory may contain:

* ``engagement.yaml``    — the engagement definition (task section 9.1)
* ``environments.yaml``  — environment mapping rules
* ``scope.yaml``         — scope overrides (merged into the engagement)
* ``reporting.yaml``     — reporting/export preferences

Only ``engagement.yaml`` is required. Real client profiles live under the
git-ignored ``profiles/private/``; sanitized examples live under
``profiles/examples/``. A profile may override operational settings but NEVER
the no-data-loss invariant or the reconciliation gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from vapt_verify.models.engagement import Engagement
from vapt_verify.profiles.environments import EnvironmentMapper, EnvironmentRule


@dataclass
class Profile:
    path: Path
    engagement: Engagement
    environment_rules: list[EnvironmentRule] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)
    reporting: dict[str, Any] = field(default_factory=dict)

    def environment_mapper(self) -> EnvironmentMapper:
        return EnvironmentMapper(self.environment_rules)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def load_profile(directory: str | Path) -> Profile:
    root = Path(directory)
    engagement_file = root / "engagement.yaml"
    if not engagement_file.exists():
        raise FileNotFoundError(f"profile has no engagement.yaml: {root}")
    engagement = Engagement.from_yaml(engagement_file.read_text(encoding="utf-8"))

    # Merge scope overrides into the engagement (additive; never weakens safety).
    scope = _load_yaml(root / "scope.yaml")
    if scope.get("approved_cidrs"):
        engagement.approved_cidrs = list(scope["approved_cidrs"])
    if scope.get("approved_hostnames"):
        engagement.approved_hostnames = list(scope["approved_hostnames"])
    if scope.get("excluded_targets"):
        engagement.excluded_targets = list(scope["excluded_targets"])

    env_data = _load_yaml(root / "environments.yaml")
    rules = [
        EnvironmentRule(
            name=item["name"],
            cidrs=list(item.get("cidrs", [])),
            hostname_patterns=list(item.get("hostname_patterns", [])),
            critical=bool(item.get("critical", False)),
        )
        for item in env_data.get("environments", [])
    ]

    reporting = _load_yaml(root / "reporting.yaml")
    return Profile(
        path=root,
        engagement=engagement,
        environment_rules=rules,
        scope=scope,
        reporting=reporting,
    )
