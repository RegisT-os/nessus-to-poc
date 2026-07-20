"""Environment mapping with strict precedence (task section 13).

Precedence (stop at the first confident match):

1. Explicit engagement configuration
2. Explicit asset mapping
3. Hostname mapping rule
4. IP-range mapping rule
5. Unknown

Safety rule: a *critical* environment is never assigned silently from a weak
hostname guess. If only a hostname matches a critical environment, the mapper
records it as a low-confidence *candidate* and requires IP or explicit
confirmation before the environment is assigned.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnvironmentRule:
    name: str
    cidrs: list[str] = field(default_factory=list)
    hostname_patterns: list[str] = field(default_factory=list)
    critical: bool = False

    def matches_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in self.cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def matches_hostname(self, hostname: str) -> bool:
        low = hostname.lower()
        return any(p.lower() in low for p in self.hostname_patterns)


@dataclass
class EnvironmentAssignment:
    environment: str = "unknown"
    confidence: str = "none"  # explicit | high | low | none
    method: str = "unknown"  # engagement | asset | hostname | ip_range | unknown
    candidate: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "confidence": self.confidence,
            "method": self.method,
            "candidate": self.candidate,
            "notes": self.notes,
        }


class EnvironmentMapper:
    def __init__(self, rules: list[EnvironmentRule]) -> None:
        self.rules = rules

    def assign(
        self,
        *,
        ips: list[str],
        hostnames: list[str],
        engagement_env: str = "",
        asset_env: str = "",
    ) -> EnvironmentAssignment:
        # 1 & 2: explicit configuration wins outright.
        if engagement_env:
            return EnvironmentAssignment(engagement_env, "explicit", "engagement")
        if asset_env and asset_env != "unknown":
            return EnvironmentAssignment(asset_env, "explicit", "asset")

        candidate = ""
        notes: list[str] = []

        # 3: hostname rule (with the critical safeguard).
        for rule in self.rules:
            if any(rule.matches_hostname(h) for h in hostnames if h):
                if rule.critical:
                    candidate = rule.name
                    notes.append(
                        f"Hostname hints environment '{rule.name}', which is critical. "
                        "Not assigned from a hostname alone; confirm via IP range or explicit "
                        "mapping."
                    )
                    break  # do not assign; try IP confirmation below
                return EnvironmentAssignment(rule.name, "low", "hostname", notes=[
                    f"Assigned from hostname match to non-critical environment '{rule.name}'."
                ])

        # 4: IP-range rule (a strong signal; can confirm a critical candidate).
        for rule in self.rules:
            if any(rule.matches_ip(ip) for ip in ips if ip):
                confidence = "high"
                if candidate and candidate == rule.name:
                    notes.append("IP range confirms the hostname-hinted critical environment.")
                return EnvironmentAssignment(rule.name, confidence, "ip_range", notes=notes)

        # 5: unknown (carry any critical candidate for reviewer attention).
        return EnvironmentAssignment("unknown", "none", "unknown", candidate=candidate, notes=notes)
