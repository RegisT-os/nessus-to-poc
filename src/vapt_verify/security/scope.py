"""Engagement scope enforcement (task section 19).

Nothing is executed against a target unless it is explicitly in the engagement
scope. The default posture is DENY: an empty scope authorises nothing. A public
IP is never in scope unless an approved CIDR/target covers it. Hostnames are
validated against a strict allow-list and a safe character set, so a hostile
"hostname" containing shell metacharacters can never be treated as in-scope.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from vapt_verify.models.engagement import Engagement

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# A conservative hostname pattern: letters, digits, dot and hyphen only.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$")


@dataclass
class ScopeDecision:
    target: str
    in_scope: bool
    reason: str
    resolved_kind: str = "unknown"  # "ip" | "hostname"
    matched_rule: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "in_scope": self.in_scope,
            "reason": self.reason,
            "resolved_kind": self.resolved_kind,
            "matched_rule": self.matched_rule,
            "notes": self.notes,
        }


class ScopeEnforcer:
    def __init__(self, engagement: Engagement) -> None:
        self.engagement = engagement
        self._cidrs = [self._net(c) for c in engagement.approved_cidrs]
        self._cidrs = [c for c in self._cidrs if c is not None]
        self._approved_targets = {t.strip().lower() for t in engagement.approved_targets}
        self._approved_hostnames = {h.strip().lower() for h in engagement.approved_hostnames}
        self._excluded = {t.strip().lower() for t in engagement.excluded_targets}

    def validate(self, target: str) -> ScopeDecision:
        raw = target.strip()
        low = raw.lower()

        # Explicit exclusion always wins.
        if low in self._excluded:
            return ScopeDecision(
                raw, False, "target is explicitly excluded", matched_rule="excluded"
            )

        ip = self._as_ip(raw)
        if ip is not None:
            return self._validate_ip(raw, ip)
        return self._validate_hostname(raw, low)

    # -- ip -----------------------------------------------------------------

    def _validate_ip(self, raw: str, ip: IPAddress) -> ScopeDecision:
        if raw.lower() in self._approved_targets:
            return ScopeDecision(
                raw, True, "IP is an explicitly approved target", "ip", "approved_target"
            )
        for net in self._cidrs:
            if net is not None and ip in net:
                return ScopeDecision(raw, True, f"IP is within approved CIDR {net}", "ip", str(net))
        note = []
        if getattr(ip, "is_global", False):
            note.append("Target is a public IP and must be explicitly in scope; refusing.")
        return ScopeDecision(
            raw, False, "IP is not within any approved CIDR/target", "ip", notes=note
        )

    # -- hostname -----------------------------------------------------------

    def _validate_hostname(self, raw: str, low: str) -> ScopeDecision:
        if not _HOSTNAME_RE.match(raw):
            return ScopeDecision(
                raw, False,
                "target is neither a valid IP nor a valid hostname (rejected as unsafe)",
                "hostname", "invalid",
                notes=["Contains characters not allowed in a hostname; will not be executed."],
            )
        if low in self._approved_hostnames or low in self._approved_targets:
            return ScopeDecision(
                raw, True, "hostname is explicitly approved", "hostname", "approved_hostname"
            )
        return ScopeDecision(
            raw, False, "hostname is not in the approved hostname list", "hostname"
        )

    # -- helpers ------------------------------------------------------------

    def _as_ip(self, value: str) -> IPAddress | None:
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    def _net(self, value: str) -> IPNetwork | None:
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
