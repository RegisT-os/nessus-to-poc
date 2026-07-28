"""Evidence redaction for client-facing deliverables.

Captured tool output routinely contains material that must not travel into a
client report: SNMP community strings, credentials passed on a command line,
private keys, bearer tokens, session cookies, basic-auth URLs.

**Redaction is a presentation-layer transform, never a mutation of evidence.**
The stored evidence file keeps its original bytes and its recorded SHA-256, so
chain of custody survives: the raw capture remains verifiable
(``vapt-verify evidence verify``) while the *exported* document carries masked
text. A document that has been redacted always says so, and reports how many
items were masked, so a reader is never misled into thinking they are looking at
an unmodified capture.

Rules are conservative: each replaces only the sensitive span, keeping
surrounding context (so ``-c public`` becomes ``-c [REDACTED:snmp_community]``,
not a deleted line). Engagement profiles can add patterns via
``redaction.yaml``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MASK = "[REDACTED:{name}]"


@dataclass(frozen=True)
class RedactionRule:
    """A named pattern whose captured group 1 (if present) is masked."""

    name: str
    pattern: re.Pattern[str]
    description: str

    def apply(self, text: str) -> tuple[str, int]:
        count = 0

        def _replace(match: re.Match[str]) -> str:
            nonlocal count
            count += 1
            mask = MASK.format(name=self.name)
            if match.re.groups == 0:
                return mask
            # Preserve everything outside group 1 so context survives.
            whole, target = match.group(0), match.group(1)
            if target is None:
                return mask
            start = match.start(1) - match.start(0)
            return whole[:start] + mask + whole[start + len(target) :]

        redacted = self.pattern.sub(_replace, text)
        return redacted, count


def _rule(name: str, pattern: str, description: str, flags: int = re.IGNORECASE) -> RedactionRule:
    return RedactionRule(name=name, pattern=re.compile(pattern, flags), description=description)


# Ordered most-specific first; each rule masks only its sensitive span.
DEFAULT_RULES: list[RedactionRule] = [
    _rule(
        "private_key",
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----(.*?)-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
        "PEM private key block",
        re.IGNORECASE | re.DOTALL,
    ),
    _rule(
        "basic_auth_url",
        # Greedy up to the LAST '@' before the host: passwords often contain '@'.
        r"[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s]+)@[^\s/@]+",
        "password embedded in a URL",
    ),
    _rule(
        "authorization_header",
        r"authorization\s*:\s*(?:bearer|basic|token)\s+(\S+)",
        "HTTP Authorization header value",
    ),
    _rule("set_cookie", r"set-cookie\s*:\s*[^=]+=([^;\s]+)", "Set-Cookie value"),
    _rule("cookie_header", r"\bcookie\s*:\s*([^\r\n]+)", "Cookie request header"),
    _rule(
        "snmp_community",
        # The flag must start a token, or "-C" inside e.g. "Set-Cookie" matches.
        r"(?:(?<=\s)|\A)(?:-c|--community)[=\s]\s*(\S+)",
        "SNMP community string on a command line",
    ),
    _rule(
        "cli_password",
        r"(?:(?<=\s)|\A)(?:-p|--password|--pass|-w|--secret)[=\s]\s*(\S+)",
        "password/secret passed as a command-line argument",
    ),
    _rule(
        "password_assignment",
        r"\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*[\"']?([^\s\"',;]+)",
        "password/secret assignment in output",
    ),
    _rule("aws_access_key", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", "AWS access key id", 0),
    _rule(
        "aws_secret_key",
        r"aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})",
        "AWS secret access key",
    ),
    _rule(
        "jwt",
        r"\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
        "JSON Web Token",
        0,
    ),
    _rule(
        "generic_bearer",
        r"\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)",
        "bearer token",
    ),
    _rule("ntlm_hash", r"\b([a-f0-9]{32}:[a-f0-9]{32})\b", "NTLM hash pair"),
]


@dataclass
class RedactionResult:
    text: str
    total: int = 0
    by_rule: dict[str, int] = field(default_factory=dict)

    @property
    def applied(self) -> bool:
        return self.total > 0

    def to_dict(self) -> dict[str, Any]:
        return {"total": self.total, "by_rule": self.by_rule, "applied": self.applied}


class Redactor:
    """Applies redaction rules to captured text."""

    def __init__(self, rules: list[RedactionRule] | None = None) -> None:
        self.rules = list(rules) if rules is not None else list(DEFAULT_RULES)

    def redact(self, text: str) -> RedactionResult:
        if not text:
            return RedactionResult(text=text)
        result = RedactionResult(text=text)
        for rule in self.rules:
            result.text, count = rule.apply(result.text)
            if count:
                result.by_rule[rule.name] = result.by_rule.get(rule.name, 0) + count
                result.total += count
        return result

    def redact_mapping(self, mapping: dict[str, Any]) -> tuple[dict[str, Any], RedactionResult]:
        """Redact string values in a flat mapping (e.g. parsed observations)."""
        combined = RedactionResult(text="")
        out: dict[str, Any] = {}
        for key, value in mapping.items():
            if isinstance(value, str):
                single = self.redact(value)
                out[key] = single.text
                for name, count in single.by_rule.items():
                    combined.by_rule[name] = combined.by_rule.get(name, 0) + count
                combined.total += single.total
            else:
                out[key] = value
        return out, combined

    @classmethod
    def from_profile(cls, extra_patterns: list[dict[str, str]]) -> Redactor:
        """Build a redactor with engagement-specific patterns layered on."""
        rules = list(DEFAULT_RULES)
        for item in extra_patterns:
            name = item.get("name", "custom")
            pattern = item.get("pattern", "")
            if not pattern:
                continue
            try:
                rules.append(
                    _rule(name, pattern, item.get("description", "engagement-specific pattern"))
                )
            except re.error:
                # A bad custom pattern must not disable redaction entirely.
                continue
        return cls(rules)
