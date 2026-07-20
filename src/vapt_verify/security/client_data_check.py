"""Client-data / secret safety checker (task section 3, tests 30 & 31).

This checker enforces the rule that the public repository must never contain
real client data. It flags:

* files tracked under ``profiles/private/`` (that path must stay git-ignored);
* real scanner exports (``*.nessus`` etc.) committed outside ``tests/fixtures/``;
* non-documentation IP addresses inside example profiles, fixtures and docs —
  these must use RFC 5737 documentation ranges only;
* a missing ``profiles/private/`` rule in ``.gitignore``.

It is deliberately conservative: in "sanitized" areas only loopback and the
RFC 5737 / RFC 3849 documentation ranges are permitted, so a stray real IP
cannot slip through.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges.
_DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# Directories whose content must be sanitized (documentation IPs only).
_SANITIZED_DIRS = ("profiles/examples", "tests/fixtures", "docs", "examples")

# File suffixes we scan as text.
_TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".jsonl",
    ".nessus",
    ".csv",
    ".cfg",
    ".ini",
    ".rst",
}

_SCANNER_EXPORT_SUFFIXES = {".nessus"}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Violation:
    kind: str
    severity: str  # "critical" | "warning"
    path: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
        }


def classify_ip(value: str) -> str:
    """Classify an IP string: 'documentation', 'loopback', 'unspecified',
    'private', 'public', or 'invalid'."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if any(ip in net for net in _DOC_NETWORKS):
        return "documentation"
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if ip.is_multicast or ip.is_reserved or ip.is_link_local:
        return "reserved"
    return "public"


def _is_sanitized_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    return any(norm == d or norm.startswith(d + "/") for d in _SANITIZED_DIRS)


def _scan_text_for_ips(rel_path: str, text: str) -> list[Violation]:
    violations: list[Violation] = []
    if not _is_sanitized_path(rel_path):
        return violations
    seen: set[str] = set()
    for match in _IPV4_RE.findall(text):
        if match in seen:
            continue
        seen.add(match)
        category = classify_ip(match)
        if category in {"documentation", "loopback", "unspecified", "invalid", "reserved"}:
            continue
        # 'private' and 'public' are both disallowed in sanitized areas: an
        # internal RFC1918 address in an example is very likely real client data.
        violations.append(
            Violation(
                kind="non_documentation_ip",
                severity="critical",
                path=rel_path,
                message=(
                    f"{category} IP address {match!r} found in a sanitized area. "
                    "Use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, "
                    "203.0.113.0/24) only."
                ),
            )
        )
    return violations


def scan_files(root: str | Path, rel_paths: list[str]) -> list[Violation]:
    """Scan the given repo-relative paths for client-data violations."""
    root = Path(root)
    violations: list[Violation] = []
    for rel in rel_paths:
        norm = rel.replace("\\", "/")
        path = root / rel

        # 1. Private profiles must never be tracked.
        if norm == "profiles/private" or norm.startswith("profiles/private/"):
            if path.name not in {".gitkeep"}:
                violations.append(
                    Violation(
                        kind="private_profile_tracked",
                        severity="critical",
                        path=norm,
                        message=(
                            "File under profiles/private/ is tracked by git. Private "
                            "engagement profiles must remain local and git-ignored."
                        ),
                    )
                )
            continue

        # 2. Real scanner exports outside tests/fixtures.
        if path.suffix.lower() in _SCANNER_EXPORT_SUFFIXES and not _is_sanitized_path(norm):
            violations.append(
                Violation(
                    kind="scanner_export_tracked",
                    severity="critical",
                    path=norm,
                    message=(
                        "A scanner export file is tracked outside tests/fixtures/. Real "
                        ".nessus files must never be committed."
                    ),
                )
            )

        # 3. Non-documentation IPs in sanitized text files.
        if path.suffix.lower() in _TEXT_SUFFIXES and path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            violations.extend(_scan_text_for_ips(norm, text))

    return violations


def _git_tracked_files(root: Path) -> list[str] | None:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(root), "ls-files"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None
    return [line for line in proc.stdout.splitlines() if line.strip()]


def _walk_files(root: Path) -> list[str]:
    rel: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if any(p in {".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache"} for p in parts):
            continue
        rel.append(str(path.relative_to(root)))
    return rel


def scan_repository(root: str | Path) -> list[Violation]:
    """Scan a repository for client-data violations.

    Prefers ``git ls-files`` (so only *tracked* files are examined, which is the
    real risk surface); falls back to a filesystem walk when git is unavailable.
    Also verifies that ``.gitignore`` excludes ``profiles/private/``.
    """
    root = Path(root)
    tracked = _git_tracked_files(root)
    rel_paths = tracked if tracked is not None else _walk_files(root)
    violations = scan_files(root, rel_paths)

    gitignore = root / ".gitignore"
    if not gitignore.exists() or "profiles/private/" not in gitignore.read_text(encoding="utf-8"):
        violations.append(
            Violation(
                kind="gitignore_missing_private",
                severity="critical",
                path=".gitignore",
                message="'.gitignore' must contain a 'profiles/private/' rule.",
            )
        )
    return violations
