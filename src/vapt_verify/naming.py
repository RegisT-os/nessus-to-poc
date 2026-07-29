"""Human-readable names for exported files and directories.

Internal ids are content hashes -- ``find-37c3608975b2529abc91d78b`` -- which is
right for a key and useless as a filename. A directory of ``poc-<hash>.md``
tells an operator nothing about what is in it, cannot be sorted by importance,
and cannot be handed to a client.

Everything exported to a filesystem goes through here instead, producing names
that say what the file is:

    1-CRITICAL_192.0.2.10_3389-tcp_MS12-020-Remote-Desktop-RCE.md
    2-HIGH_192.0.2.10_host_Ubuntu-Security-Update-for-OpenSSL.md
    3-MEDIUM_192.0.2.10_443-tcp_SSL-Certificate-Cannot-Be-Trusted.md

The leading rank exists so a plain directory listing sorts worst-first;
alphabetical severity names would file INFORMATIONAL between HIGH and LOW.

Names must be **stable** across re-exports -- an operator who re-runs an export
should get the same file updated, not a second copy -- so nothing here depends
on iteration order or a timestamp. When two findings would collide, the
disambiguator is the plugin id (meaningful, stable), and only if that still
collides does a short id fragment get appended.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: Severity name -> sort rank. Lower sorts first, so worst-first in a listing.
SEVERITY_RANK = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFORMATIONAL": 5,
}

_UNSAFE = re.compile(r"[^A-Za-z0-9]+")
# Hosts keep their dots: `192.0.2.10` and `web01.example.test` are valid path
# components everywhere, and mangling them to `192-0-2-10` defeats the point.
_UNSAFE_HOST = re.compile(r"[^A-Za-z0-9.-]+")
# Reserved device names on Windows; a file called `con.md` is unopenable there.
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def slug(value: str, *, max_length: int = 60) -> str:
    """A filesystem-safe, readable fragment: ``SSL-Certificate-Cannot-Be-Trusted``.

    Truncates on a word boundary where possible so a long plugin name degrades
    to something still readable rather than a mid-word stump.
    """
    cleaned = _UNSAFE.sub("-", value).strip("-")
    if len(cleaned) <= max_length:
        return cleaned or "unnamed"
    cut = cleaned[:max_length]
    if "-" in cut:
        cut = cut.rsplit("-", 1)[0]
    return cut.strip("-") or cleaned[:max_length]


def severity_prefix(severity: str) -> str:
    """``MEDIUM`` -> ``3-MEDIUM``. Unknown severities sort last, not first."""
    name = (severity or "UNKNOWN").upper()
    return f"{SEVERITY_RANK.get(name, 9)}-{name}"


def location(port: int, transport: str = "") -> str:
    """``443``/``tcp`` -> ``443-tcp``; a host-level finding -> ``host``.

    Port 0 means "not port-specific". Writing it as ``0-tcp`` invites reading it
    as a real port, so host-level findings say so.
    """
    if port <= 0:
        return "host"
    proto = slug(transport, max_length=8).lower()
    return f"{port}-{proto}" if proto and proto != "none" else str(port)


def host_name(target: str, *, max_length: int = 40) -> str:
    """A readable host component: ``192.0.2.10``, ``web01.example.test``.

    Empty in, empty out -- callers that omit the host must not get the string
    ``unnamed`` wedged into the middle of a filename.
    """
    cleaned = _UNSAFE_HOST.sub("-", target.strip()).strip("-.")
    return cleaned[:max_length]


def host_dir(target: str) -> str:
    """A per-host directory name. Falls back rather than producing an empty path."""
    name = host_name(target)
    if name.upper() in _WINDOWS_RESERVED:
        return f"{name}-host"
    return name or "unknown-host"


def finding_basename(
    *,
    severity: str,
    target: str,
    port: int,
    transport: str,
    title: str,
) -> str:
    """The readable stem for one finding's exported file.

    An empty ``target`` is dropped rather than filled in -- callers that already
    put the host in a parent directory should not repeat it in every filename.
    """
    parts = [
        severity_prefix(severity),
        host_name(target),
        location(port, transport),
        slug(title),
    ]
    stem = "_".join(p for p in parts if p)
    if stem.split("_")[0].upper() in _WINDOWS_RESERVED:
        stem = f"file-{stem}"
    return stem


def disambiguate(
    entries: Iterable[tuple[str, str, str]],
) -> dict[str, str]:
    """Resolve name collisions deterministically.

    Takes ``(key, base_name, plugin_id)`` triples and returns ``{key: name}``.
    Two findings can legitimately share severity, host, port and title -- two
    plugins reporting the same condition, for instance -- so a bare base name is
    not guaranteed unique. Colliding names gain their plugin id; if that still
    collides, a short fragment of the key. Non-colliding names are left clean,
    which is the common case.
    """
    items = list(entries)
    counts: dict[str, int] = {}
    for _key, base, _plugin in items:
        counts[base] = counts.get(base, 0) + 1

    resolved: dict[str, str] = {}
    used: set[str] = set()
    for key, base, plugin_id in items:
        name = base if counts[base] == 1 else f"{base}_plugin{slug(plugin_id, max_length=12)}"
        if name in used:
            name = f"{name}_{slug(key, max_length=12)[-8:]}"
        # Last resort: a numeric suffix, so this function can never return a
        # duplicate and silently overwrite an exported file.
        candidate, counter = name, 2
        while candidate in used:
            candidate = f"{name}-{counter}"
            counter += 1
        used.add(candidate)
        resolved[key] = candidate
    return resolved
