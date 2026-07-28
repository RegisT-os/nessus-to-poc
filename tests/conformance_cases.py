"""Adapter conformance cases (roadmap v3.4).

Why this exists
---------------
The OpenSSL adapter once parsed for full-mode ``CONNECTED(`` while its own
``build_argv`` invoked ``-brief``, which prints ``CONNECTION ESTABLISHED``.
Every successful TLS capture therefore recorded itself as a failed connection.
Unit tests passed throughout, because they asserted against the *assumed*
format rather than the tool's real output.

A conformance case pins three things together so that class of bug cannot
recur:

1. the **golden output** a tool actually produces,
2. the **invocation** that output came from, and
3. the **observations** the adapter's parser must extract from it.

The suite then asserts that the adapter's current ``build_argv`` is still
compatible with the invocation the fixture was captured under — so if an
adapter changes its flags, the mismatched parser is caught immediately.

Fixture provenance
------------------
:class:`Provenance` distinguishes fixtures captured from a real tool run from
those authored against documentation. **Authored fixtures are a known
limitation, not a validation** — they encode an assumption about a format,
which is the very thing that caused the original bug. They are labelled, counted
and reported so the gap stays visible, and they should be replaced with real
captures wherever the tool can be installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "tool_output"


class Provenance(Enum):
    #: Captured by running the real tool. Trustworthy.
    REAL_CAPTURE = "real_capture"
    #: Written from vendor documentation/manpages. An assumption until a real
    #: capture replaces it; the tool was unavailable in this environment.
    AUTHORED = "authored"


@dataclass
class ConformanceCase:
    """One golden output plus what the adapter must make of it."""

    adapter: str
    name: str
    fixture: str
    provenance: Provenance
    #: Flags the fixture's invocation used, e.g. ``["-brief"]``. The suite
    #: asserts the adapter's build_argv still produces these, catching the
    #: "parser expects a format the adapter never requests" bug.
    required_argv_flags: list[str] = field(default_factory=list)
    #: Context overrides passed to the adapter when building/parsing.
    context: dict[str, Any] = field(default_factory=dict)
    #: Observations the parser must produce (subset match).
    expect_observations: dict[str, Any] = field(default_factory=dict)
    #: Substrings that must appear somewhere in the parsed observation values.
    expect_contains: dict[str, str] = field(default_factory=dict)
    #: Suggested verdict the parser must return (``None`` means "no verdict").
    expect_suggested_verdict: str | None = None
    #: Simulated process state for the fixture.
    exit_code: int | None = 0
    stream: str = "stdout"  # which stream the fixture content represents
    notes: str = ""

    def read(self) -> str:
        return (FIXTURE_ROOT / self.fixture).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
CASES: list[ConformanceCase] = [
    # -- openssl: the adapter builds -brief, so THIS is the format that matters
    ConformanceCase(
        adapter="openssl",
        name="self-signed certificate, -brief mode",
        fixture="openssl/self_signed_brief.txt",
        provenance=Provenance.REAL_CAPTURE,
        required_argv_flags=["-brief"],
        stream="stderr",
        expect_observations={
            "connected": True,
            "handshake_captured": True,
            "self_signed_indicated": True,
        },
        expect_contains={
            "peer_certificate": "conformance.example.test",
            "protocol": "TLSv1.3",
            "verify_error": "self-signed",
        },
        expect_suggested_verdict=None,  # reviewer decides; never the tool
        notes="The regression case: -brief prints 'CONNECTION ESTABLISHED', "
              "not 'CONNECTED('. A parser matching only the latter reports a "
              "successful capture as a failed connection.",
    ),
    ConformanceCase(
        adapter="openssl",
        name="self-signed certificate, full (non-brief) mode",
        fixture="openssl/self_signed_full.txt",
        provenance=Provenance.REAL_CAPTURE,
        # No flag requirement: this proves the parser ALSO handles the other
        # form, so a future switch away from -brief cannot silently break it.
        required_argv_flags=[],
        stream="stdout",
        expect_observations={"connected": True, "self_signed_indicated": True},
        expect_suggested_verdict=None,
    ),
    ConformanceCase(
        adapter="openssl",
        name="connection refused",
        fixture="openssl/connection_refused.txt",
        provenance=Provenance.REAL_CAPTURE,
        stream="stderr",
        exit_code=1,
        expect_observations={"connected": False, "handshake_captured": False},
        expect_suggested_verdict=None,
        notes="A refused connection must NOT yield a verdict: unreachability "
              "is not evidence the condition is absent.",
    ),
    # -- curl
    ConformanceCase(
        adapter="http",
        name="HTTPS response headers",
        fixture="curl/https_headers.txt",
        provenance=Provenance.REAL_CAPTURE,
        context={"port": 8446, "params": {"tls": True}},
        expect_suggested_verdict=None,
        expect_contains={"status_line": "200"},
        notes="Headers are parsed into a mapping; the reviewer confirms the "
              "reported header/cookie condition.",
    ),
    # -- authored fixtures: tools unavailable in this environment ------------
    ConformanceCase(
        adapter="nmap",
        name="open port with service detection",
        fixture="nmap/open_port.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 443, "transport": "tcp"},
        expect_observations={"port_state": "open"},
        expect_suggested_verdict=None,
        notes="Nmap is supporting evidence only; the parser must never return "
              "a verdict, whatever the exit code.",
    ),
    ConformanceCase(
        adapter="nmap",
        name="closed/filtered port",
        fixture="nmap/closed_port.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 8443, "transport": "tcp"},
        expect_observations={"port_state": "closed_or_filtered"},
        expect_suggested_verdict=None,
    ),
    ConformanceCase(
        adapter="ssh_audit",
        name="weak algorithms offered",
        fixture="ssh_audit/weak_algorithms.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 22},
        expect_suggested_verdict=None,
    ),
    ConformanceCase(
        adapter="sslscan",
        name="deprecated protocols enabled",
        fixture="sslscan/deprecated_protocols.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 443},
        expect_suggested_verdict=None,
    ),
    ConformanceCase(
        adapter="testssl",
        name="deprecated protocols and expired self-signed chain",
        fixture="testssl/weak_protocols.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 443},
        expect_suggested_verdict=None,
        notes="Added because the coverage test flagged testssl as having no "
              "conformance case at all.",
    ),
    ConformanceCase(
        adapter="dns",
        name="recursion available",
        fixture="dns/recursion.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 53, "transport": "udp"},
        expect_suggested_verdict=None,
    ),
    ConformanceCase(
        adapter="snmp",
        name="community string accepted",
        fixture="snmp/sysdescr.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 161, "transport": "udp", "params": {"community": "public"}},
        expect_suggested_verdict=None,
    ),
    ConformanceCase(
        adapter="smb",
        name="share enumeration",
        fixture="smb/shares.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 445},
        expect_suggested_verdict=None,
    ),
    ConformanceCase(
        adapter="ldap",
        name="anonymous rootDSE",
        fixture="ldap/rootdse.txt",
        provenance=Provenance.AUTHORED,
        context={"port": 389},
        expect_suggested_verdict=None,
    ),
]


def cases_for(adapter: str) -> list[ConformanceCase]:
    return [c for c in CASES if c.adapter == adapter]


def real_capture_count() -> int:
    return sum(1 for c in CASES if c.provenance is Provenance.REAL_CAPTURE)


def authored_count() -> int:
    return sum(1 for c in CASES if c.provenance is Provenance.AUTHORED)
