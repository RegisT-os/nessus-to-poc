"""Adapter conformance suite (roadmap v3.4).

Runs every adapter's parser against golden tool output and asserts three things
that, together, prevent the OpenSSL `-brief` class of bug:

1. the parser extracts the expected observations from **real** tool output;
2. the adapter's current ``build_argv`` still matches the invocation the
   fixture was captured under (format drift is caught immediately);
3. no parser ever returns a verdict it is not entitled to.

Fixture provenance is asserted too: authored fixtures are a tracked limitation,
not a validation.
"""

from __future__ import annotations

import pytest

from conformance_cases import CASES, FIXTURE_ROOT, ConformanceCase, Provenance
from vapt_verify.adapters import all_adapters, get_adapter
from vapt_verify.adapters.base import AdapterKind, ExecutionContext, RawResult


def _context(case: ConformanceCase) -> ExecutionContext:
    base: dict[str, object] = {
        "finding_id": "find-conf",
        "asset_id": "asset-conf",
        "engagement_id": "eng-conf",
        "target": "192.0.2.10",
        "port": 443,
        "transport": "tcp",
        "params": {},
    }
    base.update(case.context)
    return ExecutionContext(**base)  # type: ignore[arg-type]


def _raw(case: ConformanceCase) -> RawResult:
    text = case.read()
    if case.stream == "stderr":
        return RawResult(exit_code=case.exit_code, stdout="", stderr=text)
    return RawResult(exit_code=case.exit_code, stdout=text, stderr="")


def _ids(cases: list[ConformanceCase]) -> list[str]:
    return [f"{c.adapter}:{c.name}" for c in cases]


# --- the core conformance assertions ---------------------------------------

@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_parser_extracts_expected_observations(case: ConformanceCase) -> None:
    adapter = get_adapter(case.adapter)
    assert adapter is not None, f"unknown adapter {case.adapter}"
    result = adapter.parse(_context(case), _raw(case))

    for key, expected in case.expect_observations.items():
        assert key in result.observations, (
            f"{case.adapter} parser did not produce observation {key!r} from "
            f"{case.fixture}"
        )
        assert result.observations[key] == expected, (
            f"{case.adapter}: observation {key!r} was "
            f"{result.observations[key]!r}, expected {expected!r} "
            f"(fixture {case.fixture})"
        )

    for key, substring in case.expect_contains.items():
        assert key in result.observations, f"missing observation {key!r}"
        actual = str(result.observations[key])
        assert substring.lower() in actual.lower(), (
            f"{case.adapter}: observation {key!r} = {actual!r} does not contain "
            f"{substring!r}"
        )


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_parser_returns_only_the_permitted_verdict(case: ConformanceCase) -> None:
    """A parser must not invent a verdict from tool output or exit code."""
    adapter = get_adapter(case.adapter)
    result = adapter.parse(_context(case), _raw(case))
    actual = result.suggested_verdict.value if result.suggested_verdict else None
    assert actual == case.expect_suggested_verdict, (
        f"{case.adapter} suggested {actual!r}, expected "
        f"{case.expect_suggested_verdict!r} for {case.fixture}"
    )


@pytest.mark.parametrize(
    "case", [c for c in CASES if c.required_argv_flags],
    ids=_ids([c for c in CASES if c.required_argv_flags]),
)
def test_adapter_still_invokes_the_format_the_fixture_captured(
    case: ConformanceCase,
) -> None:
    """The bug-class guard.

    If an adapter changes its flags, its parser may silently start receiving a
    different output format. This pins the fixture's invocation to what
    ``build_argv`` produces today.
    """
    adapter = get_adapter(case.adapter)
    argv = adapter.build_argv(_context(case))
    for flag in case.required_argv_flags:
        assert flag in argv, (
            f"{case.adapter} no longer invokes {flag!r} (argv={argv}), but the "
            f"golden fixture {case.fixture} was captured with it. Either update "
            f"the fixture to the new invocation, or restore the flag: the parser "
            f"is now reading a format the adapter does not request."
        )


# --- the specific regression that motivated this suite ---------------------

def test_openssl_parses_both_brief_and_full_handshake_forms() -> None:
    """`-brief` prints 'CONNECTION ESTABLISHED'; full mode prints 'CONNECTED('.

    Matching only one form made every successful capture look like a failure.
    """
    adapter = get_adapter("openssl")
    ctx = ExecutionContext(
        finding_id="f", asset_id="a", engagement_id="e",
        target="192.0.2.10", port=443, transport="tcp",
    )
    brief = adapter.parse(ctx, RawResult(
        exit_code=0, stderr=(FIXTURE_ROOT / "openssl/self_signed_brief.txt").read_text()
    ))
    full = adapter.parse(ctx, RawResult(
        exit_code=0, stdout=(FIXTURE_ROOT / "openssl/self_signed_full.txt").read_text()
    ))
    assert brief.observations["connected"] is True
    assert full.observations["connected"] is True


def test_exit_code_zero_on_refused_connection_does_not_imply_success() -> None:
    """Even with exit 0, a refused connection must parse as not-connected."""
    adapter = get_adapter("openssl")
    ctx = ExecutionContext(
        finding_id="f", asset_id="a", engagement_id="e",
        target="192.0.2.10", port=443, transport="tcp",
    )
    result = adapter.parse(ctx, RawResult(
        exit_code=0,  # deliberately 0
        stderr=(FIXTURE_ROOT / "openssl/connection_refused.txt").read_text(),
    ))
    assert result.observations["connected"] is False
    assert result.suggested_verdict is None


# --- timeout handling is uniform across adapters ---------------------------

@pytest.mark.parametrize(
    "adapter_name",
    ["openssl", "http", "nmap", "ssh_audit", "sslscan", "dns", "snmp", "smb", "ldap"],
)
def test_timeout_is_inconclusive_for_every_command_adapter(adapter_name: str) -> None:
    adapter = get_adapter(adapter_name)
    ctx = ExecutionContext(
        finding_id="f", asset_id="a", engagement_id="e",
        target="192.0.2.10", port=443, transport="tcp",
    )
    result = adapter.parse(ctx, RawResult(exit_code=None, timed_out=True))
    assert result.suggested_verdict is not None
    assert result.suggested_verdict.value == "inconclusive", (
        f"{adapter_name} must report a timeout as INCONCLUSIVE, not as evidence "
        "of absence"
    )


# --- provenance & coverage bookkeeping -------------------------------------

def test_every_fixture_file_is_referenced_by_a_case() -> None:
    """A stray fixture is either dead weight or an untested format."""
    on_disk = {
        str(p.relative_to(FIXTURE_ROOT)).replace("\\", "/")
        for p in FIXTURE_ROOT.rglob("*.txt")
    }
    referenced = {c.fixture for c in CASES}
    assert on_disk == referenced, (
        f"unreferenced fixtures: {sorted(on_disk - referenced)}; "
        f"missing fixtures: {sorted(referenced - on_disk)}"
    )


def test_authored_fixtures_declare_their_provenance_in_file() -> None:
    """An authored fixture must say so, so nobody mistakes it for a capture."""
    for case in CASES:
        if case.provenance is Provenance.AUTHORED:
            assert "PROVENANCE: AUTHORED" in case.read(), (
                f"{case.fixture} is marked AUTHORED but does not say so in-file"
            )


def test_real_captures_are_not_mislabelled() -> None:
    """A real capture must NOT carry the authored banner."""
    for case in CASES:
        if case.provenance is Provenance.REAL_CAPTURE:
            assert "PROVENANCE: AUTHORED" not in case.read(), (
                f"{case.fixture} is marked REAL_CAPTURE but carries the authored banner"
            )


def test_locally_available_tools_have_real_captures() -> None:
    """If a tool can be run here, its fixtures must be real captures.

    This is what makes conformance coverage improve over time: install a tool,
    and the suite immediately demands a genuine capture for it.
    """
    import shutil

    tool_for_adapter = {
        "openssl": "openssl", "http": "curl", "nmap": "nmap",
        "ssh_audit": "ssh-audit", "sslscan": "sslscan", "dns": "dig",
        "snmp": "snmpget", "smb": "smbclient", "ldap": "ldapsearch",
    }
    for case in CASES:
        tool = tool_for_adapter.get(case.adapter)
        if tool and shutil.which(tool) and case.provenance is Provenance.AUTHORED:
            pytest.fail(
                f"{tool} is installed in this environment, so {case.fixture} "
                f"should be replaced with a real capture rather than an authored one."
            )


def test_every_command_adapter_has_at_least_one_case() -> None:
    """No command adapter ships without its parser being exercised."""
    covered = {c.adapter for c in CASES}
    for adapter in all_adapters():
        if adapter.kind is AdapterKind.COMMAND:
            assert adapter.name in covered, (
                f"command adapter {adapter.name!r} has no conformance case; add "
                "golden output for it"
            )
