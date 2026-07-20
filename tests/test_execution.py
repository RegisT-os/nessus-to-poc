"""Safe-execution tests (task section 19; mandatory tests 18-21, 25-29)."""

from __future__ import annotations

from pathlib import Path

from vapt_verify.adapters import get_adapter
from vapt_verify.adapters.base import (
    Connector,
    ExecutionContext,
    RawResult,
    RealCommandRunner,
)
from vapt_verify.classification.models import Capabilities
from vapt_verify.execution.runner import Executor, OutcomeStatus
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.enums import Verdict


class FakeCommandRunner:
    def __init__(self, result: RawResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], timeout: float, stdin: str | None = None) -> RawResult:
        self.calls.append(argv)
        return self.result


class FakeConnector(Connector):
    def __init__(self, is_open: bool) -> None:
        self.is_open = is_open

    def connect(self, host: str, port: int, timeout: float) -> bool:
        return self.is_open


def _engagement(cidrs: list[str] | None = None) -> Engagement:
    return Engagement(engagement_id="e", approved_cidrs=cidrs or [])


def _ctx(target: str = "192.0.2.10", port: int = 443, transport: str = "tcp") -> ExecutionContext:
    return ExecutionContext(
        finding_id="find-1", asset_id="asset-1", engagement_id="e",
        target=target, port=port, transport=transport, params={"scripts": ["ssl-cert"]},
        timeout=5.0,
    )


IN_SCOPE = _engagement(["192.0.2.0/24"])
ALL_CAPS = Capabilities(available={"nmap", "openssl", "curl"})


def test_out_of_scope_target_blocked_but_retained() -> None:
    """Task 22.21 — out-of-scope target is blocked from execution but retained."""
    runner = FakeCommandRunner(RawResult(exit_code=0))
    executor = Executor(command_runner=runner, capabilities=ALL_CAPS)
    outcome = executor.run(
        ctx=_ctx(target="203.0.113.9"),  # not in the approved 192.0.2.0/24
        adapter=get_adapter("nmap"),
        engagement=IN_SCOPE,
        dry_run=False,
    )
    assert outcome.status is OutcomeStatus.BLOCKED_OUT_OF_SCOPE
    assert outcome.finding_retained is True
    assert runner.calls == []  # nothing executed


def test_missing_binary_is_capability_gap_not_removal() -> None:
    """Task 22.20 — a missing local binary is a capability gap, not a removal."""
    runner = FakeCommandRunner(RawResult(exit_code=0))
    executor = Executor(command_runner=runner, capabilities=Capabilities(available=set()))
    outcome = executor.run(ctx=_ctx(), adapter=get_adapter("nmap"), engagement=IN_SCOPE,
                           dry_run=False)
    assert outcome.status is OutcomeStatus.CAPABILITY_UNAVAILABLE
    assert outcome.finding_retained is True
    assert runner.calls == []


def test_dry_run_is_default_and_executes_nothing() -> None:
    runner = FakeCommandRunner(RawResult(exit_code=0))
    executor = Executor(command_runner=runner, capabilities=ALL_CAPS)
    outcome = executor.run(ctx=_ctx(), adapter=get_adapter("nmap"), engagement=IN_SCOPE)
    assert outcome.status is OutcomeStatus.DRY_RUN
    assert outcome.planned_command[0] == "nmap"
    assert runner.calls == []


def test_tool_timeout_is_inconclusive(tmp_path: Path) -> None:
    """Task 22.19 — a tool timeout yields INCONCLUSIVE."""
    runner = FakeCommandRunner(RawResult(exit_code=None, timed_out=True))
    executor = Executor(command_runner=runner, capabilities=ALL_CAPS, evidence_root=tmp_path)
    outcome = executor.run(ctx=_ctx(), adapter=get_adapter("nmap"), engagement=IN_SCOPE,
                           dry_run=False)
    assert outcome.status is OutcomeStatus.EXECUTED
    assert outcome.suggested_verdict == Verdict.INCONCLUSIVE.value


def test_nmap_exit_zero_does_not_assign_verdict(tmp_path: Path) -> None:
    """Task 22.25 — an exit code of 0 does not directly assign a verdict."""
    runner = FakeCommandRunner(RawResult(exit_code=0, stdout="443/tcp open https"))
    executor = Executor(command_runner=runner, capabilities=ALL_CAPS, evidence_root=tmp_path)
    outcome = executor.run(ctx=_ctx(), adapter=get_adapter("nmap"), engagement=IN_SCOPE,
                           dry_run=False)
    assert outcome.status is OutcomeStatus.EXECUTED
    assert outcome.suggested_verdict is None  # nmap is supporting; no verdict from exit code
    assert outcome.evidence is not None and outcome.evidence.exit_code == 0


def test_nmap_nonzero_exit_does_not_erase_finding(tmp_path: Path) -> None:
    """Task 22.26 — a non-zero exit does not erase the finding."""
    runner = FakeCommandRunner(RawResult(exit_code=1, stderr="host down"))
    executor = Executor(command_runner=runner, capabilities=ALL_CAPS, evidence_root=tmp_path)
    outcome = executor.run(ctx=_ctx(), adapter=get_adapter("nmap"), engagement=IN_SCOPE,
                           dry_run=False)
    assert outcome.status is OutcomeStatus.EXECUTED
    assert outcome.finding_retained is True
    assert outcome.suggested_verdict != Verdict.FALSE_POSITIVE_CANDIDATE.value


def test_commands_execute_without_shell(monkeypatch) -> None:
    """Task 22.27 — RealCommandRunner never uses a shell."""
    captured: dict[str, object] = {}

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        captured["argv"] = argv
        captured["shell"] = kwargs.get("shell", False)
        return _Proc()

    import vapt_verify.adapters.base as base

    monkeypatch.setattr(base.subprocess, "run", fake_run)
    RealCommandRunner().run(["nmap", "-p", "443", "192.0.2.10"], timeout=5)
    assert isinstance(captured["argv"], list)
    assert captured["shell"] is False


def test_hostile_hostname_cannot_inject(tmp_path: Path) -> None:
    """Task 22.28 — a hostile hostname is a single argv element and is blocked."""
    hostile = "192.0.2.10; rm -rf /"
    argv = get_adapter("nmap").build_argv(_ctx(target=hostile))
    assert argv[-1] == hostile  # one argument, not shell-split

    runner = FakeCommandRunner(RawResult(exit_code=0))
    executor = Executor(command_runner=runner, capabilities=ALL_CAPS, evidence_root=tmp_path)
    outcome = executor.run(ctx=_ctx(target=hostile), adapter=get_adapter("nmap"),
                           engagement=IN_SCOPE, dry_run=False)
    # Scope rejects it as neither a valid IP nor hostname; nothing executed.
    assert outcome.status is OutcomeStatus.BLOCKED_OUT_OF_SCOPE
    assert runner.calls == []


def test_evidence_is_timestamped_and_not_overwritten(tmp_path: Path) -> None:
    """Task 22.29 — output files are timestamped and not silently overwritten."""
    runner = FakeCommandRunner(RawResult(exit_code=0, stdout="run"))
    executor = Executor(command_runner=runner, capabilities=ALL_CAPS, evidence_root=tmp_path)
    for _ in range(2):
        executor.run(ctx=_ctx(), adapter=get_adapter("nmap"), engagement=IN_SCOPE, dry_run=False)
    files = list((tmp_path / "asset-1" / "find-1").glob("*.txt"))
    assert len(files) == 2  # two distinct evidence files, nothing overwritten


def test_closed_port_is_service_not_currently_observed(tmp_path: Path) -> None:
    """Task 22.18 — a closed port yields SERVICE_NOT_CURRENTLY_OBSERVED (not FP)."""
    executor = Executor(connector=FakeConnector(is_open=False), capabilities=ALL_CAPS,
                        evidence_root=tmp_path)
    outcome = executor.run(ctx=_ctx(port=8443), adapter=get_adapter("tcp"), engagement=IN_SCOPE,
                           dry_run=False)
    assert outcome.status is OutcomeStatus.EXECUTED
    assert outcome.suggested_verdict == Verdict.SERVICE_NOT_CURRENTLY_OBSERVED.value
    assert outcome.finding_retained is True


def test_open_port_is_exposure_only_not_confirmation(tmp_path: Path) -> None:
    executor = Executor(connector=FakeConnector(is_open=True), capabilities=ALL_CAPS,
                        evidence_root=tmp_path)
    outcome = executor.run(ctx=_ctx(port=443), adapter=get_adapter("tcp"), engagement=IN_SCOPE,
                           dry_run=False)
    assert outcome.suggested_verdict is None  # reachable != vulnerable


def test_manual_adapter_requests_evidence_without_executing() -> None:
    executor = Executor(capabilities=ALL_CAPS)
    outcome = executor.run(ctx=_ctx(), adapter=get_adapter("credentialed"), engagement=IN_SCOPE,
                           dry_run=False)
    assert outcome.status is OutcomeStatus.MANUAL_REQUIRED
    assert any("credentialed" in n.lower() for n in outcome.notes)
