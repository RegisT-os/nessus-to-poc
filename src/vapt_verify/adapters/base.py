"""Adapter framework (task section 19).

An adapter knows how to build a *structured* command (an argument array — never a
shell string) for one verification tool, and how to parse that tool's output
into observations and, at most, a *suggested* verdict. Adapters never:

* use a shell (no ``shell=True``, no string interpolation into a shell);
* decide a verdict from an exit code;
* remove a finding.

The verdict a parser suggests comes from the *content* of the evidence, and is
always a suggestion for a human reviewer — never a final decision.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from vapt_verify.models.enums import Verdict
from vapt_verify.models.recipe import SafetyClass


class AdapterKind(Enum):
    COMMAND = "command"  # runs an external binary via argv
    INPROCESS = "inprocess"  # runs pure-Python logic (e.g. a TCP connect)
    MANUAL = "manual"  # produces an evidence *request*; never executes


@dataclass
class ExecutionContext:
    finding_id: str
    asset_id: str
    engagement_id: str
    target: str
    port: int
    transport: str
    params: dict[str, Any] = field(default_factory=dict)
    operator: str = "unknown"
    timeout: float = 120.0


@dataclass
class RawResult:
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    port_open: bool | None = None


@dataclass
class ParsedResult:
    observations: dict[str, Any] = field(default_factory=dict)
    # A *suggestion* for the reviewer, derived from evidence content — NOT from
    # the exit code, and never a final decision.
    suggested_verdict: Verdict | None = None
    note: str = ""


class CommandRunner(Protocol):
    """Executes an argv array without a shell and returns a RawResult."""

    def run(self, argv: list[str], timeout: float, stdin: str | None = None) -> RawResult: ...


class Connector(Protocol):
    """Tests whether a TCP port is open (injectable for tests)."""

    def connect(self, host: str, port: int, timeout: float) -> bool: ...


class RealCommandRunner:
    """Runs commands with ``subprocess`` using an argument array and no shell."""

    def run(self, argv: list[str], timeout: float, stdin: str | None = None) -> RawResult:
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False (default)
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return RawResult(
                exit_code=None,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr="timed out",
                timed_out=True,
            )
        except FileNotFoundError:
            return RawResult(exit_code=None, stderr="binary not found")
        return RawResult(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


class RealConnector:
    def connect(self, host: str, port: int, timeout: float) -> bool:
        import socket

        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False


class Adapter(ABC):
    name: str = "adapter"
    capability: str = ""  # required external binary; "" means none needed
    kind: AdapterKind = AdapterKind.COMMAND
    safety_class: SafetyClass = SafetyClass.ACTIVE_NONINTRUSIVE
    #: Observation keys this adapter's parser can produce. Playbook validation
    #: uses these to reject a condition reading an observation nothing emits --
    #: a typo there produces a step that silently never runs, which is
    #: indistinguishable from one that simply never applies. An empty tuple
    #: means "undeclared", and validation declines to guess rather than warn
    #: falsely.
    produces_observations: tuple[str, ...] = ()

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        raise NotImplementedError(f"{self.name} is not a command adapter")

    def stdin(self, ctx: ExecutionContext) -> str | None:
        return None

    def run_inprocess(self, ctx: ExecutionContext, connector: Connector) -> RawResult:
        raise NotImplementedError(f"{self.name} is not an in-process adapter")

    @abstractmethod
    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult: ...

    def evidence_request(self, ctx: ExecutionContext) -> str:
        """Human-readable description of the evidence this adapter needs."""
        return f"Provide evidence for {self.name}."
