"""TCP connect adapter (in-process, no external binary).

Confirms whether a port is *currently* reachable from the validation source.
A closed port yields a ``SERVICE_NOT_CURRENTLY_OBSERVED`` suggestion — never a
false-positive verdict, and it never erases the historical finding.
"""

from __future__ import annotations

from vapt_verify.adapters.base import (
    Adapter,
    AdapterKind,
    Connector,
    ExecutionContext,
    ParsedResult,
    RawResult,
)
from vapt_verify.models.enums import Verdict
from vapt_verify.models.recipe import SafetyClass


class TcpConnectAdapter(Adapter):
    name = "tcp"
    capability = ""  # pure Python
    kind = AdapterKind.INPROCESS
    safety_class = SafetyClass.ACTIVE_NONINTRUSIVE

    def run_inprocess(self, ctx: ExecutionContext, connector: Connector) -> RawResult:
        is_open = connector.connect(ctx.target, ctx.port, ctx.timeout)
        return RawResult(exit_code=0, port_open=is_open,
                         stdout=f"port {ctx.port} {'open' if is_open else 'closed'}")

    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult:
        if raw.timed_out:
            return ParsedResult({"port_open": None}, Verdict.INCONCLUSIVE, "connection timed out")
        if raw.port_open is True:
            # Reachability only — NOT vulnerability confirmation.
            return ParsedResult(
                {"port_open": True},
                suggested_verdict=None,
                note="Port is reachable; exposure confirmed, vulnerability not.",
            )
        return ParsedResult(
            {"port_open": False},
            suggested_verdict=Verdict.SERVICE_NOT_CURRENTLY_OBSERVED,
            note="Port is not reachable from the validation source; the finding is retained.",
        )
