"""snmpget adapter. Only the reported community is tested; no guessing."""

from __future__ import annotations

from vapt_verify.adapters._command import SimpleCommandAdapter
from vapt_verify.adapters.base import ExecutionContext


class SnmpAdapter(SimpleCommandAdapter):
    name = "snmp"
    capability = "snmpget"

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        community = str(ctx.params.get("community", "public"))
        version = str(ctx.params.get("version", "2c"))
        oid = str(ctx.params.get("oid", "1.3.6.1.2.1.1.1.0"))
        return ["snmpget", "-v", version, "-c", community, "-t", "3", "-r", "1",
                f"{ctx.target}:{ctx.port or 161}", oid]
