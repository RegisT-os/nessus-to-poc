"""dig adapter (DNS queries). Zone transfers only when explicitly authorised."""

from __future__ import annotations

from vapt_verify.adapters._command import SimpleCommandAdapter
from vapt_verify.adapters.base import ExecutionContext


class DnsAdapter(SimpleCommandAdapter):
    name = "dns"
    capability = "dig"

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        name = str(ctx.params.get("query", "."))
        qtype = str(ctx.params.get("qtype", "NS"))
        argv = ["dig", f"@{ctx.target}", name, qtype, "+time=5", "+tries=1"]
        if ctx.params.get("dnssec"):
            argv.append("+dnssec")
        return argv
