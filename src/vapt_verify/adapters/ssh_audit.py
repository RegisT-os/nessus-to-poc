"""ssh-audit adapter (SSH algorithm/MAC/KEX enumeration)."""

from __future__ import annotations

from vapt_verify.adapters._command import SimpleCommandAdapter
from vapt_verify.adapters.base import ExecutionContext


class SshAuditAdapter(SimpleCommandAdapter):
    name = "ssh_audit"
    capability = "ssh-audit"

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        return ["ssh-audit", "-p", str(ctx.port or 22), ctx.target]
