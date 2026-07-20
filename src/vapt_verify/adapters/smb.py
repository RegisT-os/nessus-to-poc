"""smbclient adapter (non-destructive share/dialect enumeration)."""

from __future__ import annotations

from vapt_verify.adapters._command import SimpleCommandAdapter
from vapt_verify.adapters.base import ExecutionContext


class SmbAdapter(SimpleCommandAdapter):
    name = "smb"
    capability = "smbclient"

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        return ["smbclient", "-L", f"//{ctx.target}", "-N", "-g"]
