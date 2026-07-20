"""testssl.sh adapter (authoritative TLS assessment)."""

from __future__ import annotations

from vapt_verify.adapters._command import SimpleCommandAdapter
from vapt_verify.adapters.base import ExecutionContext


class TestsslAdapter(SimpleCommandAdapter):
    name = "testssl"
    capability = "testssl.sh"

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        argv = ["testssl.sh", "--warnings", "batch", "--quiet"]
        vhost = ctx.params.get("vhost") or ctx.params.get("servername")
        target = f"{vhost}" if vhost else ctx.target
        # Connect to the IP but present the vhost via URI when known.
        argv.append(f"{ctx.target}:{ctx.port}" if not vhost else f"{target}:{ctx.port}")
        return argv
