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
        if vhost:
            # `--ip` pins the socket to the scope-checked address while the URI
            # supplies the SNI and certificate name. Passing the vhost alone
            # would resolve it via DNS and connect wherever that points -- which
            # is not the host the engagement authorised, and not necessarily the
            # host the scanner saw.
            argv += ["--ip", ctx.target, f"{vhost}:{ctx.port}"]
        else:
            argv.append(f"{ctx.target}:{ctx.port}")
        return argv
