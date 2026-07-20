"""sslscan adapter (TLS protocol/cipher enumeration)."""

from __future__ import annotations

from vapt_verify.adapters._command import SimpleCommandAdapter
from vapt_verify.adapters.base import ExecutionContext


class SslscanAdapter(SimpleCommandAdapter):
    name = "sslscan"
    capability = "sslscan"

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        argv = ["sslscan", "--no-colour"]
        vhost = ctx.params.get("vhost") or ctx.params.get("servername")
        if vhost:
            argv.append(f"--sni-name={vhost}")
        argv.append(f"{ctx.target}:{ctx.port}")
        return argv
