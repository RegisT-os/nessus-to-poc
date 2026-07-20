"""ldapsearch adapter (anonymous rootDSE posture)."""

from __future__ import annotations

from vapt_verify.adapters._command import SimpleCommandAdapter
from vapt_verify.adapters.base import ExecutionContext


class LdapAdapter(SimpleCommandAdapter):
    name = "ldap"
    capability = "ldapsearch"

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        scheme = "ldaps" if ctx.params.get("tls") or ctx.port == 636 else "ldap"
        return ["ldapsearch", "-x", "-H", f"{scheme}://{ctx.target}:{ctx.port or 389}",
                "-s", "base", "-b", "", "+"]
