"""OpenSSL adapter (TLS).

Used as a primary tool for TLS/certificate findings, with SNI support. The
parser captures certificate/handshake observations; the confirming/refuting
decision is left to the reviewer (v0.6), because a raw handshake needs
interpretation against the specific reported condition.
"""

from __future__ import annotations

from vapt_verify.adapters.base import Adapter, ExecutionContext, ParsedResult, RawResult
from vapt_verify.models.recipe import SafetyClass


class OpensslAdapter(Adapter):
    name = "openssl"
    capability = "openssl"
    safety_class = SafetyClass.ACTIVE_NONINTRUSIVE

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        argv = ["openssl", "s_client", "-connect", f"{ctx.target}:{ctx.port}"]
        vhost = ctx.params.get("vhost") or ctx.params.get("servername")
        if vhost:
            argv += ["-servername", str(vhost)]
        starttls = ctx.params.get("starttls")
        if starttls:
            argv += ["-starttls", str(starttls)]
        argv.append("-brief")
        return argv

    def stdin(self, ctx: ExecutionContext) -> str | None:
        # Send EOF so s_client completes the handshake and exits.
        return ""

    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult:
        if raw.timed_out:
            from vapt_verify.models.enums import Verdict

            return ParsedResult({"timed_out": True}, Verdict.INCONCLUSIVE, "openssl timed out")
        text = raw.stdout + "\n" + raw.stderr
        observations = {
            "connected": "CONNECTED" in text,
            "verify_return_code": _extract(text, "Verify return code:"),
            "protocol": _extract(text, "Protocol"),
            "cipher": _extract(text, "Cipher"),
            "handshake_captured": "CONNECTED" in text or "SSL handshake" in text,
        }
        return ParsedResult(
            observations,
            suggested_verdict=None,
            note="TLS handshake captured; reviewer interprets it against the reported condition.",
        )


def _extract(text: str, marker: str) -> str:
    for line in text.splitlines():
        if marker in line:
            return line.strip()
    return ""
