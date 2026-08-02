"""HTTP adapter (curl-based header inspection).

Fetches response headers with the correct Host/SNI. Header/cookie hygiene
findings can be confirmed from content; application-level issues cannot and are
routed to manual validation by classification, not here.
"""

from __future__ import annotations

from vapt_verify.adapters.base import Adapter, ExecutionContext, ParsedResult, RawResult
from vapt_verify.models.recipe import SafetyClass


class HttpAdapter(Adapter):
    name = "http"
    capability = "curl"
    safety_class = SafetyClass.ACTIVE_NONINTRUSIVE
    produces_observations = ("headers", "status_line", "timed_out")

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        tls = bool(ctx.params.get("tls")) or ctx.port in {443, 8443}
        scheme = "https" if tls else "http"
        vhost = ctx.params.get("vhost") or ctx.params.get("servername") or ctx.target
        url = f"{scheme}://{ctx.target}:{ctx.port}/"
        argv = ["curl", "-sS", "-o", "/dev/null", "-D", "-", "--max-time", str(int(ctx.timeout))]
        method = str(ctx.params.get("method", "HEAD")).upper()
        if method == "HEAD":
            argv.append("-I")
        else:
            argv += ["-X", method]
        if ctx.params.get("follow_redirects"):
            argv.append("-L")
        # Host header carries the vhost; the URL uses the IP/target explicitly.
        argv += ["-H", f"Host: {vhost}", url]
        return argv

    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult:
        if raw.timed_out:
            from vapt_verify.models.enums import Verdict

            return ParsedResult({"timed_out": True}, Verdict.INCONCLUSIVE, "curl timed out")
        headers = {}
        for line in raw.stdout.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()
        status_line = raw.stdout.splitlines()[0] if raw.stdout else ""
        return ParsedResult(
            {"headers": headers, "status_line": status_line},
            suggested_verdict=None,
            note="Response headers captured; reviewer confirms the reported condition.",
        )
