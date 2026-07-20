"""Nmap adapter.

Nmap is *supporting* evidence for most findings and *primary* only for basic
exposure. Its parser NEVER assigns a confirming verdict and NEVER uses the exit
code to decide anything: a non-zero exit does not erase a finding, and a zero
exit does not confirm one.
"""

from __future__ import annotations

from vapt_verify.adapters.base import Adapter, ExecutionContext, ParsedResult, RawResult
from vapt_verify.models.recipe import SafetyClass


class NmapAdapter(Adapter):
    name = "nmap"
    capability = "nmap"
    safety_class = SafetyClass.ACTIVE_NONINTRUSIVE

    def build_argv(self, ctx: ExecutionContext) -> list[str]:
        scan_flag = "-sU" if ctx.transport == "udp" else "-sT"
        argv = ["nmap", "-Pn", scan_flag, "-p", str(ctx.port)]
        scripts = ctx.params.get("scripts")
        if isinstance(scripts, list) and scripts:
            argv += ["--script", ",".join(str(s) for s in scripts)]
        if ctx.params.get("service_detection"):
            argv.append("-sV")
        # The target is always the final, single argument — never shell-split.
        argv.append(ctx.target)
        return argv

    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult:
        if raw.timed_out:
            from vapt_verify.models.enums import Verdict

            return ParsedResult({"timed_out": True}, Verdict.INCONCLUSIVE, "nmap timed out")
        text = raw.stdout.lower()
        observations = {
            "port_state": (
                "open" if f"{ctx.port}/" in text and "open" in text
                else "closed_or_filtered" if ("closed" in text or "filtered" in text)
                else "unknown"
            ),
            "exit_code": raw.exit_code,
        }
        # Deliberately no suggested verdict: Nmap is supporting evidence only, and
        # the exit code is not evidence of the vulnerability's state.
        return ParsedResult(
            observations,
            suggested_verdict=None,
            note="Nmap output is supporting evidence; it does not by itself set a verdict.",
        )
