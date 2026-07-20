"""Shared base for simple command adapters that capture output as supporting
or primary evidence but leave the confirming/refuting decision to a reviewer.
"""

from __future__ import annotations

from vapt_verify.adapters.base import Adapter, ExecutionContext, ParsedResult, RawResult
from vapt_verify.models.enums import Verdict
from vapt_verify.models.recipe import SafetyClass


class SimpleCommandAdapter(Adapter):
    """A command adapter whose parser records output and suggests no verdict.

    On timeout it suggests ``INCONCLUSIVE`` (never a false positive). Subclasses
    implement :meth:`build_argv` and may override :meth:`parse`.
    """

    safety_class = SafetyClass.ACTIVE_NONINTRUSIVE

    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult:
        if raw.timed_out:
            return ParsedResult({"timed_out": True}, Verdict.INCONCLUSIVE, f"{self.name} timed out")
        return ParsedResult(
            {"output_lines": raw.stdout.splitlines()[:200], "exit_code": raw.exit_code},
            suggested_verdict=None,
            note=f"{self.name} output captured as evidence; reviewer interprets it.",
        )
