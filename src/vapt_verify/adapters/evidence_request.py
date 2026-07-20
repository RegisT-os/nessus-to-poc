"""Evidence-request adapters (manual / administrative / credentialed).

These adapters do NOT execute anything. They describe the evidence a human must
supply, so a finding that cannot be validated by automation still has a concrete
path to resolution instead of being dropped.
"""

from __future__ import annotations

from vapt_verify.adapters.base import (
    Adapter,
    AdapterKind,
    ExecutionContext,
    ParsedResult,
    RawResult,
)
from vapt_verify.models.recipe import SafetyClass


class _ManualBase(Adapter):
    kind = AdapterKind.MANUAL
    safety_class = SafetyClass.MANUAL

    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult:
        return ParsedResult({}, suggested_verdict=None, note=self.evidence_request(ctx))


class ManualAdapter(_ManualBase):
    name = "manual"

    def evidence_request(self, ctx: ExecutionContext) -> str:
        return (
            "Manual validation required. Reproduce the condition with an authorised account/role "
            "and attach request/response (or command/output) evidence."
        )


class AdministrativeAdapter(_ManualBase):
    name = "administrative"

    def evidence_request(self, ctx: ExecutionContext) -> str:
        return (
            "Administrative evidence required. Request the exact build/patch level, "
            "configuration export, or management-console output from the system owner, and "
            "map it to the reported condition/advisory."
        )


class CredentialedAdapter(_ManualBase):
    name = "credentialed"

    def evidence_request(self, ctx: ExecutionContext) -> str:
        return (
            "Credentialed validation required. Re-verify via an authenticated rescan or "
            "package/patch-management evidence; a remote unauthenticated check cannot reproduce "
            "this local-check finding."
        )
