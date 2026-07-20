"""Database adapter (evidence request — no automated password attacks).

Database validation needs product-specific native clients and, often,
authorised credentials. By default this adapter does not execute anything: it
describes the safe connection/version check to perform. No brute force, no
password spraying (task section 12.11).
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


class DatabaseAdapter(Adapter):
    name = "database"
    kind = AdapterKind.MANUAL
    safety_class = SafetyClass.MANUAL

    def parse(self, ctx: ExecutionContext, raw: RawResult) -> ParsedResult:
        return ParsedResult({}, suggested_verdict=None, note=self.evidence_request(ctx))

    def evidence_request(self, ctx: ExecutionContext) -> str:
        return (
            "Database validation required. Use the product's native client for a safe "
            "connection/version check (and authenticated configuration queries only where "
            "explicitly permitted). No password attacks by default."
        )
