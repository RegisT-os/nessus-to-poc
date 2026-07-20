"""VAPT Verification Orchestrator.

A local-first, multi-engagement vulnerability verification and evidence
orchestration platform.

Design invariant (see docs/METHODOLOGY.md):

    Every imported source finding must appear in the normalized inventory and
    receive an explicit, reviewable verification disposition. No finding may
    disappear silently.

The v0.1 core implements the lossless-import foundation: safe Nessus XML
parsing, a full finding model with source provenance, JSONL normalized
exports and a reconciliation gate that fails closed when findings are lost
without an explicit disposition.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
