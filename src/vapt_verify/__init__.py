"""VAPT Verification Orchestrator.

A local-first, multi-engagement vulnerability verification and evidence
orchestration platform.

Design invariant (see docs/METHODOLOGY.md):

    Every imported source finding must appear in the normalized inventory and
    receive an explicit, reviewable verification disposition. No finding may
    disappear silently.

The platform spans lossless multi-scanner import (with a fail-closed
reconciliation gate), explainable classification and planning, dry-run-by-default
safe execution with hashed evidence, a reviewer-owned decision workflow,
coverage-first reporting, and — from v2.0 — cross-scanner correlation that links
findings without ever merging or removing them.
"""

__version__ = "2.6.0"
__all__ = ["__version__"]
