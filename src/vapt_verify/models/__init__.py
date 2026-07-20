"""Core domain models for the verification platform.

The models deliberately preserve source provenance and keep distinct finding
identities separate (the opposite of the legacy tool's lossy collapse). Each
model is a plain dataclass with explicit ``to_dict`` / ``from_dict`` methods so
that normalized JSONL exports are stable and reviewable.
"""

from vapt_verify.models.asset import Asset
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.enums import (
    Disposition,
    ObservationSource,
    Severity,
    Transport,
    Verdict,
)
from vapt_verify.models.finding import Finding, SourceProvenance
from vapt_verify.models.service import ServiceObservation

__all__ = [
    "Asset",
    "Disposition",
    "Engagement",
    "Finding",
    "ObservationSource",
    "ServiceObservation",
    "Severity",
    "SourceProvenance",
    "Transport",
    "Verdict",
]
