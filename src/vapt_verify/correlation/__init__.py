"""Cross-scanner correlation: links and candidate groups, never silent merges."""

from vapt_verify.correlation.diff import (
    ChangeKind,
    DiffEntry,
    ImportSetDiff,
    diff_import_sets,
)
from vapt_verify.correlation.engine import CorrelationEngine, normalize_title
from vapt_verify.correlation.models import (
    AssetIdentityGroup,
    AssetLinkBasis,
    CorrelationGroup,
    CorrelationReport,
    LinkBasis,
)

__all__ = [
    "AssetIdentityGroup",
    "AssetLinkBasis",
    "ChangeKind",
    "CorrelationEngine",
    "CorrelationGroup",
    "CorrelationReport",
    "DiffEntry",
    "ImportSetDiff",
    "LinkBasis",
    "diff_import_sets",
    "normalize_title",
]
