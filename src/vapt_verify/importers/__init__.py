"""Scanner importers.

Every importer must be *lossless*: each source record becomes either a
normalized finding or an explicitly recorded parse failure. An importer may
never silently discard a record. The reconciliation gate enforces this after
the fact (task section 14).
"""

from vapt_verify.importers.base import ImportResult, ParseFailure

__all__ = ["ImportResult", "ParseFailure"]
