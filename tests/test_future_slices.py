"""Placeholders for the remaining mandatory regression test owned by a later slice.

The task brief (section 22) lists 32 mandatory regression tests. All are now
implemented except one, which belongs to the review/decision workflow:

* 22.15 — a TLS finding not reproduced by Nmap can still be CONFIRMED from
  OpenSSL/TestSSL evidence. This is a *decision* behaviour (evidence from a
  primary tool outweighs Nmap's supporting evidence) and lands in v0.6.

Implemented elsewhere:
* import/reconciliation/safety (1-12, 22, 23, 30-32): test_import_lossless.py,
  test_reconciliation.py, test_security_safety.py, test_legacy_failure_modes.py
* classification/planning (13, 14, 16, 17, 24): test_classification.py,
  test_planning.py
* safe execution (18-21, 25-29): test_execution.py
"""

from __future__ import annotations

import pytest

_V06 = "implemented in v0.6 (review & evidence workflow)"


@pytest.mark.skip(reason=_V06)
def test_tls_not_reproduced_by_nmap_can_be_confirmed_by_openssl() -> None:  # task 22.15
    ...
