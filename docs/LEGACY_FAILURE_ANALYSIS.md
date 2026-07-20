# Legacy Failure Analysis

This document records exactly how the legacy Nessus-to-Nmap script could omit
findings, and how the VAPT Verification Orchestrator prevents each failure. It
is the anchor for the regression tests in `tests/` — every failure mode below
has at least one test that pins the fix.

## Provenance of the legacy script

When this project was recovered, the repository contained **no commits and no
tracked files** — the original `nmap.py` was not present. A faithful
behavioural reconstruction, rebuilt from the documented description of the
original tool, is preserved at [`legacy/nmap_legacy.py`](../legacy/nmap_legacy.py)
and clearly marked as a reconstruction. It intentionally preserves every defect
below so the losses can be demonstrated and migrated, not guessed at.

> The legacy script is a useful *command generator*. It is **not** a complete
> finding inventory, a verification engine, or a source of truth. Operational
> reliance on it caused findings to be missed.

## Summary of the legacy workflow

1. Recursively search for `.nessus` files.
2. Parse the XML with the standard-library (unsafe) parser.
3. Match each report item's `pluginName` against a hard-coded list of
   case-sensitive substrings (`VULNERABILITIES`).
4. For matches, collect `vuln_name → host → {ports}`, but only when `port != "0"`.
5. Generate `nmap -sS ...` command strings and optionally run them with
   `shell=True`, saving output to overwritten text files.

## Finding-loss mechanisms

| # | Failure mode | Mechanism in `legacy/nmap_legacy.py` | How v0.1 fixes it | Test |
|---|---|---|---|---|
| 2.1 | **Hard-coded coverage** | Only plugin names containing a `VULNERABILITIES` substring are recorded; everything else is dropped. | Importer normalizes **every** `ReportItem` into a `Finding`, regardless of plugin. | `test_finding_absent_from_legacy_mapping_is_retained`, `test_new_importer_keeps_everything_legacy_drops` |
| 2.2 | **Port-zero discarded** | `if port != "0"` guards both the "open ports" set and the results dict, so host-level/patch/policy/local-check findings vanish. | Port `0` is a first-class, host-level value; `Transport.NONE`; retained as a finding. | `test_port_zero_findings_are_retained` |
| 2.3 | **Case-sensitive substring only** | `if vuln_name in plugin_name` — a lowercase or reworded plugin name never matches. | Import is name-agnostic; matching (later, for *recipes*) uses plugin id, family, output, CVEs, etc. | `test_case_variation_in_plugin_name_does_not_cause_loss` |
| 2.4 | **Findings collapsed** | Reduced to `name → host → {ports}`; multiple plugins/certs/vhosts/CVEs on one port merge and lose identity. | Each finding keeps a distinct id + content fingerprint; duplicates are *linked*, never merged. | `test_multiple_findings_on_one_host_and_port_stay_distinct`, `test_duplicate_candidates_are_linked_not_merged` |
| 2.5 | **Protocol ignored** | `protocol` is read then discarded; only the port is kept, so UDP becomes a TCP scan. | `Transport` is stored separately from the port and application protocol. | `test_udp_findings_retain_udp`, `test_transport_round_trips` |
| 2.6 | **"All open ports" unreliable** | Every non-zero report-item port is added to `all_open_ports` as if currently open. | Modelled as **scanner-referenced** service observations; only a verification check can mark a port "observed open". | `ObservationSource` enum; `test_port_zero_...` (no service for port 0) |
| 2.7 | **Nmap limitations unmodelled** | A failed script was treated as meaningful, ignoring firewalls, credentials, SNI, load balancers, remediation, etc. | Verdict taxonomy separates blocked/inconclusive/not-reproduced; no auto-false-positive (v0.3). | Verdict enum + `docs/METHODOLOGY.md` |
| 2.8 | **No reconciliation** | No comparison of source vs. imported vs. classified counts. | Fail-closed reconciliation gate: `source == normalized + failures + suppressions`. | `test_reconciliation.py` (all) |
| 2.9 | **No result interpretation** | Nmap exit `0` implied success/verification. | Tool status, evidence, disposition and verdict are separate concepts; exit code never sets a verdict. | `docs/METHODOLOGY.md`; enforced in v0.3 |
| 2.10 | **Unsafe execution** | `shell=True`, string commands, overwritten outputs, root-only SYN scans, no scope. | v0.1 executes nothing; the safe adapter layer (v0.3) uses argument arrays, scope allow-lists and timestamped evidence. | `tests/test_future_slices.py` (v0.3 placeholders) |

## The invariant that replaces the legacy behaviour

> Every imported source finding must appear in the normalized inventory and
> receive an explicit, reviewable verification disposition. No finding may
> disappear silently.

The reconciliation gate enforces the accounting identity on every import and
**fails closed** (non-zero exit) if it does not hold. See
[`METHODOLOGY.md`](METHODOLOGY.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md).
