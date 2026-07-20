# Verification Methodology

This document defines the principles the platform enforces. They exist to stop
the class of error that made the legacy script unsafe: treating an automated
tool's output as a verdict.

## The non-negotiable invariant

> Every imported source finding must appear in the normalized inventory and
> receive an explicit, reviewable verification disposition.

An "unsupported" finding must remain **visible**. The answer to *"did any
finding disappear?"* must always be:

> No finding disappeared without an explicit, reviewable disposition.

## Four separate concepts

The legacy tool conflated these; the platform keeps them strictly separate.

1. **Tool execution status** — did the tool run? (exit code, timeout). This is
   *never* a verdict. `nmap` exit `0` means "nmap ran", nothing more.
2. **Evidence** — the structured, hashed, timestamped output a tool produced.
3. **Disposition** — the routing decision: what *kind* of validation this
   finding needs (automated / assisted / manual / credentialed / administrative
   / blocked / unsupported…). See `Disposition` in
   [`models/enums.py`](../src/vapt_verify/models/enums.py).
4. **Verdict** — the human/review conclusion. See `Verdict`.

## Disposition taxonomy

Every finding carries exactly one `Disposition`. v0.1 imports set
`PENDING_CLASSIFICATION` (an explicit, counted state); v0.2's classification
engine replaces it with a concrete value:

`AUTOMATED_VERIFICATION_AVAILABLE`, `ASSISTED_VERIFICATION_AVAILABLE`,
`MANUAL_VALIDATION_REQUIRED`, `CREDENTIALED_VALIDATION_REQUIRED`,
`ADMINISTRATIVE_EVIDENCE_REQUIRED`, `SCANNER_SPECIFIC_VALIDATION_REQUIRED`,
`ENVIRONMENT_BLOCKED`, `NETWORK_PATH_BLOCKED`, `AUTHENTICATION_UNAVAILABLE`,
`TOOL_CAPABILITY_UNAVAILABLE`, `UNSUPPORTED_BUT_RETAINED`,
`OUT_OF_AUTHORISED_SCOPE`, `DUPLICATE_CANDIDATE_RETAINED`,
`INFORMATIONAL_RETAINED`, `NO_ACTIVE_VALIDATION_APPROPRIATE`.

## Verdict taxonomy and transition rules

See `Verdict` in `models/enums.py` for the full list. Non-negotiable rules
(enforced from v0.6's review workflow; encoded in the enum now):

- `NOT_REPRODUCED` **must not** auto-become `FALSE_POSITIVE_CANDIDATE`.
- `SERVICE_NOT_CURRENTLY_OBSERVED` **must not** auto-become `POSSIBLY_REMEDIATED`
  without contextual evidence.
- `POSSIBLY_REMEDIATED` **must not** become `CONFIRMED_REMEDIATED` without review.
- Only an authorised reviewer may assign `FALSE_POSITIVE_APPROVED`.
- Tool exit code `0` **must never** directly determine a verdict.
- A port closed during retest **must not** erase the historical finding.
- Contradictory evidence is **surfaced**, never silently resolved.

## Nmap is not a vulnerability oracle

A failed or empty Nmap result can mean many things other than "false positive":
the service is temporarily down, a firewall or source-IP allow-list blocks the
validation host, SNI/DNS is required, a load balancer routes elsewhere, the
Nessus finding was a credentialed local check that no remote script reproduces,
the target was remediated after the scan, or Nmap simply cannot test the
condition. For each finding the platform records whether Nmap is **primary**,
**supporting**, **discovery-only**, or **inappropriate**.

## Defensible reporting language

Preferred:

- "The condition was confirmed using …"
- "The service was not observable from the validation source."
- "The original condition was not reproduced."
- "The validation method does not reproduce the scanner plugin's local-check logic."
- "Credentialed / administrative validation is required."
- "The environment blocked verification."
- "Evidence suggests remediation may have occurred after the original scan."
- "Insufficient evidence exists to classify the original finding as a false positive."
- "Contradictory evidence requires reviewer assessment."

Prohibited automatic statements:

- "Nmap found nothing, therefore false positive."
- "Port closed, therefore remediated."
- "Command returned zero, therefore confirmed."
- "Plugin not configured, therefore finding irrelevant."
- "No CVE, therefore no vulnerability."
- "Port zero, therefore ignore."

## Coverage, not automation, is the success metric

The primary metric is **accounted-for findings / imported findings = 100%**.
Automation percentage is explicitly *not* the headline quality metric — a high
automation rate that silently drops local-check findings is exactly the legacy
failure.
