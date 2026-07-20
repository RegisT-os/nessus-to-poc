# Roadmap

Delivered in safe, reviewable slices. Each slice: inspect → implement only the
necessary files → focused tests → full tests → lint → type-check → security
check → review diff → commit.

## v0.1 — Lossless Import Foundation ✅ (this slice)

- Python package + `pyproject.toml` (py3.12, ruff, mypy, pytest).
- CLI scaffold (`vapt-verify`): `version`, `doctor`, `init`, `engagement
  create/show`, `import`, `import status`, `inventory assets/services`,
  `findings list/show`, `security scan`.
- Safe, streaming Nessus XML importer (defusedxml).
- Full finding model with source provenance; port-zero and protocol preserved.
- Reconciliation gate (fail-closed) + import statistics.
- JSONL normalized exports + engagement workspace / evidence-bundle layout.
- Synthetic fixtures + regression tests for every legacy failure mode.
- Repository client-data safety checker + sanitized example profile.
- Legacy reconstruction preserved and covered by contrast tests.

**Acceptance:** 100% of synthetic source report items are accounted for.
`tests/test_reconciliation.py::test_coverage_totals_back_to_imported` and the
lossless-import suite pin this.

## v0.2 — Classification and Planning

Finding families, capability model, declarative recipe schema, migration of the
legacy `VULNERABILITIES` map into versioned recipes, manual fallback, `classify`
/ `explain` / `coverage` commands, per-finding verification plans, and
`legacy export-nmap` (with the "incomplete" warning).

## v0.3 — Safe Adapter Foundation

Adapters: nmap, tcp, openssl, http, manual, administrative-evidence,
credentialed-evidence. Dry-run-by-default execution, scope enforcement
(allow-list, CIDR/hostname validation), structured + hashed evidence. No
`shell=True`; argument arrays only.

## v0.4 — Protocol Expansion

testssl, sslscan, ssh-audit, dns, snmp, smb, rdp, smtp, ldap, database planning.

## v0.5 — MBSB Operational Profile

Private profile loader, environment mapping with careful precedence, retest
workflow, MBSB reporting mappings, scanner-source distinctions, sanitized
banking example. No real client data committed.

## v0.6 — Review and Evidence Workflow

Evidence attachment, decision workflow, contradictory-evidence handling,
reviewer approval, false-positive approval control, audit trail.

## v0.7 — Reporting

Markdown / JSON / CSV verification matrix, coverage dashboard, retest report,
evidence index.

## v0.8 — Additional Scanner Imports

OpenVAS/Greenbone, Qualys, Rapid7, Nuclei, Nmap XML, manual CSV — without
letting scanner-specific schemas contaminate the core finding model.

## v0.9 — Desktop Usability

Optional local-only desktop interface after the CLI is stable. No cloud hosting.

## v1.0 — Production Readiness

Stable schemas + migrations, full test suite, secure packaging, docs, sample
engagement, threat model, backup/restore, evidence integrity, release
checklist, no known finding-loss path.
