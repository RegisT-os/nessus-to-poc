# Roadmap

Two horizons:

- **Near-term (v0.1 → v1.0)** — fine-grained *slices*. Each slice: inspect →
  implement only the necessary files → focused tests → full tests → lint →
  type-check → security check → review diff → commit.
- **Long-term (v2.0 → v10.0)** — *major-version* themes. Each is a coherent
  capability step, not a single slice; it expands into its own slice plan when
  it becomes the active horizon.

## Invariants that hold across every release

These never regress, at any version. New capabilities are rejected if they
would weaken any of them.

1. **No silent loss.** Every imported finding appears in the inventory with an
   explicit, reviewable disposition. Reconciliation fails closed.
2. **Provenance is permanent.** Original imports are immutable and hashed;
   evidence is timestamped and hash-chained; nothing is edited in place.
3. **Human owns the verdict.** Tool exit codes, model suggestions and automated
   evidence never assign a verdict. Only an authorised reviewer approves
   `FALSE_POSITIVE_APPROVED` / `RISK_ACCEPTED`.
4. **Coverage, not automation, is the metric.** Accounted-for / imported = 100%
   is the headline; automation rate is never the quality claim.
5. **Local-first, safe by default.** No cloud requirement; dry-run default;
   argument arrays (never `shell=True`); scope allow-lists; no target touched
   outside authorised scope.
6. **Client data stays private.** Real client data never enters the repository;
   `profiles/private/` and `engagements/` are git-ignored and enforced by the
   safety checker.

---

# Near-term slices (v0.1 → v1.0)

## v0.1 — Lossless Import Foundation ✅ (delivered)

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

---

# Long-term major versions (v2.0 → v10.0)

Each major version keeps every invariant above, remains local-first by default,
and expands into its own slice plan when work begins.

## v2.0 — Multi-Scanner Correlation & Source of Truth

*Theme: one defensible inventory across many scanners.*

- Production-parity importers for all v0.8 sources, each lossless and reconciled
  independently.
- Cross-scanner **correlation** of findings and assets *with provenance*: link
  candidates across scanners, never merge away identity or source.
- Unified but non-lossy finding taxonomy; a canonical view layered over — not
  replacing — each scanner's raw record.
- Asset reconciliation across sources with explicit identity-confidence.
- Import-set diffing (what a new scan added / changed / no longer reports),
  where "no longer reported" is a state, never a deletion.

Guardrail: correlation produces *links and candidate groups*, never silent
de-duplication. A merged view must always be decomposable back to sources.

## v3.0 — Verification Orchestration at Scale

*Theme: safe, repeatable verification pipelines.*

- Verification **playbooks**: ordered, conditional adapter pipelines per family.
- Concurrency scheduler with per-host / per-adapter safety governors, rate
  limits, testing-window enforcement and operator interrupt.
- Evidence **chaining** (one adapter's output conditions the next) with full
  lineage.
- Adapter **plugin SDK**: third-party adapters with a declared safety
  classification and capability contract; no arbitrary executable recipes.
- Deterministic re-run: a playbook + engagement state reproduces the same plan.

Guardrail: scale changes throughput, not judgement — no pipeline step may
assign a verdict, and every step is dry-run-previewable.

## v4.0 — Continuous Verification & Vulnerability Lifecycle

*Theme: from point-in-time to continuous assurance.*

- Time-series findings: track a finding across scans (open → verified →
  remediated → retested → closed → recurred) without erasing history.
- Drift & recurrence detection; SLA / due-date tracking; ageing analytics.
- Scheduled re-verification and retest campaigns.
- Ticketing systems (Jira / ServiceNow) integrated as **evidence and workflow
  state**, not as the source of truth.

Guardrail: a closed or remediated finding retains its full historical record; a
port closing on retest yields `SERVICE_NOT_CURRENTLY_OBSERVED`, never deletion.

## v5.0 — Team Governance, RBAC & Tamper-Evident Audit

*Theme: multi-operator engagements with defensible chain-of-custody.*

- Roles: operator / reviewer / engagement-lead / read-only, with least-privilege
  defaults.
- Review queues, four-eyes approval, and signed dispositions.
- Hash-linked (append-only) audit chain across import, execution, evidence and
  decision events.
- Concurrent-edit safety on shared evidence stores; conflict surfacing.

Guardrail: only reviewers approve false-positive / risk-accepted verdicts;
signatures and the audit chain make every disposition attributable and
verifiable.

## v6.0 — Reporting, Analytics & Compliance Mapping

*Theme: defensible reporting for technical and executive audiences.*

- Template-driven report engine (per client / per regulator), reusing the
  defensible-language rules from `METHODOLOGY.md`.
- Coverage-first dashboards and risk-scoring models (EPSS / CVSS / exploit
  status as inputs, not verdicts).
- Compliance mappings (e.g. PCI DSS, ISO 27001, NIST CSF, CIS, and banking
  regimes such as BNM RMiT / MAS TRM) as evidence overlays.
- Exportable, self-contained evidence packs with integrity manifests.

Guardrail: reports state what was confirmed, blocked, not reproduced or requires
other evidence — never "clean because a tool returned nothing".

## v7.0 — Integration Platform & API

*Theme: interoperate with the wider security ecosystem.*

- Stable, versioned API (REST/gRPC) and webhooks over the same core models.
- Connectors: Tenable.sc / Tenable.io / Nessus Manager, SIEM/SOAR, data
  warehouse export.
- CI/CD security-gate mode and SBOM ingestion.
- Threat-intel enrichment (CISA KEV, EPSS, vendor advisories) as *context*.

Guardrail: the API exposes provenance and disposition on every finding;
integrations may enrich and route, but may not mutate a verdict.

## v8.0 — Assisted Analysis (Explainable, Human-in-the-Loop)

*Theme: augment the reviewer; never replace the verdict.*

- Assisted classification, evidence summarization, recipe recommendation and
  false-positive-pattern surfacing — all as **suggestions** with cited evidence.
- Offline / local-capable inference option to preserve the local-first and
  data-privacy posture.
- Every suggestion is logged with its inputs and confidence and requires
  explicit reviewer confirmation to affect state.

Guardrail: no model output ever sets a disposition or verdict automatically;
suggestions are advisory, attributable and reversible.

## v9.0 — Enterprise Scale, Resilience & Chain-of-Custody

*Theme: durability at large scale.*

- Performance for very large engagements (millions of findings); streaming and
  indexed evidence stores.
- Optional high-availability server mode (still deployable fully on-prem).
- Encryption at rest, key management, and WORM / immutable evidence archival.
- Data retention, legal-hold and disaster-recovery policies; verified
  backup/restore of complete engagements.

Guardrail: archival and retention are additive to provenance — evidence
integrity and reconstructability are preserved end-to-end.

## v10.0 — Extensible Standard & Ecosystem

*Theme: a durable, certifiable verification standard.*

- Curated, **signed** recipe/adapter marketplace with a certification program.
- Long-term schema-stability guarantees with automated migration.
- Optional multi-tenant managed deployments; full i18n and accessibility.
- A published **conformance suite** that any deployment can run to prove the
  no-finding-loss invariant and audit integrity hold end-to-end.

Guardrail: the conformance suite is the contract — a build that cannot prove
"no finding disappeared without an explicit, reviewable disposition" is not a
conformant v10.0.
