# Roadmap

## How to read this document

Three horizons:

- **Delivered (v0.1 → v2.5)** — shipped, tested, merged. Recorded here so
  the history of *why* each capability exists is not lost.
- **Planned majors (v3.0 → v10.0)** — each is a coherent capability step, broken
  into numbered slices with deliverables, guardrails and acceptance criteria.
  Slices are sized to be independently reviewable and independently shippable.
- **Backlog** — known work that is real but not yet scheduled into a version.

Every slice follows the same discipline: inspect current state → implement only
the necessary files → focused tests → full suite → lint → type-check → security
check → review the diff → commit. A slice is not done until the full suite,
`ruff`, `mypy --strict` and `vapt-verify security scan` are all clean.

Each planned version below carries:

| Field | Meaning |
| --- | --- |
| **Theme** | The single sentence that justifies the version existing |
| **Depends on** | What must be true before the work can start |
| **Slices** | Independently shippable units of work |
| **Guardrails** | Rules the version must not violate — enforced by tests |
| **Acceptance** | The measurable condition for calling the version done |
| **Non-goals** | Explicitly out of scope, to stop scope creep |

---

## Invariants that hold across every release

These never regress, at any version. A capability that would weaken one is
rejected, not negotiated.

1. **No silent loss.** Every imported finding appears in the inventory with an
   explicit, reviewable disposition. Reconciliation fails closed.
2. **Provenance is permanent.** Original imports are immutable and hashed;
   evidence is timestamped and hashed; nothing is edited in place.
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
7. **Redaction is presentation-layer, never mutation.** *(added v2.2)* Masking
   sensitive content in a deliverable must never alter the stored evidence, so a
   redacted report and an intact, hash-verifiable capture always coexist.
8. **Installed behaviour is the real behaviour.** *(added v1.1)* Anything that
   works only from a source checkout is broken. Packaging is part of the
   product and is tested against a real non-editable install.

## Lessons that shaped this roadmap

Grounded in defects actually found in this codebase, not hypotheticals:

- **A repo-relative data path shipped nothing.** Recipes resolved via
  `__file__`-walking worked in development and were entirely absent on a normal
  `pip install`, so every classification crashed. → Invariant 8; every version
  that adds data files must ship them as package data and prove it.
- **Assumed tool output formats lie.** The OpenSSL adapter matched full-mode
  `CONNECTED(` while actually invoking `-brief`, which prints `CONNECTION
  ESTABLISHED` — so successful captures recorded themselves as failures. →
  Adapter parsers must be validated against real captured output (v3.4).
- **Non-ASCII in output is a portability bug.** Em dashes in CLI strings crashed
  legacy Windows consoles, including on `--help`. → CLI output stays ASCII;
  enforced by a test.
- **Secrets arrive in evidence by default.** SNMP communities and CLI passwords
  land in captures unprompted. → Redaction defaults on for deliverables (v2.2).

---

# Delivered

## v0.1 → v1.0 — Foundation ✅

| Version | Delivered |
| --- | --- |
| **v0.1** | Lossless Nessus XML import, full finding model with provenance, fail-closed reconciliation gate, JSONL inventory, engagement workspace, client-data safety checker, legacy reconstruction + failure analysis |
| **v0.2** | Explainable layered classification, declarative recipe library, legacy `VULNERABILITIES` migration, per-finding planning, coverage, `legacy export-nmap` |
| **v0.3** | Safe adapter framework, dry-run-default execution, scope enforcement, structured + hashed evidence |
| **v0.4** | Protocol adapters (testssl, sslscan, ssh-audit, dns, snmp, smb, ldap, database) |
| **v0.5** | Engagement profiles, environment mapping with critical-env safeguard, retest |
| **v0.6** | Review/decision workflow, role-gated false-positive approval, contradictory-evidence surfacing |
| **v0.7** | Markdown / JSON / CSV / self-contained HTML reporting |
| **v0.8** | Nessus CSV, Nmap XML, normalized-JSON importers via one shared normalizer |
| **v0.9** | Local HTML dashboard (the desktop-usability answer; no cloud) |
| **v1.0** | Schema versioning, backup/restore with integrity manifest, threat model, release checklist, sample engagement |

**Acceptance met:** 100% of source report items accounted for; all 32 mandatory
regression tests from the founding brief pass.

## v1.1 — Cross-Platform Correctness ✅

*Theme: the tool must work where the operator actually is.*

Three independently fatal Windows defects, each root-caused and fixed:
recipes not shipped as package data (crashed all classification on a normal
install); non-ASCII CLI output crashing cp1252/cp437 consoles; scan files with
BOM/UTF-16 encodings or HTML-masquerading-as-XML failing with opaque parser
errors. Plus friendly top-level errors (`--traceback`), Explorer "Copy as path"
handling, `python -m vapt_verify`, a diagnostic `doctor`, and `docs/WINDOWS.md`.

## v2.0 — Multi-Scanner Correlation ✅

*Theme: one defensible inventory across many scanners.*

Layered cross-scanner correlation (`correlate`), asset identity candidates
(`identities`), and correlation-aware import-set diffing (`diff`).

**Guardrails held:** correlation is additive and never mutates a record;
`grouped + singletons == total findings`; "no longer reported" is a state,
never a deletion.

## v2.1 — PoC Export ✅

*Theme: close the gap between an evidence file and a pasteable report section.*

One report-ready document per finding pairing scanner claim → exact command →
captured output → parsed observations → verdict + rationale → evidence hash →
method limitations. **No evidence exports as an evidence *request*, never a
proof; an unreviewed capture is labelled, never implied to be a confirmation.**

## v2.2 — Sanitization & Chain of Custody ✅

*Theme: what leaves the organisation must be safe, and what stays must be provable.*

Redaction of SNMP communities, CLI passwords, private keys, bearer/JWT tokens,
basic-auth URLs, cookies, AWS keys and NTLM hashes — on by default for
deliverables, presentation-layer only. `evidence verify` re-hashes stored
captures and fails closed on modification or loss.

## v2.3 — Manual Capture Runbooks ✅

*Theme: the operator runs the commands; the platform generates them and takes
the results back.*

v2.1 assembled a PoC document from evidence that already existed. v2.3 supplies
the other half: `runbook` turns every finding into the concrete commands to run
by hand (bash for Kali, PowerShell for Windows, a Markdown checklist, a JSON
manifest), and `evidence import` reads the captured output back, parses it with
the adapter that generated the command, hashes it, and attaches it.

Design decisions worth keeping:

- **Generation is not execution.** `run` blocks an out-of-scope target *before*
  building a command, which is right for execution and wrong for planning — an
  engagement with no scope configured produced nothing at all. The runbook
  generates regardless and **labels** scope per command; unauthorised commands
  are emitted commented out with their reason, never deleted.
- **Commands come from the adapters.** A conformance test asserts every runbook
  argv equals what `Adapter.build_argv` produces, so the command an operator
  runs and the command `run` would execute cannot drift.
- **Coverage is fail-closed.** Every finding yields a command or an explicit
  manual evidence task; the command exits 1 and names anything unaccounted for.
- **A missing tool is a capability gap.** The scripts skip a step whose tool is
  absent and write a `.skipped` marker; the import reports it as a gap, never as
  evidence the condition is absent.
- **A mangled target yields no command.** A host field that is not a valid IP or
  hostname becomes a manual task; shell quoting is the second line of defence,
  not the only one.

## v2.4 - Finding Selection

*Theme: an operator chooses what to verify; the tool records the choice and
never lets it look like a deletion.*

`select` picks which findings become capture scripts -- interactively, or by
severity / host / plugin / service / port / free text / explicit id, with
`--add` and `--remove` to refine. `runbook`, `kit build` and `prepare` honour
the saved selection automatically; `--all-findings` overrides it.

The guardrail that makes this safe to have at all: a selection is a **scoping
decision, not a deletion**. Deselected findings stay in the inventory, acquire
no disposition, and are never a false positive. `coverage` reports against
every imported finding and names the selection separately; every generated
artefact states how many findings it left out and that they still require a
disposition. Criteria are OR'd, because operators think additively.

## v2.5 — Playbooks & Classification Correctness ✅

*Theme: order the evidence gathering, and stop routing ordinary findings to the
wrong recipe.*

Delivers roadmap slice **v3.1 (Playbooks)** ahead of the rest of v3.0, plus a
classification defect found while building it.

**The defect.** `vmware-hypervisor-advisory` lists plugin families `Misc.` and
`General` alongside its VMware/ESXi name indicators. Family alone qualified a
recipe, and because that recipe sits at selection layer 2 it beat every
layer-3/4 recipe — so *every* finding in those two buckets was routed to manual
hypervisor evidence. "General" and "Misc." carry a large share of a real Nessus
scan, so an ordinary HTTP finding was being handed an administrative VMware
evidence request instead of an HTTP check.

The fix has two parts, both generalisations of a rule the classifier already
applied to `services`: catch-all families are never a signal for any recipe,
and a recipe that declares name/plugin/text signals may not qualify on family
alone. A genuine VMware advisory still selects via its name indicator, and a
genuine `Ubuntu Local Security Checks` family still selects the patch recipe.

---

# Planned

## v3.0 — Verification Orchestration at Scale

**Theme:** run many verifications safely, repeatably and unattended — without
any step ever acquiring the authority to decide a verdict.

**Depends on:** v0.3 adapters, v0.5 profiles (rate limits, testing windows).

### Slices

- **v3.1 — Playbooks.** ✅ **(delivered)** Declarative, ordered adapter
  pipelines per verification family, with conditional steps. Same
  no-executable-content rule as recipes: a condition is a structured record
  (`observation` / `operator` / `value` / `from_step`), never an expression
  string, so a YAML file cannot name a callable or reach anything beyond
  earlier steps' observations. Eleven total operators, every one of which
  returns a bool for any input — a condition can never raise mid-run and
  orphan a half-written evidence file. An absent observation satisfies no
  value comparison, `not_equals` included: absence is unknown, not inequality.
  Validation is load-time and catches the failure mode playbooks invite — a
  condition that can never fire (typo'd observation, forward reference to a
  later step, conditional first step) is indistinguishable at run time from a
  step that legitimately does not apply. Adapters now declare
  `produces_observations` so that check has something to check against.
  New: `playbook list|show|validate`.
- **v3.2 — Scheduler & safety governors.** Bounded concurrency with per-host,
  per-adapter and per-engagement limits; token-bucket rate limiting; testing-
  window enforcement; graceful operator interrupt that never leaves a half-
  written evidence file. New: `run --plan <playbook> --max-concurrency N`.
- **v3.3 — Evidence chaining & lineage.** One step's parsed observations
  condition the next; each evidence record stores its parent, so a chain is
  reconstructable end to end. Extends `poc export` to render a chain.
- **v3.4 — Adapter conformance suite.** ✅ **(delivered)** Golden-output
  fixtures with explicit provenance (`REAL_CAPTURE` vs `AUTHORED`); every
  adapter parser is tested against them, every parser's verdict entitlement is
  asserted, and each fixture's captured invocation is pinned to what the
  adapter's `build_argv` produces today — so a flag change that would leave the
  parser reading a format the adapter never requests fails immediately. Real
  captures for openssl (brief, full, refused) and curl; authored fixtures are
  labelled in-file and auto-upgraded to a hard failure once the tool is
  installed locally. Directly prevents the OpenSSL `-brief` class of bug.
- **v3.5 — Adapter plugin SDK.** Third-party adapters declaring capability,
  safety class and parser contract; loaded from an allow-listed directory.
  Plugins declare, they do not execute arbitrary recipe content.
- **v3.6 — Deterministic re-run.** A playbook plus engagement state reproduces
  an identical *plan* (evidence naturally differs); `run --explain-plan` shows
  what would execute and why.

**Guardrails:** every step is dry-run-previewable; no pipeline step may assign a
verdict; a governor breach aborts the run rather than proceeding; concurrency
never bypasses scope validation; an interrupt leaves the evidence store
consistent.

**Acceptance:** a 500-finding engagement executes a multi-step playbook within
declared rate limits, produces a complete evidence chain per finding, and
`coverage` still totals back to imported findings.

**Non-goals:** distributed execution; any form of exploitation or brute force.

## v4.0 — Continuous Verification & Vulnerability Lifecycle

**Theme:** move from point-in-time assessment to continuous assurance, without
ever erasing history.

**Depends on:** v2.0 correlation (to track a finding across scans), v3.0
scheduling.

### Slices

- **v4.1 — Finding timeline.** A durable per-finding history: open → verified →
  remediated → retested → closed → recurred. Append-only; no state transition
  deletes a prior one. New: `timeline <finding-id>`.
- **v4.2 — Drift & recurrence detection.** Identify conditions that return after
  closure, and assets whose exposure changes between scans.
- **v4.3 — SLA & ageing.** Due dates from severity + engagement policy; ageing
  buckets; overdue reporting. Policy lives in the profile, never in core.
- **v4.4 — Scheduled re-verification.** Recurring retest campaigns over a saved
  scope, honouring v3.2 governors and testing windows.
- **v4.5 — Ticketing bridges.** Jira / ServiceNow as **evidence and workflow
  state**, never the source of truth; two-way link with conflict surfacing.

**Guardrails:** a closed or remediated finding retains its full record; a port
closing on retest yields `SERVICE_NOT_CURRENTLY_OBSERVED`, never deletion and
never an automatic remediation claim; ticket state never overwrites a reviewer
verdict.

**Acceptance:** a finding tracked across five scans exposes a complete,
gap-free timeline, and recurrence after closure is detected and surfaced.

**Non-goals:** becoming a ticketing system; agent-based continuous scanning.

## v5.0 — Team Governance, RBAC & Tamper-Evident Audit

**Theme:** multi-operator engagements with defensible attribution.

**Depends on:** v0.6 review workflow, v2.2 integrity.

### Slices

- **v5.1 — Roles & least privilege.** operator / reviewer / engagement-lead /
  read-only, enforced at the command boundary.
- **v5.2 — Review queues & four-eyes.** Work assignment; high-severity or
  false-positive decisions require a second authorised reviewer.
- **v5.3 — Signed dispositions.** Cryptographic signing of decisions, so a
  verdict is attributable to a specific reviewer and detectably unaltered.
- **v5.4 — Hash-linked audit chain.** Each audit entry commits to its
  predecessor's digest, making silent history edits detectable. New:
  `audit verify`.
- **v5.5 — Concurrent-edit safety.** Optimistic concurrency on shared evidence
  stores; conflicts surfaced for resolution, never silently last-write-wins.

**Guardrails:** only reviewers approve false-positive / risk-accepted verdicts;
the audit chain is append-only and verifiable; no role can delete evidence.

**Acceptance:** a tampered audit entry is detected by `audit verify`; a
false-positive approval by a non-reviewer is rejected with a clear reason.

**Non-goals:** SSO/directory integration (v7.0); a permissions UI.

## v6.0 — Reporting, Analytics & Compliance Mapping

**Theme:** reporting defensible to technical reviewers, executives and auditors
from one evidence base.

**Depends on:** v0.7 reporting, v2.1 PoC export, v4.1 timelines.

### Slices

- **v6.1 — Template engine.** Per-client / per-regulator report templates,
  reusing the defensible-language rules from `METHODOLOGY.md`.
- **v6.2 — Coverage-first dashboards.** Trend, ageing and disposition analytics
  — coverage always the headline, automation rate never presented as quality.
- **v6.3 — Risk-scoring inputs.** EPSS / CVSS / KEV / exploit availability as
  *inputs to a reviewer*, never auto-verdicts.
- **v6.4 — Compliance overlays.** PCI DSS, ISO 27001, NIST CSF, CIS, and banking
  regimes (BNM RMiT, MAS TRM) mapped as evidence overlays over findings.
- **v6.5 — Evidence packs.** Self-contained, integrity-manifested export bundles
  for handover or audit.

**Guardrails:** every generated statement traces to evidence or is labelled as
requiring review; prohibited phrasings from `METHODOLOGY.md` are rejected by a
lint test over templates; compliance mapping never changes a verdict.

**Acceptance:** a report generated from a sample engagement passes the
report-language lint, and every claim in it resolves to an evidence id.

**Non-goals:** being a GRC platform; automated compliance attestation.

## v7.0 — Integration Platform & API

**Theme:** interoperate with the wider security ecosystem without surrendering
the source of truth.

**Depends on:** v1.0 stable schemas, v5.1 roles.

### Slices

- **v7.1 — Versioned local API.** REST over the existing models, with the same
  RBAC; local-bound by default.
- **v7.2 — Webhooks & events.** Emit import/verification/decision events.
- **v7.3 — Scanner connectors.** Tenable.sc / Tenable.io / Nessus Manager pull,
  reusing the v0.8 normalizer.
- **v7.4 — SIEM / SOAR & warehouse export.** Push findings and verdicts outward.
- **v7.5 — CI/CD gate mode.** Fail a pipeline on unaccounted or unreviewed
  high-severity findings; SBOM ingestion.
- **v7.6 — Threat-intel enrichment.** CISA KEV, EPSS, vendor advisories as
  context.

**Guardrails:** the API exposes provenance and disposition on every finding;
integrations may enrich and route but may **not** mutate a verdict; no network
listener is enabled by default.

**Acceptance:** a full engagement round-trips through the API without loss, and
an integration attempting to set a verdict is rejected.

**Non-goals:** hosted multi-tenant SaaS; inbound internet exposure.

## v8.0 — Assisted Analysis (Explainable, Human-in-the-Loop)

**Theme:** augment the reviewer's judgement; never substitute for it.

**Depends on:** v6.1 templates, v5.3 attribution.

### Slices

- **v8.1 — Assisted classification.** Suggest recipes/families for findings that
  currently reach only the manual fallback, always with cited evidence.
- **v8.2 — Evidence summarization.** Condense long captures into review-ready
  summaries, with the full capture one click away.
- **v8.3 — False-positive pattern surfacing.** Highlight historical patterns
  similar to the finding under review — as prior art, not as a conclusion.
- **v8.4 — Local/offline inference option.** Preserve the local-first posture
  and keep client data in-boundary.
- **v8.5 — Suggestion audit.** Every suggestion logged with inputs, model
  identity, version and confidence; explicit reviewer confirmation required to
  affect any state.

**Guardrails:** no model output ever sets a disposition or verdict; suggestions
are advisory, attributable and reversible; a suggestion is visually distinct
from an evidence-backed statement in every rendering; disabling assistance
entirely must leave the platform fully functional.

**Acceptance:** with assistance enabled, no state transition occurs without a
recorded human confirmation; with it disabled, the full suite still passes.

**Non-goals:** autonomous verdict assignment; sending client data to third-party
inference services by default.

## v9.0 — Enterprise Scale, Resilience & Long-Term Custody

**Theme:** durability at scale, over years.

**Depends on:** v3.2 scheduling, v5.4 audit chain.

### Slices

- **v9.1 — Large-engagement performance.** Millions of findings: streaming
  reconciliation, indexed evidence stores, bounded memory.
- **v9.2 — Optional HA server mode.** Still fully on-premises deployable.
- **v9.3 — Encryption at rest & key management.**
- **v9.4 — WORM archival.** Immutable long-term evidence storage.
- **v9.5 — Retention, legal hold & DR.** Verified backup/restore of complete
  engagements, with policy-driven retention.

**Guardrails:** archival and retention are additive to provenance; evidence
integrity and reconstructability survive every migration, restore and archive
transition; performance work never weakens the reconciliation gate.

**Acceptance:** a one-million-finding engagement imports, reconciles and reports
within documented resource bounds; a restored archive verifies byte-for-byte.

**Non-goals:** cloud-only features; proprietary storage formats.

## v10.0 — Extensible Standard & Ecosystem

**Theme:** a durable, certifiable verification standard rather than one tool.

**Depends on:** everything above; v3.5 plugin SDK; v1.0 schema stability.

### Slices

- **v10.1 — Conformance suite.** A published, runnable suite any deployment
  executes to prove the invariants hold end to end.
- **v10.2 — Signed recipe/adapter marketplace.** Curated, signature-verified
  distribution with a certification process.
- **v10.3 — Long-term schema guarantees.** Stability commitments plus automated
  forward migration.
- **v10.4 — Optional multi-tenant deployment.** For organisations that need it,
  never as a requirement.
- **v10.5 — i18n & accessibility.** Full localisation and accessible reporting.

**Guardrails:** the conformance suite is the contract — a build that cannot
prove *"no finding disappeared without an explicit, reviewable disposition"* is
not conformant, regardless of what else it offers.

**Acceptance:** an independent deployment passes the published conformance suite
unmodified.

**Non-goals:** vendor lock-in; closed extension formats.

---

# Backlog (real, not yet scheduled)

Work that is genuinely needed but has no version assigned. Listed so it is not
quietly forgotten.

| Item | Notes |
| --- | --- |
| OpenVAS/Greenbone, Qualys, Rapid7 importers | Reuse the v0.8 shared normalizer; importer work, not core work |
| Nuclei importer + safe template execution | Requires a template safety classification |
| Recipe coverage expansion | The built-in library covers common families; long-tail plugins still reach the manual fallback |
| Per-profile redaction patterns | `Redactor.from_profile` exists; profile wiring and docs do not |
| Evidence screenshot workflow | `evidence add` accepts files; no capture-and-annotate flow |
| Correlation tuning telemetry | Measure how often the weakest (title) basis is later rejected by reviewers |
| Structured manual-test checklists | v0.2 emits manual steps; application-security checklists could be richer |
| Windows verification-tool bundle | Documented in `WINDOWS.md`; could be scripted |

# Deliberate non-goals (all versions)

Recorded so they are not re-proposed:

- Automatic exploitation, brute force, password spraying, denial of service, or
  destructive HTTP methods.
- Cloud-hosted-by-default operation, or any design that requires sending client
  data off-premises.
- Automatic false-positive classification, or any path where a tool exit code,
  closed port or model output assigns a verdict.
- Silent de-duplication or merging of findings.
- A "coverage" metric based on automation rate.
