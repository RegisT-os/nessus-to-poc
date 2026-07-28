# VAPT Verification Orchestrator

*(working name; CLI: `vapt-verify`)*

A local-first, multi-engagement **vulnerability verification and evidence
orchestration** platform. It replaces an ad-hoc Nessus→Nmap command generator
that silently dropped findings. Its founding rule:

> **No finding disappears without an explicit, reviewable disposition.**

Every imported Nessus finding is normalized, kept with full provenance, and
reconciled against the source so you can always answer *"did any finding
disappear?"* with a definitive **no**.

## Status

**v2.0 — Multi-scanner correlation** (see [`docs/ROADMAP.md`](docs/ROADMAP.md)).
152 tests; all 32 mandatory regression tests from the brief pass; `ruff` +
`mypy --strict` clean.

New in v2.2 — **evidence sanitization & integrity**:

- `poc export` now **redacts by default** (SNMP communities, CLI passwords,
  private keys, bearer/JWT tokens, basic-auth URLs, cookies, AWS keys, NTLM
  hashes). Crucially, redaction is a **presentation-layer transform**: stored
  evidence files keep their original bytes, so a redacted client deliverable and
  an intact, hash-verifiable capture coexist. Every document states whether
  redaction was applied and how many items were masked; `--no-redact` opts out
  and says so in the output.
- `evidence verify` re-hashes every stored capture against its recorded SHA-256
  and **fails closed** on modification or loss — a chain-of-custody check for
  report time, handover, or after a restore.

New in v2.1 — **`poc export`**: the Nessus→PoC deliverable. One report-ready
document per finding pairing the original scanner claim (traceable to its source
file + hash), the exact command executed, the captured output, parsed
observations, the reviewer's verdict and rationale, the evidence SHA-256, and
the limitations of the method used. Two guardrails are enforced in the output: a
finding with **no evidence exports as an evidence request, never a proof**, and a
capture with **no verdict is labelled "CAPTURED, NOT REVIEWED"** rather than
reading as a confirmation.

New in v2.0:

- **Cross-scanner correlation** (`correlate`) — links findings that describe the
  same condition across Nessus/Nmap/CSV/other sources, with a confidence and a
  written rationale per group. It **never merges or removes** anything: groups
  reference finding ids, and `grouped + singletons` always equals the total.
- **Asset identity candidates** (`identities`) — asset records linked by
  MAC/IP/FQDN for reviewer confirmation; a shared IP is never treated as proof
  of a shared asset.
- **Import-set diff** (`diff`) — still / newly / no-longer reported and severity
  changes, matched correlation-aware so it works across scanners. "No longer
  reported" is a **state**, never a deletion, and never an automatic
  false-positive or remediation claim.

Windows users: see **[`docs/WINDOWS.md`](docs/WINDOWS.md)** — v1.1 fixed three
install/console defects that made imports fail there.

Already delivered (v0.1 → v1.0):

- Lossless multi-scanner import (Nessus XML/CSV, Nmap XML, normalized JSON) with
  a fail-closed reconciliation gate.
- Explainable classification into verification families + declarative recipe
  library (with legacy `VULNERABILITIES` migration) and per-finding plans.
- Safe execution: dry-run by default, scope-enforced, argv arrays (no shell),
  timestamped + hashed evidence; exit codes never set verdicts.
- Review/decision workflow with role-gated false-positive approval.
- Coverage-first reporting (Markdown/JSON/CSV/HTML), engagement profiles with
  environment mapping, retest, backup/restore with integrity manifest, and
  schema versioning.

The long-term horizon (v3.0 → v10.0) is mapped in `docs/ROADMAP.md`.

## Why (the legacy lesson)

The previous script only generated Nmap commands for plugin names matching a
hard-coded list, discarded port-`0` findings, ignored transport, and collapsed
findings by name→host→ports. Findings were missed. Full analysis:
[`docs/LEGACY_FAILURE_ANALYSIS.md`](docs/LEGACY_FAILURE_ANALYSIS.md). The
original script is preserved (as a reconstruction) at
[`legacy/nmap_legacy.py`](legacy/nmap_legacy.py) and covered by contrast tests.

## Install (development)

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

## Quickstart

```bash
# Create an engagement workspace
vapt-verify engagement create --id demo1 --client-alias ExampleBank --type internal

# Import a Nessus file (fails closed if findings can't be accounted for)
vapt-verify import --engagement demo1 tests/fixtures/sample_small.nessus

# Reconciliation status and inventory
vapt-verify import status --engagement demo1
vapt-verify inventory assets   --engagement demo1
vapt-verify inventory services --engagement demo1
vapt-verify findings list      --engagement demo1
vapt-verify findings show <finding-id> --engagement demo1

# Export report-ready PoC documents (scanner claim -> command -> capture ->
# verdict -> evidence hash -> method limitations)
vapt-verify poc export --engagement demo1 --finding <finding-id> --print
vapt-verify poc export --engagement demo1 --format all

# Correlate across scanners, inspect asset identities, diff two imports
vapt-verify correlate  --engagement demo1 --show
vapt-verify identities --engagement demo1
vapt-verify diff       --engagement demo1

# Repository safety (run before every commit)
vapt-verify security scan --root .

# Environment / tool capability check (run this first if anything misbehaves)
vapt-verify doctor
```

On Windows use `.\.venv\Scripts\vapt-verify.exe ...`, or
`python -m vapt_verify ...` if `Scripts\` is not on `PATH`. See
[`docs/WINDOWS.md`](docs/WINDOWS.md).

Engagement data is written under `engagements/<id>/` (git-ignored):
immutable original imports, `normalized/*.jsonl`, import manifests,
reconciliation records and an append-only audit log.

## Client data & profiles

The core engine is generic. Real client data lives only in **git-ignored**
`profiles/private/` and `engagements/`. A sanitized example profile using
RFC 5737 documentation IPs is at
[`profiles/examples/banking-enterprise/`](profiles/examples/banking-enterprise/).
See [`docs/ENGAGEMENT_PROFILES.md`](docs/ENGAGEMENT_PROFILES.md) and
[`docs/SECURITY.md`](docs/SECURITY.md).

## Development checks

```bash
.venv/bin/python -m pytest -q      # tests
.venv/bin/ruff check src tests     # lint
.venv/bin/mypy                     # types (strict)
```

## Documentation

- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) — verification principles, verdict taxonomy
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module layout & data flow
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — slice plan
- [`docs/LEGACY_FAILURE_ANALYSIS.md`](docs/LEGACY_FAILURE_ANALYSIS.md) — finding-loss mechanisms
- [`docs/SECURITY.md`](docs/SECURITY.md) — data handling & safe execution
- [`docs/ENGAGEMENT_PROFILES.md`](docs/ENGAGEMENT_PROFILES.md) — generic core vs. private profiles
