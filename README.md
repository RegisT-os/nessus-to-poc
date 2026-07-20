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

**v1.0 — Production ready** (see [`docs/ROADMAP.md`](docs/ROADMAP.md)). The full
near-term workflow is implemented and tested (115 tests; all 32 mandatory
regression tests from the brief pass; `ruff` + `mypy --strict` clean):

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

The long-term horizon (v2.0 → v10.0) is mapped in `docs/ROADMAP.md`.

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

# Repository safety (run before every commit)
vapt-verify security scan --root .

# Environment / tool capability check
vapt-verify doctor
```

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
