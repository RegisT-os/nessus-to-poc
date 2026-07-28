# Architecture

Local-first, CLI-first, modular Python. No cloud, no daemon, no heavyweight
infrastructure. Real client data lives only in git-ignored private profiles and
git-ignored engagement workspaces.

## Package layout

The target layout (task section 8) is built out slice by slice. Modules marked
*(vN)* are planned for a later slice and are tracked in [`ROADMAP.md`](ROADMAP.md).

```
src/vapt_verify/
├── __init__.py              # version, top-level invariant docstring
├── cli/main.py              # argparse dispatcher (vapt-verify ...)
├── importers/
│   ├── base.py              # ImportResult, ParseFailure
│   ├── nessus_xml.py        # safe, streaming, lossless Nessus importer
│   ├── nessus_csv.py        # (v0.8)
│   └── tenable_sc_csv.py    # (v0.8)
├── models/
│   ├── enums.py             # Severity, Transport, Disposition, Verdict, ObservationSource
│   ├── engagement.py        # Engagement (authorisation + scope context)
│   ├── asset.py             # Asset (identity-confidence aware)
│   ├── service.py           # ServiceObservation (scanner-referenced vs observed-open)
│   ├── finding.py           # Finding + SourceProvenance (lossless)
│   ├── recipe.py            # (v0.2) declarative verification recipes
│   ├── evidence.py          # (v0.3)
│   └── decision.py          # (v0.6)
├── reconciliation/
│   ├── stats.py             # import statistics (section 14)
│   └── gate.py              # fail-closed accounting gate
├── correlation/             # (v2.0) cross-scanner links, asset identities, diff
│   ├── models.py            #   CorrelationGroup / AssetIdentityGroup / report
│   ├── engine.py            #   layered link bases, strongest signal first
│   └── diff.py              #   import-set diff ("no longer reported" is a state)
├── classification/          # (v0.2) explainable recipe selection
├── recipes/                 # (v0.2) versioned, declarative recipe library
├── planning/                # (v0.2) per-finding / per-asset verification plans
├── adapters/                # (v0.3+) nmap, tcp, openssl, http, manual, ...
├── execution/               # (v0.3) dry-run-by-default runner, scope enforcement
├── evidence/                # (v0.3) hashed, timestamped evidence manifests
├── review/                  # (v0.6) reviewer workflow, false-positive approval
├── reporting/               # (v0.7) markdown/json/csv/coverage
├── security/client_data_check.py   # repository safety checker
├── utilities/               # hashing, stable ids/fingerprints, jsonl
└── workspace.py             # engagement workspace / evidence-bundle layout
```

Top-level (repo) directories: `recipes/`, `profiles/` (with `examples/` and
git-ignored `private/`), `examples/`, `tests/`, `fixtures/`, `docs/`, `legacy/`.

## Data flow (v0.1)

```
.nessus file
   │  NessusImporter.import_file()  (defusedxml iterparse; streaming)
   ▼
ImportResult { assets, services, findings, parse_failures, source counts }
   │  reconcile()  → ReconciliationReport (fail closed if imbalanced)
   ▼
EngagementWorkspace.persist_import()
   ├── imports/originals/<ts>_<hash>_<name>.nessus   (immutable copy, hashed)
   ├── imports/manifests/<import_id>.json            (counts, tool versions, stats)
   ├── normalized/{assets,services,findings}.jsonl   (append: repeated scans stay distinct)
   ├── reconciliation/<import_id>.json               (accounting record)
   └── audit/import_audit.jsonl                       (append-only audit)
```

## Key modelling decisions

- **Losslessness first.** Every `ReportItem` becomes one `Finding` or one
  explicit `ParseFailure`. `Finding.raw` holds every source attribute and child
  element verbatim, so no scanner field is ever silently dropped — even fields
  this version does not model. `reconciliation/stats.py` lists the unmodelled
  element tags for transparency.
- **Identity is preserved.** A finding's id is derived from source file hash +
  host + per-host occurrence index + a content fingerprint. The fingerprint
  spans plugin id, host, port, transport, service, virtual host, the CVE set and
  a digest of the plugin output — deliberately **more** than `name + IP + port`
  (task 9.4). Findings sharing a fingerprint are linked as *duplicate
  candidates*, never merged.
- **Scanner-referenced ≠ observed-open.** A `ServiceObservation` records *how*
  it was seen via `ObservationSource`. Import produces only
  `SCANNER_REFERENCED` observations; "observed open" requires a verification
  check (v0.3).
- **Transport is separate from port.** Port `0` ⇒ host-level ⇒ `Transport.NONE`
  (the raw protocol attribute is still preserved in `raw`).
- **Fail closed.** The reconciliation gate makes `import` return non-zero when
  the accounting identity does not hold, or when explicit exceptions exist and
  have not been acknowledged.
- **Correlation is additive (v2.0).** Cross-scanner grouping produces a separate
  layer that *references* finding ids; it never mutates, merges or removes a
  finding. `grouped + singletons == total findings` is the correlation-side
  analogue of the import reconciliation gate, and is asserted by tests.
- **Recipes ship inside the package.** `recipes/data/*.yaml` is package data
  loaded via `importlib.resources`, so classification works in every install
  layout (a repo-relative path previously broke non-editable installs).

## Dependencies

Runtime: `defusedxml` (safe XML), `PyYAML` (config). Dev: `pytest`, `ruff`,
`mypy`. Models are plain dataclasses with explicit `to_dict`/`from_dict` — no
heavyweight ORM or schema engine. Python 3.12+, fully type-hinted, `mypy
--strict` clean.

## Security posture

XML is parsed with `defusedxml` (entity expansion + external entities
forbidden). Nothing is executed in v0.1. Original scan files are never modified.
See [`SECURITY.md`](SECURITY.md).
