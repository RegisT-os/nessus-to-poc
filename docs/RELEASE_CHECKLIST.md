# Release Checklist

Run before tagging a release.

## Quality gates

- [ ] `pytest` — full suite green (all 32 mandatory regression tests pass).
- [ ] `ruff check src tests` — clean.
- [ ] `mypy` — clean under `--strict`.
- [ ] `vapt-verify security scan --root .` — no violations.

## Invariant checks

- [ ] Import a synthetic fixture; confirm `coverage` totals back to imported
      (accounted / imported = 100%).
- [ ] Confirm no finding-loss path: reconciliation fails closed on imbalance.
- [ ] Confirm dry-run is the execution default and scope is enforced.
- [ ] Confirm exit codes never set verdicts and terminal verdicts need a reviewer.

## Data safety

- [ ] No real `.nessus` files tracked (only `tests/fixtures/**`).
- [ ] `profiles/private/` and `engagements/` are git-ignored and empty of client data.
- [ ] Example profiles use RFC 5737 documentation ranges only.
- [ ] No secrets, tokens, or internal hostnames in the diff.

## Schema & compatibility

- [ ] `SCHEMA_VERSION` bumped if the normalized format changed, with a migration
      registered in `schema.py`.
- [ ] Backup/restore round trip verifies integrity (`backup` then `restore`).

## Packaging & docs

- [ ] `__version__` (src/vapt_verify/__init__.py) and `pyproject.toml` version match.
- [ ] README status and `docs/ROADMAP.md` updated.
- [ ] `docs/THREAT_MODEL.md` reviewed for any new attack surface.
- [ ] Sample engagement walkthrough (`examples/SAMPLE_ENGAGEMENT.md`) still accurate.

## Release

- [ ] Tag the release; attach the changelog.
- [ ] Confirm the definition of success (docs README §Definition of Success): a
      tester can answer every question, and "did any finding disappear?" is
      always **No — not without an explicit, reviewable disposition.**
