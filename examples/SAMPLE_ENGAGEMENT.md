# Sample Engagement Walkthrough

An end-to-end run using the sanitized example profile and synthetic fixture. All
data is fictional (RFC 5737 ranges). Assumes `pip install -e ".[dev]"`.

```bash
# 1. Create an engagement from the sanitized example profile
vapt-verify profile apply profiles/examples/banking-enterprise --id demo

# 2. Import a Nessus scan (fails closed if anything is unaccounted for)
vapt-verify import --engagement demo tests/fixtures/sample_small.nessus
vapt-verify import status --engagement demo

# 3. Assign environments from the profile's rules (critical envs need IP/explicit confirmation)
vapt-verify environments assign --engagement demo

# 4. Classify every finding (assigns an explicit disposition to each)
vapt-verify classify --engagement demo
vapt-verify coverage  --engagement demo        # accounted / imported = 100%

# 5. Explain and plan a specific finding
vapt-verify findings list --engagement demo
vapt-verify explain  --engagement demo <finding-id>
vapt-verify plan     --engagement demo --finding <finding-id>

# 6. Dry-run a verification (nothing executes without --approve and in-scope target)
vapt-verify run --engagement demo --finding <finding-id>          # dry-run
# vapt-verify run --engagement demo --finding <finding-id> --approve --operator you

# 7. Request evidence for a credentialed/local-check finding
vapt-verify evidence request --engagement demo <finding-id>

# 8. Record a reviewer decision (terminal verdicts require a rationale)
vapt-verify review --engagement demo <finding-id> \
    --verdict confirmed --reviewer you --rationale "OpenSSL presented the cert"

# 9. Reports (coverage-first) and a self-contained HTML dashboard
vapt-verify report --engagement demo --format all

# 9b. Report-ready PoC documents: scanner claim -> command -> captured output
#     -> verdict -> reviewer rationale -> evidence hash -> method limitations.
#     Findings with no evidence export as evidence REQUESTS, never as proofs.
vapt-verify poc export --engagement demo --finding <finding-id> --print
vapt-verify poc export --engagement demo --format all          # every finding
vapt-verify poc export --engagement demo --with-evidence-only  # captures only

# 10. Back up the engagement (integrity manifest embedded) and verify schema
vapt-verify backup --engagement demo
vapt-verify schema --engagement demo

# 11. Repo safety before committing anything
vapt-verify security scan --root .
```

Every step preserves the founding invariant: no finding disappears without an
explicit, reviewable disposition.
