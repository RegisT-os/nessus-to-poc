# Security & Data-Handling

This tool processes vulnerability data and, in later slices, actively probes
authorised targets. Safety is a first-class design constraint.

## Client-data protection (enforced now)

Real client data must never enter the public repository. Enforced by:

- **`.gitignore`** excludes `profiles/private/`, real `*.nessus` exports
  (except `tests/fixtures/**`), `engagements/`, credentials and secrets.
- **Client-data safety checker** (`vapt-verify security scan`, module
  `security/client_data_check.py`) flags:
  - files tracked under `profiles/private/` (must stay local);
  - scanner exports committed outside `tests/fixtures/`;
  - non-documentation IP addresses in sanitized areas (`profiles/examples/`,
    `tests/fixtures/`, `docs/`, `examples/`) — only RFC 5737 / RFC 3849
    documentation ranges and loopback are allowed;
  - a missing `profiles/private/` rule in `.gitignore`.
- **Tests** (`tests/test_security_safety.py`) assert the committed repository is
  clean and that the checker catches each violation class.

Run it before every commit:

```
vapt-verify security scan --root .
```

## Safe XML parsing (enforced now)

Nessus XML is parsed with **`defusedxml`** using `iterparse`, which forbids DTDs,
entity expansion and external entity resolution. This blocks billion-laughs /
XXE / SSRF attacks from a hostile scan file. The standard-library parser (used
by the legacy script) is never used for untrusted input.

## Evidence integrity (enforced now, extended later)

- Original imported files are **never modified** — they are copied into
  `imports/originals/` and hashed (SHA-256).
- Import manifests record tool versions, timestamps and counts.
- An append-only `audit/import_audit.jsonl` records every import.
- v0.3+ evidence adds per-evidence SHA-256 hashes, sanitization status and
  immutable execution audit.

## Credentials

- Engagement config stores **credential references only** (e.g.
  `vault://...`), never plaintext passwords.
- No secret is written to command history or logs.

## Safe execution (v0.3)

The execution layer will enforce: scope allow-list + explicit exclusions,
IP/CIDR/hostname validation, DNS-resolution recording, approval before
execution (dry-run is the default), per-host rate limits, per-adapter timeouts,
concurrency limits and testing-window awareness. Commands use `subprocess`
argument arrays — **never** `shell=True`. No automatic exploitation, brute
force, password spraying, denial of service, or destructive HTTP methods. A
public IP is never scanned unless explicitly present in the engagement scope.

## Reporting a concern

This is an internal tooling project. Raise data-handling or safety concerns with
the VAPT tooling lead before pushing changes that touch parsing, execution or
profile handling.
