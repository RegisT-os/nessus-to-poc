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

## Evidence sanitization (v2.2)

Captured tool output routinely contains material that must not reach a client
report: SNMP community strings, credentials on a command line, private keys,
bearer/JWT tokens, session cookies, basic-auth URLs, AWS keys, NTLM hashes.

`vapt-verify poc export` **redacts by default**. The critical property:

> Redaction is a **presentation-layer transform, never a mutation of evidence.**

The stored evidence file keeps its original bytes and its recorded SHA-256, so a
redacted deliverable and an intact, verifiable capture coexist. Every exported
document records its `sanitization_status` and how many items were masked;
`--no-redact` exports raw and the document states that redaction was not applied.

Engagement profiles can add patterns; a malformed custom pattern is skipped
rather than disabling redaction.

## Evidence integrity / chain of custody (v2.2)

`vapt-verify evidence verify` re-reads every stored capture and re-computes its
SHA-256 against the recorded digest, reporting `verified` / `modified` /
`missing` / `not_recorded`. It **fails closed** (exit 1) on modification or
loss, so a broken chain of custody cannot pass silently. Run it before report
handover and after any restore.

## Generated runbooks (v2.3)

`vapt-verify runbook` writes shell and PowerShell scripts that an operator runs
by hand. Generated scripts are a supply chain of their own, so:

- **Targets are validated before rendering.** A host field that is not a valid
  IP address or hostname produces **no command**; it becomes a manual task with
  the reason attached. This is the same rule `ScopeEnforcer` applies before
  execution (`security/scope.py: is_valid_target`).
- **Every argument is literal-quoted** (`sh_quote` / `ps_quote`) and round-trip
  tested against the real shell parser. A scanner-supplied string is data inside
  a quoted argument and cannot become a second command.
- **Scope labels, never suppresses.** A target outside the engagement's approved
  scope is emitted **commented out** with the reason. An engagement with no
  scope configured is stated as unconfirmed on every command and in the header —
  the tool never claims an authorisation it cannot verify.
- **No `set -e`, no `shell=True` equivalent.** A non-zero exit from a probe is
  ordinary output, not a failure to abort on and not a verdict.
- Generated scripts contain only what the declarative recipes describe: no
  password or community-string guessing, no destructive HTTP methods, no
  exploitation.

`vapt-verify evidence import` copies each captured file into the workspace
unmodified and hashes the stored copy, so an operator-run capture carries the
same chain of custody as one `run` produced. Re-import is idempotent by digest.
A step whose tool was missing on the operator's machine is recorded as a
**capability gap**, never as evidence that the condition is absent, and no
import path sets a verdict.

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
