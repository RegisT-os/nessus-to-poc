# Threat Model

Scope: the VAPT Verification Orchestrator as a **local-first CLI** that parses
untrusted scanner output and, on explicit approval, executes verification tools
against authorised targets.

## Assets to protect

1. **Client data** — findings, IPs, hostnames, evidence. Highest sensitivity.
2. **Evidence integrity / chain-of-custody** — hashes, timestamps, audit log.
3. **The operator's host and network** — must not be harmed by a hostile input.
4. **Authorisation boundaries** — only in-scope targets may be touched.

## Trust boundaries

| Input | Trust | Mitigation |
|---|---|---|
| `.nessus` / `.xml` scan files | **Untrusted** | Parsed with `defusedxml` (DTD/entities/external refs forbidden) — blocks XXE / billion-laughs / SSRF. |
| CSV / JSON imports | Untrusted | Parsed with stdlib `csv` / `json`; values are data, never executed. |
| Scanner field values (hostnames, plugin output) | Untrusted | Never interpolated into a shell; command adapters build argv arrays. |
| Engagement/profile YAML | Semi-trusted (operator-authored) | `yaml.safe_load` only. |
| Backup archives | Untrusted | Path-traversal check on every entry; per-file hash verification on restore. |

## Threats & mitigations

- **Malicious scan file → code execution / SSRF.** `defusedxml`; no `eval`; no
  network calls during import.
- **Command injection via hostile hostname/port.** All execution uses
  `subprocess` argv arrays with `shell=False`; a hostile target is a single
  argv element. Scope validation additionally rejects anything that is not a
  valid IP or hostname. (Tests 22.27, 22.28.)
- **Out-of-scope scanning.** Default-deny scope enforcement; a public IP is
  never in scope unless an approved CIDR/target covers it; execution is dry-run
  by default and requires `--approve`. (Test 22.21.)
- **Silent finding loss.** Fail-closed reconciliation gate; every finding
  carries an explicit disposition. (Tests 1-12, 22, 32.)
- **False confidence from a tool.** Exit codes never set verdicts; timeouts are
  INCONCLUSIVE; only a reviewer assigns terminal verdicts; false-positive
  approval is role-gated. (Tests 19, 25, 26; review guardrails.)
- **Evidence tampering.** Originals are immutable and hashed; evidence files are
  uniquely named (never overwritten) and hashed; the audit log is append-only;
  backups embed a per-file hash manifest verified on restore. (Test 22.29.)
- **Client-data leak into the repo.** `.gitignore` + `security/client_data_check`
  + CI-style tests block real `.nessus`, private profiles and non-documentation
  IPs. (Tests 30, 31.)
- **Secret exposure.** Engagements store credential *references* only; no
  plaintext secrets, none written to logs or command history.

## Out of scope (by design)

No automatic exploitation, brute force, password spraying, denial of service, or
destructive HTTP methods. No cloud hosting. These are non-goals and must not be
added without a new threat-model review.

## Residual risks

- The operator can still authorise execution against a target they should not.
  Scope config and approval are controls, not guarantees; the audit log records
  who approved what.
- Verification tools themselves (nmap, openssl, …) are trusted binaries; the
  platform does not sandbox them beyond argv/scope/timeout controls.
