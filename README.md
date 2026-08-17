# Nessus to Manual PoC

Turn a Nessus scan into validation scripts that you can run manually from Kali.

The Windows machine prepares the scripts only. It does not scan the client. Kali
runs the checks onsite and captures the evidence. The captured evidence can then
be imported back into this tool for review and final PoC documents.

```text
Windows: .nessus -> Kali Bash kit
Kali:    run scripts -> captured evidence
Windows: import evidence -> final PoC documents
```

## 1. Install on Windows

Open PowerShell in this project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\vapt-verify.exe doctor
```

## 2. Convert Nessus into a Kali kit

This is the normal starting command:

```powershell
.\.venv\Scripts\vapt-verify.exe prepare `
  "C:\Scans\client-report.nessus" `
  --engagement client-2026 `
  --client-alias ClientName `
  --output "C:\Work\client-2026-kali-kit"
```

The generated directory contains:

```text
client-2026-kali-kit/
|-- README.md          Instructions for Kali
|-- commands.md        Human-readable finding and command list
|-- manifest.json      Finding-to-command mapping
|-- run-all.sh         Runs the scripts with confirmation prompts
|-- scripts/           Individual Bash validation scripts
|-- lib/capture.sh     Evidence-capture helper
`-- evidence/          Captured output is written here
```

Each Nessus finding remains visible. The tool generates Nmap NSE commands where
Nmap is appropriate and uses better tools where necessary, including OpenSSL,
testssl.sh, sslscan, ssh-audit, curl, snmpget, dig, smbclient and ldapsearch.

Findings that cannot be validated remotely, such as credentialed patch checks,
receive an exact manual evidence request instead of a misleading Nmap command.

## 3. Run at the client site from Kali

Copy the entire kit directory to Kali, then:

```bash
cd client-2026-kali-kit
chmod +x run-all.sh scripts/*.sh lib/capture.sh
less commands.md
./run-all.sh
```

The runner displays and asks permission before every command. To run only one
finding:

```bash
./run-all.sh --finding FINDING_ID
```

After you have reviewed the whole kit and confirmed scope, `./run-all.sh --yes`
runs without individual prompts.

Output and metadata are saved under `evidence/`. Keep the entire kit together
and do not modify captures after collection; their SHA-256 hashes are checked
during import.

## 4. Import the Kali evidence on Windows

Copy the returned kit back to Windows and run:

```powershell
.\.venv\Scripts\vapt-verify.exe kit import `
  "C:\Evidence\client-2026-kali-kit" `
  --engagement client-2026
```

The import verifies every capture hash, rejects unknown finding IDs, and skips
captures that were already imported.

## 5. Review and export final PoCs

List the finding IDs:

```powershell
.\.venv\Scripts\vapt-verify.exe findings list --engagement client-2026
```

Record a reviewer verdict after assessing the evidence:

```powershell
.\.venv\Scripts\vapt-verify.exe review FINDING_ID `
  --engagement client-2026 `
  --verdict confirmed `
  --reviewer YOUR_NAME `
  --rationale "Validated from the authorised Kali source."
```

Export the final evidence-backed PoC documents:

```powershell
.\.venv\Scripts\vapt-verify.exe poc export `
  --engagement client-2026 `
  --format all
```

## Rebuild a kit for an existing engagement

If the Nessus file was already imported:

```powershell
.\.venv\Scripts\vapt-verify.exe kit build `
  --engagement client-2026 `
  --output "C:\Work\client-2026-kali-kit"
```

Use `--force` to refresh generated scripts. Existing files under `evidence/`
are preserved.

## Pick which findings to convert

A 200-finding scan rarely needs 200 sets of capture scripts. `select` chooses
which findings get them, and `prepare`, `kit build` and `poc export` all
honour that choice automatically.

Interactive (the default — a numbered list you tick):

```powershell
.\.venv\Scripts\vapt-verify.exe select --engagement client-2026
```

```text
       #  SEVERITY      HOST             PORT       FINDING
  ----------------------------------------------------------------------------
  [ ]    1  HIGH          192.0.2.10       host       Ubuntu Security Update for OpenSSL
  [x]    2  MEDIUM        192.0.2.10       22/tcp     SSH Weak Algorithms Supported
  [x]    3  MEDIUM        192.0.2.10       443/tcp    SSL Certificate Cannot Be Trusted
  ----------------------------------------------------------------------------
  selected 2 of 6
  1-5,9 toggle | a all | n none | v invert | s HIGH | /text filter | p,< page | d done | q quit
```

Or by criteria, for scripting:

```powershell
vapt-verify select --engagement client-2026 --severity CRITICAL,HIGH
vapt-verify select --engagement client-2026 --host 192.0.2.10 --add
vapt-verify select --engagement client-2026 --search "SSL" --add
vapt-verify select --engagement client-2026 --severity LOW --remove
vapt-verify select --engagement client-2026 --show
vapt-verify select --engagement client-2026 --clear     # cover everything again
```

Criteria are **OR'd**, so "the criticals, plus everything on that one host" is a
single command rather than an empty result.

**Deselecting is scoping, not deleting.** A deselected finding stays in the
engagement, is not a false positive, and still needs a disposition. Every
generated kit and script states how many findings were left out, and
`vapt-verify coverage` still reports against every imported finding. Pass
`--all-findings` to `kit build` to ignore the selection once.

## Informational findings are not scanned

Informational findings report inventory and context, not a condition to
confirm, so no validation script is generated for them. They are **not
dropped**: they stay in the engagement, they are listed in `commands.md` under
"Retained, not scanned", and they still need a disposition at review time.

Add `--include-informational` to `prepare` or `kit build` to generate commands
for them anyway. `poc export --skip-informational` omits them
from the exported pack.

## File names

Generated files are named for a human, not for a hash:

```text
scripts/3-MEDIUM_192.0.2.10_443-tcp_SSL-Certificate-Cannot-Be-Trusted__01_openssl.sh
reports/poc/2-HIGH_192.0.2.10_host_Ubuntu-Security-Update-for-OpenSSL.md
```

The leading number is a severity rank, so a directory listing sorts worst-first.
A host-level finding says `host` rather than `0-tcp`. Names are stable across
re-exports, so re-running an export updates the same file rather than
accumulating copies.

The finding id is recorded inside every script and in `manifest.json` — which is
what import matches on — so readable names cost no traceability.
`./run-all.sh --finding` accepts a full finding id or any substring of the
readable name, e.g. `./run-all.sh --finding SSL-Self-Signed`.

## Important limits

- Generated checks are validation procedures, not automatic exploitation.
- A command exit code is not a vulnerability verdict.
- Nmap is supporting evidence for many findings and inappropriate for some.
- Port-zero/local-check findings usually require package, registry, credentialed,
  or administrator-supplied evidence.
- Review `commands.md` and confirm written authorisation before running anything.

## Technical reference

The normal operator workflow is fully covered above. These documents are only
needed when changing or auditing the platform itself:

- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) - verdict and evidence rules
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - internal modules and data flow
- [`docs/SECURITY.md`](docs/SECURITY.md) - client-data and execution safeguards
- [`docs/WINDOWS.md`](docs/WINDOWS.md) - Windows installation troubleshooting
- [`docs/ROADMAP.md`](docs/ROADMAP.md) - future development
