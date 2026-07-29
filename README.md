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
