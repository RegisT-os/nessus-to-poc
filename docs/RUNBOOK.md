# Manual Capture Runbooks — Nessus to commands you run yourself

This is the answer to *"turn my Nessus findings into nmap/openssl commands I can
run by hand to capture the evidence."*

`vapt-verify runbook` reads the normalized inventory and emits, for **every**
finding, the concrete commands to run — as a bash script, a PowerShell script, a
Markdown checklist, and a JSON manifest. You run them wherever the targets are
actually reachable. `vapt-verify evidence import` reads the captured output back
in, parses it, hashes it, and attaches it to the right finding, so `review` and
`poc export` can finish the job.

```
import -> classify -> runbook -> [you run the commands] -> evidence import
                                                        -> review -> poc export
```

## Why this exists separately from `run`

`vapt-verify run` executes a verification itself. That is the right tool when
the machine running `vapt-verify` can reach the target and has the tools
installed. In practice it often cannot: the scan data is on a laptop, the
targets are reachable from a jump host, and the tooling lives on Kali.

`run` is also, correctly, **gated**: an out-of-scope target is blocked *before*
a command is built, so it returns a blocked status and no command at all. That
is right for execution and wrong for planning — an engagement whose scope has
not been filled in yet produced an empty result and nothing to work with.

Generating a command is not executing it. So the runbook:

- **generates for every finding**, whatever the scope state;
- **labels** each command's scope status instead of suppressing it;
- **comments out** anything the engagement has declared out of scope, with the
  reason attached, so the authorisation signal survives without hiding evidence
  of what was considered.

## Generate

```bash
vapt-verify runbook --engagement demo1
```

Options:

| Flag | Effect |
| --- | --- |
| `--finding <id>` / `--asset <id>` | limit to one finding or asset |
| `--severity HIGH,MEDIUM` | limit by severity label |
| `--format sh\|ps1\|md\|json\|all` | which outputs to write (default `all`; `json` is always written) |
| `--output <dir>` | output directory (default `engagements/<id>/runbooks/`) |
| `--capture-dir <dir>` | where the script writes captures (default `capture`) |
| `--timeout <seconds>` | per-step timeout recorded in the runbook |

The JSON manifest is always written even if you ask for another format alone —
a runbook you cannot re-import is only half a workflow.

Output summary tells you what you got:

```
Runbook for engagement 'demo1':
  findings covered:       6 of 6
  with runnable commands: 4
  manual-only findings:   1
  informational retained: 1 (listed, not scanned; --include-informational to probe)
  commands generated:     9 (9 runnable, 0 withheld)
  manual evidence tasks:  4
```

`findings covered` always equals the number of findings considered. If any
finding produced no command, no manual task and no explicit retain decision,
`runbook` **exits 1** and names it — the same fail-closed posture as the import
reconciliation gate.

## Informational findings

Informational findings report inventory and context, not a condition to
confirm, so **no scanning command is generated for them by default**. Probing
them spends your time at the client site on noise.

They are not dropped. They stay in the inventory, they are listed in the
generated script and checklist under "Retained, not scanned" with the reason,
and they still need a disposition at review time. Pass
`--include-informational` to generate commands for them anyway.

The same rule and flag apply to `kit build` and `prepare`. `poc export` still
documents them by default; `--skip-informational` omits them from the pack.

## File and directory names

Everything written to disk is named for a human, not for a hash:

```
capture/192.0.2.10/3-MEDIUM_443-tcp_SSL-Certificate-Cannot-Be-Trusted/01_openssl.txt
reports/poc/2-HIGH_192.0.2.10_host_Ubuntu-Security-Update-for-OpenSSL.md
kali-kit/scripts/3-MEDIUM_192.0.2.10_22-tcp_SSH-Weak-Algorithms-Supported__01_ssh_audit.sh
```

The leading number is a severity rank, so a plain directory listing sorts
worst-first — alphabetical severity names would file INFORMATIONAL between HIGH
and LOW. A host-level finding says `host` rather than `0-tcp`, which invites
being read as a real port. Names are stable across re-exports, so re-running an
export updates the same file instead of accumulating copies; when two findings
would collide the plugin id disambiguates them.

The finding id is still recorded *inside* every generated script and in the
manifest, which is what import matches on, so readable names cost no
traceability. `run-all.sh --finding` accepts either — a full finding id, or any
substring of the readable name (`--finding SSL-Self-Signed`).

## What a generated command looks like

Commands come from the adapters, not from a template. `nmap` script selection,
openssl SNI, snmpget's community handling — all of it is the recipe library's
decision, identical to what `run` would execute. A conformance test asserts the
two can never drift.

```bash
#   [IN SCOPE] Retrieve the presented certificate using SNI.
step 'find-37c3...-1' 'openssl' 'asset-f12d.../find-37c3.../01_openssl.txt' \
  'openssl' 's_client' '-connect' '192.0.2.10:443' \
  '-servername' 'web01.example-doc.test' '-brief'
```

Every argument is single-quoted. A scanner-supplied hostname is data inside a
quoted string and can never become a second command; on top of that, a target
that is not a valid IP or hostname produces **no command at all** and becomes a
manual task instead.

## Run it

```bash
# Kali / Linux
bash engagements/demo1/runbooks/runbook.sh

# Windows
powershell -File engagements\demo1\runbooks\runbook.ps1
```

Both scripts:

- check tool availability first and **skip** steps whose tool is missing,
  writing a `.skipped` marker rather than a fake result;
- write each step's output to its own file under the capture directory,
  wrapped with the step id, the exact command, timestamps and the exit code;
- **do not** abort on a non-zero exit — a closed port or a failed handshake is
  ordinary output, not a reason to stop, and not a verdict.

Environment overrides: `VAPT_CAPTURE_DIR`, `VAPT_STEP_TIMEOUT` (bash only;
Windows PowerShell has no portable `timeout` equivalent that preserves output
ordering, so interrupt a hung probe with Ctrl+C).

You can also just copy individual commands out of `runbook.md` and run them by
hand — save the output to the path the checklist names and the import still
finds it.

## Import the captures

```bash
vapt-verify evidence import --engagement demo1 \
  --manifest engagements/demo1/runbooks/runbook.json \
  --capture-dir ./capture --operator you
```

Each capture is parsed by the adapter that generated its command, copied into
the workspace, hashed with SHA-256, and recorded as evidence. The report
distinguishes:

| Status | Meaning |
| --- | --- |
| `imported` | parsed and attached |
| `already imported` | same digest already recorded — re-import is idempotent |
| `not captured yet` | you have not run this step |
| `tool skipped` | the tool was absent where the runbook ran — a **capability gap**, not evidence the condition is absent |
| `empty capture` | the file exists but is empty — re-run it or record why |

It then lists **findings that still have no evidence at all**, because an import
that quietly leaves findings bare is how evidence gaps hide.

Nothing here sets a verdict. Adapters may *suggest* one from the content of the
evidence; the exit code never does; a reviewer decides.

## Then finish the loop

```bash
vapt-verify review  --engagement demo1 <finding-id> --verdict confirmed --rationale "..."
vapt-verify evidence verify --engagement demo1     # chain of custody
vapt-verify poc export --engagement demo1 --format all
```

## Manual-only findings

Some findings cannot be verified by a remote probe and must not appear to be.
A missing-patch finding from a local check gets no port scan — it gets an
explicit credentialed/administrative evidence request with a path to save what
you collect. The runbook says so in the script, the checklist and the manifest.

## Safety properties

- Scope **labels**, never silently deletes. Out-of-scope commands are emitted
  commented out with their reason.
- An engagement with no configured scope is stated as such, loudly, on every
  command and in the script header — the tool does not claim authorisation it
  cannot verify.
- Argument arrays throughout; the shell quoter is a second line of defence
  behind target validation, not the only one.
- No password guessing, no community-string guessing, no destructive methods:
  the runbook can only emit what the declarative recipes describe.
- Captured files are copied, never modified; the stored copy's hash is what
  `evidence verify` re-checks.
