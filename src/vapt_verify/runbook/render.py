"""Render a runbook into the forms an operator actually uses.

Four outputs, one model:

``sh``    a bash script for Kali/Linux, where the tools live;
``ps1``   a PowerShell script for Windows;
``md``    a human checklist saying what to run and what to look for;
``json``  the manifest ``evidence import`` reads back.

Shell-safety rules, which the tests pin:

* Every argument is emitted through a **literal quoter** (:func:`sh_quote`,
  :func:`ps_quote`). A scanner-supplied hostname is data inside a quoted
  string; it can never become a second command.
* The builder has already refused to generate a command for a target that is
  not a valid IP or hostname, so the quoter is the second line of defence and
  not the only one.
* A command the engagement has not authorised is emitted **commented out**,
  with the reason. Nothing is hidden; nothing unauthorised runs by accident.
* The scripts never ``set -e``: a non-zero exit from nmap or openssl is
  ordinary and must not abort the run -- and, per the project's rules, is not a
  verdict either.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from vapt_verify.runbook.models import CommandStatus, Runbook, RunbookCommand, RunbookEntry

_STATUS_LABEL = {
    CommandStatus.READY: "IN SCOPE",
    CommandStatus.SCOPE_UNCONFIRMED: "SCOPE NOT CONFIGURED - CONFIRM AUTHORISATION",
    CommandStatus.OUT_OF_SCOPE: "OUT OF SCOPE - NOT AUTHORISED",
    CommandStatus.UNSAFE_TARGET: "NO USABLE TARGET",
    CommandStatus.NO_TARGET_PORT: "NO PORT (HOST-LEVEL FINDING)",
}


# ---------------------------------------------------------------------------
# quoting
# ---------------------------------------------------------------------------
def sh_quote(value: str) -> str:
    """POSIX-shell literal quoting.

    Always single-quoted, with embedded single quotes closed and re-opened.
    Inside single quotes the shell performs no expansion at all, so ``$(id)``,
    backticks and ``;`` are inert text.
    """
    return "'" + value.replace("'", "'\\''") + "'"


def ps_quote(value: str) -> str:
    """PowerShell single-quoted literal (no expansion; ``'`` doubles)."""
    return "'" + value.replace("'", "''") + "'"


def _sh_argv(argv: Iterable[str]) -> str:
    return " ".join(sh_quote(a) for a in argv)


def _ps_argv(argv: Iterable[str]) -> str:
    return "@(" + ", ".join(ps_quote(a) for a in argv) + ")"


# ---------------------------------------------------------------------------
# shared header text
# ---------------------------------------------------------------------------
def _header_lines(runbook: Runbook) -> list[str]:
    coverage = runbook.coverage()
    lines = [
        "vapt-verify manual verification runbook",
        f"engagement:    {runbook.engagement_id}"
        + (f" ({runbook.client_alias})" if runbook.client_alias else ""),
        f"authorisation: {runbook.authorisation_reference or '(not recorded)'}",
        f"generated:     {runbook.generated_at} by vapt-verify {runbook.tool_version}",
        f"findings:      {coverage.entries} "
        f"({coverage.with_runnable_command} with commands, "
        f"{coverage.manual_only} manual-only)",
        "",
        "SCOPE",
    ]
    lines += [f"  {s}" for s in runbook.scope_summary]
    lines += [
        "",
        "BEFORE YOU RUN ANYTHING",
        "  1. Confirm every target below is covered by your written authorisation.",
        "  2. Run from a network position that can actually reach the targets.",
        "  3. Output is written under the capture directory; do not edit those files.",
        "  4. Feed the results back with:",
        "       vapt-verify evidence import --engagement "
        f"{runbook.engagement_id} --manifest runbook.json --capture-dir <dir>",
        "",
        "HOW TO READ THE RESULTS",
        "  A tool's exit code is not a verdict. An empty result is not a false",
        "  positive, a closed port is not a remediation, and a successful",
        "  connection is not by itself a confirmation. Capture the output; the",
        "  reviewer decides.",
    ]
    return lines


# ---------------------------------------------------------------------------
# bash
# ---------------------------------------------------------------------------
def to_shell(runbook: Runbook) -> str:
    out: list[str] = ["#!/usr/bin/env bash"]
    out += [f"# {line}" if line else "#" for line in _header_lines(runbook)]
    out += [
        "",
        "# No `set -e`: a non-zero exit from a probe is normal and must not abort",
        "# the run. `set -u` catches unset variables only.",
        "set -u",
        "",
        'CAPTURE_DIR="${VAPT_CAPTURE_DIR:-./' + runbook.capture_dir + '}"',
        'TIMEOUT="${VAPT_STEP_TIMEOUT:-180}"',
        'mkdir -p "$CAPTURE_DIR"',
        "",
        "have() { command -v \"$1\" >/dev/null 2>&1; }",
        "",
        "step() {",
        "  local id=$1 tool=$2 rel=$3; shift 3",
        '  local out="$CAPTURE_DIR/$rel"',
        '  mkdir -p "$(dirname "$out")"',
        '  if ! have "$tool"; then',
        '    printf "# step: %s\\n# SKIPPED: %s is not installed on this machine.\\n" \\',
        '      "$id" "$tool" > "$out.skipped"',
        '    printf "[%s] SKIPPED (%s not installed)\\n" "$id" "$tool"',
        "    return 0",
        "  fi",
        '  printf "[%s] %s\\n" "$id" "$*"',
        '  {',
        '    printf "# step: %s\\n" "$id"',
        '    printf "# command: %s\\n" "$*"',
        '    printf "# started: %s\\n\\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"',
        '  } > "$out"',
        "  local rc=0",
        '  if have timeout; then',
        '    timeout "$TIMEOUT" "$@" </dev/null >>"$out" 2>&1 || rc=$?',
        "  else",
        '    "$@" </dev/null >>"$out" 2>&1 || rc=$?',
        "  fi",
        '  printf "\\n# exit_code: %s\\n# finished: %s\\n" \\',
        '    "$rc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out"',
        '  printf "      -> %s (exit %s)\\n" "$out" "$rc"',
        "  return 0",
        "}",
        "",
    ]

    tools = runbook.required_tools()
    if tools:
        out += ["echo 'Tool availability on this machine:'"]
        for tool in tools:
            out.append(
                f"if have {sh_quote(tool)}; then echo '  {tool}: found'; "
                f"else echo '  {tool}: MISSING (its steps will be skipped)'; fi"
            )
        out.append("echo")

    for entry in runbook.entries:
        if entry.retained_only:
            continue
        out += _shell_entry(entry)

    out += _retained_comment_block(runbook)
    out += [
        "",
        "echo",
        "echo 'Capture complete. Import the results with:'",
        "echo \"  vapt-verify evidence import --engagement "
        + runbook.engagement_id
        + " --manifest runbook.json --capture-dir $CAPTURE_DIR\"",
    ]
    return "\n".join(out) + "\n"


def _retained_comment_block(runbook: Runbook) -> list[str]:
    """List informational findings that were carried but not probed.

    They are named rather than silently omitted: an operator reading the script
    must be able to see that the tool made a decision about them, not that they
    fell out somewhere.
    """
    retained = [e for e in runbook.entries if e.retained_only]
    if not retained:
        return []
    out = [
        "",
        "# " + "=" * 74,
        f"# RETAINED, NOT SCANNED - {len(retained)} informational finding(s)",
        "#   Reported for inventory/context, not as a condition to confirm. They",
        "#   remain in the inventory and still need a disposition at review time.",
        "#   Re-run with --include-informational to generate commands for them.",
    ]
    for entry in retained:
        out.append(
            f"#   - [{entry.severity}] {entry.target}:{entry.port}/{entry.transport}  "
            f"{entry.plugin_name}"
        )
    return out


def _shell_entry(entry: RunbookEntry) -> list[str]:
    out = [
        "",
        "# " + "-" * 74,
        f"# {entry.finding_id}  [{entry.severity}]  {entry.plugin_name}",
        f"#   target: {entry.target}:{entry.port}/{entry.transport}  "
        f"service={entry.service or 'unknown'}",
        f"#   recipe: {entry.recipe_id}  (nmap role: {entry.nmap_role})",
        f"#   objective: {entry.objective}",
    ]
    for requirement in entry.sni_requirements:
        out.append(f"#   SNI: {requirement}")
    for item in entry.confirming_evidence[:2]:
        out.append(f"#   confirms: {item}")
    for item in entry.refuting_evidence[:2]:
        out.append(f"#   refutes:  {item}")
    for note in entry.notes:
        out.append(f"#   note: {note}")

    if not entry.commands:
        out.append("#   (no automatable command for this finding)")

    for command in entry.commands:
        out += _shell_command(command)
    for task in entry.manual_tasks:
        out += [
            f"#   MANUAL [{task.adapter}]: {task.instruction}",
            f"#     save your evidence as: $CAPTURE_DIR/{task.output_file}",
        ]
    return out


def _shell_command(command: RunbookCommand) -> list[str]:
    label = _STATUS_LABEL[command.status]
    out = [f"#   [{label}] {command.description or command.adapter}"]
    if not command.argv:
        out.append(f"#     {command.scope_reason}")
        return out
    invocation = (
        f"step {sh_quote(command.step_id)} {sh_quote(command.tool)} "
        f"{sh_quote(command.output_file)} {_sh_argv(command.argv)}"
    )
    if command.runnable:
        if command.status is CommandStatus.SCOPE_UNCONFIRMED:
            out.append(f"#     {command.scope_reason}")
        out.append(invocation)
    else:
        out.append(f"#     NOT RUN: {command.scope_reason}")
        out.append(f"#     {invocation}")
    return out


# ---------------------------------------------------------------------------
# powershell
# ---------------------------------------------------------------------------
def to_powershell(runbook: Runbook) -> str:
    out: list[str] = [f"# {line}" if line else "#" for line in _header_lines(runbook)]
    out += [
        "",
        "# Errors from a probe are expected and must not stop the run.",
        "$ErrorActionPreference = 'Continue'",
        "# NOTE: unlike the bash runbook, this script applies no per-step timeout.",
        "# Windows PowerShell has no portable equivalent of coreutils `timeout` that",
        "# preserves interleaved output, so a hung probe must be interrupted (Ctrl+C).",
        "",
        "$CaptureDir = if ($env:VAPT_CAPTURE_DIR) { $env:VAPT_CAPTURE_DIR } "
        f"else {{ Join-Path (Get-Location) {ps_quote(runbook.capture_dir)} }}",
        "New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null",
        "",
        "function Test-Tool { param([string]$Name)",
        "  return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }",
        "",
        "function Invoke-Step {",
        "  param([string]$Id, [string]$Tool, [string]$Rel, [string[]]$Argv)",
        "  $out = Join-Path $CaptureDir $Rel",
        "  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $out) | Out-Null",
        "  if (-not (Test-Tool $Tool)) {",
        "    \"# step: $Id`n# SKIPPED: $Tool is not installed on this machine.\" |"
        " Set-Content -Encoding utf8 \"$out.skipped\"",
        "    Write-Host \"[$Id] SKIPPED ($Tool not installed)\"",
        "    return",
        "  }",
        "  Write-Host \"[$Id] $($Argv -join ' ')\"",
        "  $started = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')",
        "  $header = \"# step: $Id`n# command: $($Argv -join ' ')`n# started: $started`n\"",
        "  $header | Set-Content -Encoding utf8 $out",
        "  $exe = $Argv[0]",
        "  $rest = if ($Argv.Count -gt 1) { $Argv[1..($Argv.Count - 1)] } else { @() }",
        "  $global:LASTEXITCODE = $null",
        "  # `$null |` closes stdin so a tool like `openssl s_client` completes its",
        "  # handshake and exits instead of waiting for console input.",
        "  try { $null | & $exe @rest 2>&1 | Out-File -Append -Encoding utf8 $out }",
        "  catch { \"# error: $_\" | Out-File -Append -Encoding utf8 $out }",
        "  $rc = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 0 }",
        "  $finished = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')",
        "  \"`n# exit_code: $rc`n# finished: $finished\" | Out-File -Append -Encoding utf8 $out",
        "  Write-Host \"      -> $out (exit $rc)\"",
        "}",
        "",
    ]

    tools = runbook.required_tools()
    if tools:
        out.append("Write-Host 'Tool availability on this machine:'")
        for tool in tools:
            out.append(
                f"if (Test-Tool {ps_quote(tool)}) {{ Write-Host '  {tool}: found' }} "
                f"else {{ Write-Host '  {tool}: MISSING (its steps will be skipped)' }}"
            )
        out.append("Write-Host ''")

    for entry in runbook.entries:
        if entry.retained_only:
            continue
        out += _powershell_entry(entry)

    out += _retained_comment_block(runbook)
    out += [
        "",
        "Write-Host ''",
        "Write-Host 'Capture complete. Import the results with:'",
        "Write-Host \"  vapt-verify evidence import --engagement "
        + runbook.engagement_id
        + " --manifest runbook.json --capture-dir $CaptureDir\"",
    ]
    return "\n".join(out) + "\n"


def _powershell_entry(entry: RunbookEntry) -> list[str]:
    out = [
        "",
        "# " + "-" * 74,
        f"# {entry.finding_id}  [{entry.severity}]  {entry.plugin_name}",
        f"#   target: {entry.target}:{entry.port}/{entry.transport}",
        f"#   objective: {entry.objective}",
    ]
    for requirement in entry.sni_requirements:
        out.append(f"#   SNI: {requirement}")
    for command in entry.commands:
        label = _STATUS_LABEL[command.status]
        out.append(f"#   [{label}] {command.description or command.adapter}")
        if not command.argv:
            out.append(f"#     {command.scope_reason}")
            continue
        invocation = (
            f"Invoke-Step -Id {ps_quote(command.step_id)} -Tool {ps_quote(command.tool)} "
            f"-Rel {ps_quote(command.output_file)} -Argv {_ps_argv(command.argv)}"
        )
        if command.runnable:
            if command.status is CommandStatus.SCOPE_UNCONFIRMED:
                out.append(f"#     {command.scope_reason}")
            out.append(invocation)
        else:
            out.append(f"#     NOT RUN: {command.scope_reason}")
            out.append(f"#     {invocation}")
    for task in entry.manual_tasks:
        out += [
            f"#   MANUAL [{task.adapter}]: {task.instruction}",
            f"#     save your evidence as: {task.output_file} (under $CaptureDir)",
        ]
    return out


# ---------------------------------------------------------------------------
# markdown checklist
# ---------------------------------------------------------------------------
def to_markdown(runbook: Runbook) -> str:
    coverage = runbook.coverage()
    lines = [
        "# Manual Verification Runbook",
        "",
        f"- **Engagement:** {runbook.engagement_id}"
        + (f" ({runbook.client_alias})" if runbook.client_alias else ""),
        f"- **Authorisation:** {runbook.authorisation_reference or '_not recorded_'}",
        f"- **Generated:** {runbook.generated_at} by vapt-verify {runbook.tool_version}",
        f"- **Findings covered:** {coverage.entries} "
        f"({coverage.with_runnable_command} with commands, "
        f"{coverage.manual_only} manual-only, "
        f"{coverage.retained_only} informational retained)",
        f"- **Coverage complete:** {'yes' if coverage.is_complete else 'NO - see below'}",
        "",
        "## Scope",
        "",
    ]
    lines += [f"- {s}" for s in runbook.scope_summary]
    lines += [
        "",
        "## How to use this",
        "",
        "1. Run the generated script (`runbook.sh` on Kali/Linux, `runbook.ps1` on Windows),",
        "   or copy individual commands below.",
        "2. Every command writes its output to the file named beneath it.",
        "3. Import the captures:",
        "   `vapt-verify evidence import --engagement "
        f"{runbook.engagement_id} --manifest runbook.json --capture-dir <dir>`",
        "4. Review each finding, then export the PoC pack.",
        "",
        "> **A tool's exit code is not a verdict.** An empty result is not a false",
        "> positive, a closed port is not a remediation, and a successful connection is",
        "> not a confirmation. Capture the output; a reviewer decides.",
        "",
    ]
    if coverage.unaccounted:
        lines += [
            "> **WARNING:** the following findings produced neither a command nor a manual",
            "> task and are therefore unaccounted for: "
            + ", ".join(coverage.unaccounted),
            "",
        ]

    for entry in runbook.entries:
        if entry.retained_only:
            continue
        lines += _markdown_entry(entry, runbook.capture_dir)

    retained = [e for e in runbook.entries if e.retained_only]
    if retained:
        lines += [
            f"## Retained, not scanned ({len(retained)} informational)",
            "",
            "Reported for inventory and context rather than as a condition to confirm,",
            "so no verification command is generated. They remain in the inventory and",
            "still require a disposition at review time. Re-run with",
            "`--include-informational` to generate commands for them.",
            "",
            "| Severity | Target | Finding |",
            "| --- | --- | --- |",
        ]
        for entry in retained:
            lines.append(
                f"| {entry.severity} | `{entry.target}:{entry.port}/{entry.transport}` "
                f"| {entry.plugin_name} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def _markdown_entry(entry: RunbookEntry, capture_dir: str) -> list[str]:
    lines = [
        f"## {entry.finding_id} - {entry.plugin_name}",
        "",
        f"- **Severity:** {entry.severity}   **Disposition:** {entry.disposition}",
        f"- **Target:** `{entry.target}:{entry.port}/{entry.transport}`"
        f"   **Service:** {entry.service or 'unknown'}",
        f"- **Recipe:** {entry.recipe_id} ({entry.recipe_title})",
        f"- **Nmap role for this finding:** {entry.nmap_role}",
        f"- **Objective:** {entry.objective}",
        "",
    ]
    if entry.sni_requirements:
        lines += ["**SNI / virtual host:**", ""]
        lines += [f"- {r}" for r in entry.sni_requirements]
        lines.append("")

    if entry.commands:
        lines += ["**Commands to run:**", ""]
        for command in entry.commands:
            label = _STATUS_LABEL[command.status]
            lines.append(f"- `[{label}]` {command.description or command.adapter}")
            if command.argv:
                lines += [
                    "",
                    "  ```",
                    "  " + _sh_argv(command.argv),
                    "  ```",
                    "",
                    f"  Save output to `{capture_dir}/{command.output_file}`",
                ]
                if not command.runnable:
                    lines.append(f"  **Do not run:** {command.scope_reason}")
                elif command.status is CommandStatus.SCOPE_UNCONFIRMED:
                    lines.append(f"  **Confirm first:** {command.scope_reason}")
                if not command.tool_present_locally:
                    lines.append(
                        f"  _`{command.tool}` was not found on the machine that generated this "
                        "runbook; run it where the tool is installed._"
                    )
            else:
                lines.append(f"  {command.scope_reason}")
            lines.append("")

    if entry.manual_tasks:
        lines += ["**Manual evidence required:**", ""]
        for task in entry.manual_tasks:
            lines.append(f"- [{task.adapter}] {task.instruction}")
            lines.append(f"  Save your evidence as `{capture_dir}/{task.output_file}`")
        lines.append("")

    if entry.confirming_evidence:
        lines += ["**Confirms the finding:**", ""]
        lines += [f"- {e}" for e in entry.confirming_evidence]
        lines.append("")
    if entry.refuting_evidence:
        lines += ["**Contradicts the finding:**", ""]
        lines += [f"- {e}" for e in entry.refuting_evidence]
        lines.append("")
    if entry.inconclusive_conditions:
        lines += ["**Inconclusive if:**", ""]
        lines += [f"- {e}" for e in entry.inconclusive_conditions]
        lines.append("")
    if entry.limitations:
        lines += ["**Known limitations:**", ""]
        lines += [f"- {e}" for e in entry.limitations]
        lines.append("")
    for note in entry.notes:
        lines += [f"_Note: {note}_", ""]
    return lines


# ---------------------------------------------------------------------------
# json manifest
# ---------------------------------------------------------------------------
def to_json(runbook: Runbook) -> str:
    return json.dumps(runbook.to_dict(), indent=2, sort_keys=True)
