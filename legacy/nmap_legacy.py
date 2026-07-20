#!/usr/bin/env python3
# ===========================================================================
# LEGACY ARTIFACT — RECONSTRUCTION — DO NOT USE IN PRODUCTION
# ===========================================================================
#
# Provenance note
# ---------------
# The original operational script (referred to as "nmap.py") was NOT present
# in this repository when the VAPT Verification Orchestrator project was
# recovered: the repository contained no commits and no tracked files.
#
# This file is a FAITHFUL BEHAVIOURAL RECONSTRUCTION of that script, rebuilt
# from the documented description of its behaviour so that:
#
#   1. Its exact finding-loss mechanisms can be demonstrated by tests.
#   2. Its useful seed knowledge (the VULNERABILITIES list) can be migrated
#      into versioned recipes.
#   3. The new platform can prove, via regression tests, that it does not
#      repeat the same losses.
#
# It intentionally preserves every known defect described in
# docs/LEGACY_FAILURE_ANALYSIS.md, including:
#   * hard-coded plugin-name substring coverage (2.1)
#   * discarding port-zero findings (2.2)
#   * case-sensitive substring matching only (2.3)
#   * collapsing findings to name -> host -> {ports} (2.4)
#   * dropping transport/application protocol (2.5)
#   * an unreliable "all open ports" model (2.6)
#   * shell=True command execution and result-file overwrites (2.10)
#
# DO NOT "fix" this file. Its purpose is to be a frozen baseline. The tests in
# tests/test_legacy_failure_modes.py depend on these defects being present.
# ===========================================================================

import os
import subprocess  # noqa: S404 (preserved legacy behaviour)
import xml.etree.ElementTree as ET  # noqa: S405 (preserved legacy behaviour)

# ---------------------------------------------------------------------------
# 2.1 Hard-coded coverage: only findings whose *plugin name* contains one of
# these case-sensitive substrings ever receive a verification command. Every
# other Nessus finding is silently absent from the generated output.
# ---------------------------------------------------------------------------
VULNERABILITIES = {
    "SSL Certificate Cannot Be Trusted": ["--script", "ssl-cert"],
    "SSL Self-Signed Certificate": ["--script", "ssl-cert"],
    "SSL Certificate Expiry": ["--script", "ssl-cert"],
    "SSL Medium Strength Cipher Suites Supported": ["--script", "ssl-enum-ciphers"],
    "SSL Weak Cipher Suites Supported": ["--script", "ssl-enum-ciphers"],
    "SSL RC4 Cipher Suites Supported": ["--script", "ssl-enum-ciphers"],
    "SSL Version 2 and 3 Protocol Detection": ["--script", "ssl-enum-ciphers"],
    "TLS Version 1.0 Protocol Detection": ["--script", "ssl-enum-ciphers"],
    "TLS Version 1.1 Protocol Detection": ["--script", "ssl-enum-ciphers"],
    "SSH Weak Algorithms Supported": ["--script", "ssh2-enum-algos"],
    "SSH Weak MAC Algorithms Enabled": ["--script", "ssh2-enum-algos"],
    "SSH Server CBC Mode Ciphers Enabled": ["--script", "ssh2-enum-algos"],
    "Terminal Services Encryption Level is Medium or Low": ["--script", "rdp-enum-encryption"],
    "Terminal Services Doesn't Use Network Level Authentication": ["--script", "rdp-ntlm-info"],
}


def find_nessus_files(root="."):
    """Search recursively for .nessus files."""
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".nessus"):
                found.append(os.path.join(dirpath, name))
    return found


def parse_nessus(path):
    """
    Parse a Nessus file and collapse matches into:

        results[vuln_name][host] = set(ports)

    This is the lossy core of the legacy tool.
    """
    # 2.4 Findings collapsed to name -> host -> {ports}.
    results = {}
    # 2.6 "All open ports" — every nonzero ReportItem port, treated (wrongly)
    # as if the port were currently open.
    all_open_ports = {}

    tree = ET.parse(path)  # noqa: S314 (preserved legacy behaviour; unsafe parser)
    root = tree.getroot()

    for report_host in root.iter("ReportHost"):
        host = report_host.get("name")
        for item in report_host.iter("ReportItem"):
            plugin_name = item.get("pluginName", "")
            port = item.get("port", "0")
            # protocol IS read here...
            _protocol = item.get("protocol", "tcp")
            # 2.5 ...but is then discarded: only the port number is kept.

            # 2.2 Port-zero findings are discarded entirely.
            if port != "0":
                all_open_ports.setdefault(host, set()).add(port)

            # 2.1 / 2.3 Case-sensitive substring match against the hard-coded
            # list. A finding whose plugin name is not covered here is dropped.
            for vuln_name in VULNERABILITIES:
                if vuln_name in plugin_name:
                    # 2.2 again: a matched vulnerability is only recorded when
                    # port != "0", so host/patch/policy findings vanish.
                    if port != "0":
                        results.setdefault(vuln_name, {}).setdefault(host, set()).add(port)

    return results, all_open_ports


def build_commands(results):
    """Generate Nmap command strings (2.10: strings, not argument arrays)."""
    commands = []
    for vuln_name, hosts in results.items():
        script_args = VULNERABILITIES[vuln_name]
        for host, ports in hosts.items():
            port_list = ",".join(sorted(ports))
            # 2.10 SYN scan (-sS) requires root for every scan.
            cmd = f"nmap -sS -p {port_list} {' '.join(script_args)} {host}"
            commands.append((vuln_name, host, cmd))
    return commands


def run_commands(commands, outdir="nmap_output"):
    """
    Optionally run the commands with shell=True and save output to text files.

    2.9 A zero exit code is (wrongly) treated as success/verification.
    2.10 shell=True + result-file overwrite, no scope validation, no manifest.
    """
    os.makedirs(outdir, exist_ok=True)
    for vuln_name, host, cmd in commands:
        # 2.10 Result files are overwritten; nothing is timestamped.
        outfile = os.path.join(outdir, f"{host}_{vuln_name}.txt".replace(" ", "_"))
        # 2.10 shell=True with interpolated host/port is a command-injection risk.
        proc = subprocess.run(  # noqa: S602 (preserved legacy behaviour)
            cmd, shell=True, capture_output=True, text=True
        )
        with open(outfile, "w") as fh:  # noqa: PTH123
            fh.write(proc.stdout)
        # 2.9 exit code 0 == "done" in the legacy mental model.


def main():
    for path in find_nessus_files("."):
        results, _all_open_ports = parse_nessus(path)
        commands = build_commands(results)
        # In the legacy workflow the operator would optionally call run_commands().
        for vuln_name, host, cmd in commands:
            print(f"[{vuln_name}] {host}: {cmd}")


if __name__ == "__main__":
    main()
