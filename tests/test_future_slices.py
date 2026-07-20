"""Placeholders for mandatory regression tests owned by later slices.

The task brief (section 22) lists 32 mandatory regression tests. The v0.1
lossless-import foundation implements the import/reconciliation/safety subset
(covered in the other test modules). The remaining mandatory tests depend on
the classification engine (v0.2), the safe adapter/execution layer (v0.3) and
the review workflow (v0.6). They are declared here as explicit skips — with the
owning slice — so the full mandatory list stays visible and nothing is quietly
forgotten. Each will be un-skipped and implemented in its slice.
"""

from __future__ import annotations

import pytest

_V02 = "implemented in v0.2 (classification & planning)"
_V03 = "implemented in v0.3 (safe adapter foundation & execution)"
_V04 = "implemented in v0.4 (protocol expansion)"
_V06 = "implemented in v0.6 (review & evidence workflow)"


@pytest.mark.skip(reason=_V02)
def test_local_check_findings_not_assigned_remote_nmap_only() -> None:  # task 22.13
    ...


@pytest.mark.skip(reason=_V04)
def test_tls_finding_requiring_sni_generates_sni_aware_plan() -> None:  # task 22.14
    ...


@pytest.mark.skip(reason=_V04)
def test_tls_not_reproduced_by_nmap_can_be_confirmed_by_openssl() -> None:  # task 22.15
    ...


@pytest.mark.skip(reason=_V04)
def test_ssh_enum_alone_does_not_confirm_complex_ssh_vuln() -> None:  # task 22.16
    ...


@pytest.mark.skip(reason=_V02)
def test_vmware_advisory_requests_build_or_patch_evidence() -> None:  # task 22.17
    ...


@pytest.mark.skip(reason=_V03)
def test_closed_port_yields_service_not_currently_observed() -> None:  # task 22.18
    ...


@pytest.mark.skip(reason=_V03)
def test_tool_timeout_yields_inconclusive() -> None:  # task 22.19
    ...


@pytest.mark.skip(reason=_V03)
def test_missing_binary_is_capability_gap_not_finding_removal() -> None:  # task 22.20
    ...


@pytest.mark.skip(reason=_V03)
def test_out_of_scope_target_blocked_but_retained() -> None:  # task 22.21
    ...


@pytest.mark.skip(reason=_V02)
def test_legacy_export_warns_it_is_incomplete() -> None:  # task 22.24
    ...


@pytest.mark.skip(reason=_V03)
def test_nmap_exit_zero_does_not_assign_verdict() -> None:  # task 22.25
    ...


@pytest.mark.skip(reason=_V03)
def test_nmap_nonzero_does_not_erase_finding() -> None:  # task 22.26
    ...


@pytest.mark.skip(reason=_V03)
def test_commands_execute_without_shell_true() -> None:  # task 22.27
    ...


@pytest.mark.skip(reason=_V03)
def test_hostile_hostnames_cannot_trigger_command_injection() -> None:  # task 22.28
    ...


@pytest.mark.skip(reason=_V03)
def test_output_files_timestamped_not_overwritten() -> None:  # task 22.29
    ...
