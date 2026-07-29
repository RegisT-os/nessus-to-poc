"""Turn classified findings into commands an operator runs by hand.

The builder walks every finding, resolves its recipe exactly as ``classify``
and ``run`` do, and asks each recipe step's adapter to ``build_argv`` for the
finding's real target and port. That reuse is the point: a runbook command and
an executed command come from the same code path, so they cannot drift.

What the builder deliberately does *not* do:

* **It does not gate on scope.** Writing a command into a text file is not
  running it. Gating generation on scope was what made an unconfigured
  workspace produce an empty runbook -- the operator got nothing at all. Scope
  is recorded per command instead, and the renderers comment out anything
  unauthorised.
* **It does not gate on locally installed tools.** A runbook is routinely
  generated on a laptop and run on Kali. A tool missing *here* is recorded as a
  note, never a reason to omit the command.
* **It does not drop a finding.** A finding with no runnable command gets an
  explicit manual evidence task, so every finding leaves the builder with
  something the operator can act on.
"""

from __future__ import annotations

import re
from typing import Any

from vapt_verify.adapters import get_adapter
from vapt_verify.adapters.base import Adapter, AdapterKind, ExecutionContext
from vapt_verify.classification.classifier import Classifier
from vapt_verify.classification.models import Capabilities
from vapt_verify.models.engagement import Engagement
from vapt_verify.models.enums import Severity
from vapt_verify.models.finding import Finding
from vapt_verify.models.recipe import Recipe, RecipeStep
from vapt_verify.naming import disambiguate, finding_basename, host_dir
from vapt_verify.planning.planner import Planner
from vapt_verify.recipes.library import RecipeLibrary
from vapt_verify.runbook.models import (
    CommandStatus,
    Runbook,
    RunbookCommand,
    RunbookEntry,
    RunbookManualTask,
)
from vapt_verify.security.scope import ScopeEnforcer, is_valid_target

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_component(value: str, fallback: str = "unknown") -> str:
    """Make a path component that is safe on both POSIX and Windows."""
    cleaned = _UNSAFE_PATH_CHARS.sub("_", value.strip()).strip("._")
    return cleaned[:64] or fallback


class RunbookBuilder:
    """Builds a :class:`Runbook` from an engagement's normalized findings."""

    def __init__(
        self,
        *,
        library: RecipeLibrary | None = None,
        capabilities: Capabilities | None = None,
        default_timeout: int = 120,
        capture_dir: str = "capture",
    ) -> None:
        self.library = library or RecipeLibrary.load_builtin()
        # Capabilities of the *generating* machine, recorded per command so the
        # operator knows what is missing here. Advisory only.
        self.capabilities = capabilities if capabilities is not None else Capabilities.detect()
        # Recipe selection, however, must NOT depend on them. A runbook written
        # on a Windows laptop with no security tools installed and run on Kali
        # must choose the same recipes as one written on Kali; classifying
        # against the local toolset would silently downgrade findings to
        # "capability unavailable" on the wrong machine.
        self.classifier = Classifier(self.library, Capabilities(available=set()))
        self.planner = Planner()
        self.default_timeout = default_timeout
        self.capture_dir = capture_dir
        # Populated per build(); capture paths need the whole finding set to be
        # both readable and collision-free.
        self._target_cache: dict[str, str] = {}
        self._finding_dirs: dict[str, str] = {}

    # -- entry point --------------------------------------------------------

    def build(
        self,
        *,
        engagement: Engagement,
        findings: list[dict[str, Any]],
        assets: list[dict[str, Any]] | None = None,
        include_informational: bool = False,
    ) -> Runbook:
        asset_index = {a["asset_id"]: a for a in (assets or [])}
        enforcer = ScopeEnforcer(engagement)

        # Resolve targets and readable per-finding directory names up front: a
        # capture path must be readable and unique, and uniqueness can only be
        # decided by looking at the whole set at once.
        self._target_cache = {}
        for row in findings:
            finding = Finding.from_dict(row)
            self._target_cache[finding.finding_id] = self._target(
                row, asset_index.get(finding.asset_id, {}), finding
            )
        self._finding_dirs = disambiguate(
            (
                row["finding_id"],
                finding_basename(
                    severity=Finding.from_dict(row).severity.name,
                    target="",  # the host is already the parent directory
                    port=int(row.get("port", 0)),
                    transport=str(row.get("transport", "")),
                    title=str(row.get("plugin_name", "")),
                ),
                str(row.get("plugin_id", "")),
            )
            for row in findings
        )
        scope_configured = bool(
            engagement.approved_cidrs
            or engagement.approved_targets
            or engagement.approved_hostnames
        )

        runbook = Runbook(
            engagement_id=engagement.engagement_id,
            client_alias=engagement.client_alias,
            authorisation_reference=engagement.authorisation_reference,
            capture_dir=self.capture_dir,
            scope_configured=scope_configured,
            scope_summary=self._scope_summary(engagement),
        )
        for row in findings:
            runbook.entries.append(
                self._entry(
                    row, asset_index, enforcer,
                    scope_configured=scope_configured,
                    include_informational=include_informational,
                )
            )
        return runbook

    # -- per-finding --------------------------------------------------------

    def _entry(
        self,
        row: dict[str, Any],
        asset_index: dict[str, dict[str, Any]],
        enforcer: ScopeEnforcer,
        *,
        scope_configured: bool,
        include_informational: bool = False,
    ) -> RunbookEntry:
        finding = Finding.from_dict(row)
        classification = self.classifier.classify(finding)
        recipe = self.library.by_id(classification.selected_recipe_id)
        asset = asset_index.get(finding.asset_id, {})
        hostnames = list(asset.get("fqdns", [])) + list(asset.get("hostnames", []))
        target = self._target(row, asset, finding)

        entry = RunbookEntry(
            finding_id=finding.finding_id,
            asset_id=finding.asset_id,
            plugin_id=finding.plugin_id,
            plugin_name=finding.plugin_name,
            severity=finding.severity.name,
            target=target,
            port=finding.port,
            transport=finding.transport.value,
            service=finding.service,
            recipe_id=classification.selected_recipe_id,
            recipe_title=classification.selected_recipe_title,
            disposition=classification.disposition,
            nmap_role=classification.nmap_role,
            objective=f"Independently verify: {finding.plugin_name}.",
            confirming_evidence=list(classification.expected_confirming_evidence),
            refuting_evidence=list(classification.expected_contradictory_evidence),
            limitations=list(classification.known_limitations),
        )

        # Informational findings do not get scanning commands by default. They
        # report state, not a condition to confirm, so probing them spends the
        # operator's time on noise. They are still carried in the runbook --
        # dropping them would break the guarantee that every finding is
        # accounted for -- just marked as retained rather than probed.
        if finding.severity is Severity.INFORMATIONAL and not include_informational:
            entry.retained_only = True
            entry.objective = (
                "Retained for context. No active verification is generated for "
                "informational findings; pass --include-informational to probe them."
            )
            entry.notes.append(
                "Informational: reported for inventory/context, not as a condition to "
                "confirm. It is retained in the inventory and still requires a "
                "disposition at review time."
            )
            return entry

        if recipe is None:
            entry.manual_tasks.append(
                RunbookManualTask(
                    task_id=f"{finding.finding_id}-manual-1",
                    finding_id=finding.finding_id,
                    asset_id=finding.asset_id,
                    adapter="manual",
                    instruction=(
                        "No verification recipe resolved for this finding. Determine an "
                        "appropriate validation method and record the evidence obtained."
                    ),
                    reason="no_recipe",
                    output_file=self._output_path(finding, "manual", 1, extension="txt"),
                )
            )
            return entry

        plan = self.planner.plan(
            finding=finding,
            classification=classification,
            recipe=recipe,
            environment=str(asset.get("environment", "unknown")),
            asset_hostname=hostnames[0] if hostnames else "",
        )
        entry.objective = plan.verification_objective
        entry.sni_requirements = list(plan.sni_vhost_requirements)
        entry.inconclusive_conditions = list(recipe.inconclusive_conditions)

        decision = enforcer.validate(target) if target else None
        sequence = 0
        for step in list(recipe.automated_steps) + list(recipe.assisted_steps):
            adapter = get_adapter(step.adapter)
            if adapter is None or adapter.kind is AdapterKind.MANUAL:
                continue
            sequence += 1
            if adapter.kind is AdapterKind.INPROCESS:
                # In-process checks (a bare TCP connect) have no binary to hand
                # over. Telling the operator to "use vapt-verify run" is useless
                # here -- they are on a different machine, which is the whole
                # reason for a runbook -- so emit the equivalent netcat probe.
                command = self._inprocess_equivalent(
                    finding=finding,
                    recipe=recipe,
                    step=step,
                    target=target,
                    sequence=sequence,
                    scope_reason=decision.reason if decision else "no target address available",
                    in_scope=bool(decision.in_scope) if decision else False,
                    scope_configured=scope_configured,
                )
                if command is None:
                    sequence -= 1
                    entry.notes.append(
                        f"Step '{step.adapter}' has no external-command equivalent for "
                        f"{finding.transport.value}/{finding.port}; run it with "
                        f"'vapt-verify run --finding {finding.finding_id} --approve' from a "
                        "host that can reach the target."
                    )
                    continue
                entry.commands.append(command)
                continue
            entry.commands.append(
                self._command(
                    finding=finding,
                    recipe=recipe,
                    step=step,
                    adapter=adapter,
                    target=target,
                    hostnames=hostnames,
                    sequence=sequence,
                    scope_reason=decision.reason if decision else "no target address available",
                    in_scope=bool(decision.in_scope) if decision else False,
                    scope_configured=scope_configured,
                )
            )

        for index, step in enumerate(recipe.manual_steps, start=1):
            entry.manual_tasks.append(
                RunbookManualTask(
                    task_id=f"{finding.finding_id}-manual-{index}",
                    finding_id=finding.finding_id,
                    asset_id=finding.asset_id,
                    adapter=step.adapter,
                    instruction=step.description or self._manual_instruction(step),
                    reason="recipe_manual_step",
                    output_file=self._output_path(
                        finding, f"manual-{step.adapter}", index, extension="txt"
                    ),
                )
            )

        if not entry.commands and not entry.manual_tasks:
            # The last line of the no-finding-disappears guarantee: a finding
            # that produced neither a command nor a recipe manual step still
            # leaves here with an explicit evidence request.
            entry.manual_tasks.append(
                RunbookManualTask(
                    task_id=f"{finding.finding_id}-manual-1",
                    finding_id=finding.finding_id,
                    asset_id=finding.asset_id,
                    adapter="manual",
                    instruction=(
                        "This finding has no automatable verification step. Obtain evidence "
                        "manually (administrative/credentialed/application review as "
                        "appropriate) and attach it."
                    ),
                    reason="no_automatable_step",
                    output_file=self._output_path(finding, "manual", 1, extension="txt"),
                )
            )
        return entry

    # -- per-step -----------------------------------------------------------

    def _command(
        self,
        *,
        finding: Finding,
        recipe: Recipe,
        step: RecipeStep,
        adapter: Adapter,
        target: str,
        hostnames: list[str],
        sequence: int,
        scope_reason: str,
        in_scope: bool,
        scope_configured: bool,
    ) -> RunbookCommand:
        params = dict(step.params)
        if hostnames:
            params.setdefault("vhost", hostnames[0])
        ctx = ExecutionContext(
            finding_id=finding.finding_id,
            asset_id=finding.asset_id,
            engagement_id="",
            target=target,
            port=finding.port,
            transport=finding.transport.value,
            params=params,
            timeout=float(self.default_timeout),
        )
        status = self._status(
            target=target,
            port=finding.port,
            in_scope=in_scope,
            scope_configured=scope_configured,
        )
        argv = adapter.build_argv(ctx) if status is not CommandStatus.UNSAFE_TARGET else []
        return RunbookCommand(
            step_id=f"{finding.finding_id}-{sequence}",
            finding_id=finding.finding_id,
            asset_id=finding.asset_id,
            adapter=adapter.name,
            tool=adapter.capability or adapter.name,
            description=step.description,
            argv=argv,
            target=target,
            port=finding.port,
            transport=finding.transport.value,
            output_file=self._output_path(finding, adapter.name, sequence),
            status=status,
            scope_reason=self._scope_reason(status, scope_reason),
            safety_class=adapter.safety_class.value,
            optional=step.optional,
            timeout=self.default_timeout,
            stdin_empty=adapter.stdin(ctx) is not None,
            tool_present_locally=self.capabilities.has(adapter.capability),
            params=params,
            look_for=list(recipe.positive_evidence),
        )

    def _inprocess_equivalent(
        self,
        *,
        finding: Finding,
        recipe: Recipe,
        step: RecipeStep,
        target: str,
        sequence: int,
        scope_reason: str,
        in_scope: bool,
        scope_configured: bool,
    ) -> RunbookCommand | None:
        """A netcat stand-in for an in-process reachability check.

        ``nc -vz`` reports the same thing the TCP-connect adapter does -- whether
        the port answers -- and, like it, proves exposure and nothing more. Only
        TCP has a safe, non-intrusive equivalent; UDP does not, so we return
        ``None`` rather than emit a probe whose result would be uninterpretable.
        """
        if finding.transport.value != "tcp" or finding.port <= 0:
            return None
        status = self._status(
            target=target,
            port=finding.port,
            in_scope=in_scope,
            scope_configured=scope_configured,
        )
        argv = (
            ["nc", "-vz", "-w", "5", target, str(finding.port)]
            if status is not CommandStatus.UNSAFE_TARGET
            else []
        )
        return RunbookCommand(
            step_id=f"{finding.finding_id}-{sequence}",
            finding_id=finding.finding_id,
            asset_id=finding.asset_id,
            adapter=step.adapter,
            tool="nc",
            description=(
                f"{step.description} (netcat stand-in for the in-process TCP check; "
                "reachability only -- it confirms exposure, not the vulnerability)"
            ).strip(),
            argv=argv,
            target=target,
            port=finding.port,
            transport=finding.transport.value,
            output_file=self._output_path(finding, f"{step.adapter}-nc", sequence),
            status=status,
            scope_reason=self._scope_reason(status, scope_reason),
            safety_class=recipe.safety_class.value,
            optional=step.optional,
            timeout=self.default_timeout,
            tool_present_locally=self.capabilities.has("nc"),
            params=dict(step.params),
            look_for=list(recipe.positive_evidence),
        )

    def _status(
        self, *, target: str, port: int, in_scope: bool, scope_configured: bool
    ) -> CommandStatus:
        if not target or not is_valid_target(target):
            return CommandStatus.UNSAFE_TARGET
        if port <= 0:
            return CommandStatus.NO_TARGET_PORT
        if in_scope:
            return CommandStatus.READY
        if not scope_configured:
            return CommandStatus.SCOPE_UNCONFIRMED
        return CommandStatus.OUT_OF_SCOPE

    def _scope_reason(self, status: CommandStatus, reason: str) -> str:
        if status is CommandStatus.UNSAFE_TARGET:
            return (
                "No valid IP or hostname is available for this finding; no command was "
                "generated. Resolve the address before attempting verification."
            )
        if status is CommandStatus.NO_TARGET_PORT:
            return (
                "The finding is host-level (port 0), so a port-specific probe cannot be "
                "addressed. Adjust the port or verify by another method."
            )
        if status is CommandStatus.SCOPE_UNCONFIRMED:
            return (
                "This engagement declares no approved scope, so authorisation cannot be "
                "confirmed by the tool. Confirm the target is in scope before running."
            )
        return reason

    # -- helpers ------------------------------------------------------------

    def _output_path(
        self, finding: Finding, adapter: str, sequence: int, extension: str = "txt"
    ) -> str:
        """A capture path an operator can read without a lookup table.

        ``192.0.2.10/3-MEDIUM_443-tcp_SSL-Certificate-Cannot-Be-Trusted/01_openssl.txt``
        rather than ``asset-f12da461b6465376/find-37c3608975b2529abc91d78b/...``.
        Uniqueness still comes from the finding id, appended only when two
        findings on a host would otherwise share a directory.
        """
        host = host_dir(self._target_cache.get(finding.finding_id, finding.asset_id))
        folder = self._finding_dirs.get(
            finding.finding_id, _safe_component(finding.finding_id, "finding")
        )
        name = f"{sequence:02d}_{_safe_component(adapter, 'step')}.{extension}"
        return f"{host}/{folder}/{name}"

    def _target(self, row: dict[str, Any], asset: dict[str, Any], finding: Finding) -> str:
        props = row.get("host_properties", {})
        if isinstance(props, dict):
            ip = props.get("host-ip")
            if isinstance(ip, list):
                ip = ip[0] if ip else ""
            if ip:
                return str(ip)
        for ip in asset.get("ip_addresses", []) or []:
            return str(ip)
        for key in ("primary_key",):
            value = asset.get(key)
            if value:
                return str(value)
        return finding.asset_id

    def _manual_instruction(self, step: RecipeStep) -> str:
        adapter = get_adapter(step.adapter)
        if adapter is None:
            return "Manual validation required; record the evidence obtained."
        ctx = ExecutionContext(
            finding_id="", asset_id="", engagement_id="", target="", port=0, transport="tcp"
        )
        return adapter.evidence_request(ctx)

    def _scope_summary(self, engagement: Engagement) -> list[str]:
        summary: list[str] = []
        if engagement.approved_cidrs:
            summary.append("approved CIDRs: " + ", ".join(engagement.approved_cidrs))
        if engagement.approved_targets:
            summary.append("approved targets: " + ", ".join(engagement.approved_targets))
        if engagement.approved_hostnames:
            summary.append("approved hostnames: " + ", ".join(engagement.approved_hostnames))
        if engagement.excluded_targets:
            summary.append("EXCLUDED: " + ", ".join(engagement.excluded_targets))
        if not summary:
            summary.append(
                "No approved scope is configured for this engagement. Nothing below has been "
                "confirmed as authorised by the tool."
            )
        return summary
