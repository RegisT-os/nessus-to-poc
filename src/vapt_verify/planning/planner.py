"""Build a verification plan from a finding + its classification + recipe.

The planner turns the declarative recipe into a concrete, human-readable plan.
TLS findings always produce SNI/virtual-host guidance (task test 22.14): if a
hostname is known it is named for SNI; if only an IP is available the plan says
so and warns against validating a hostname mismatch by IP alone.
"""

from __future__ import annotations

from vapt_verify.classification.models import Classification
from vapt_verify.models.finding import Finding
from vapt_verify.models.recipe import Recipe, RecipeStep, VerificationFamily
from vapt_verify.planning.models import VerificationPlan


class Planner:
    def plan(
        self,
        *,
        finding: Finding,
        classification: Classification,
        recipe: Recipe,
        environment: str = "unknown",
        asset_hostname: str = "",
    ) -> VerificationPlan:
        primary, supporting = self._methods(recipe)
        manual = [s.description for s in recipe.manual_steps]
        tools = sorted(set(recipe.all_required_capabilities()) | set(recipe.optional_capabilities))

        return VerificationPlan(
            finding_id=finding.finding_id,
            finding_summary=f"{finding.plugin_name} ({finding.severity.name})",
            original_scanner_evidence=finding.plugin_output or finding.synopsis,
            asset_id=finding.asset_id,
            environment=environment,
            port=finding.port,
            transport=finding.transport.value,
            credentialed=finding.credentialed,
            verification_objective=self._objective(finding, recipe),
            primary_validation_method=primary,
            supporting_validation_methods=supporting,
            manual_fallback=manual or ["Reviewer determines the appropriate validation method."],
            required_tools=tools,
            required_credentials=recipe.auth_requirement.value,
            required_network_position=recipe.network_position.value,
            sni_vhost_requirements=self._sni(finding, recipe, asset_hostname),
            expected_confirming_evidence=list(recipe.positive_evidence),
            expected_contradictory_evidence=list(recipe.negative_evidence),
            inconclusive_conditions=list(recipe.inconclusive_conditions),
            safety_classification=recipe.safety_class.value,
            reviewer_checklist=self._checklist(finding, classification, recipe),
        )

    def _methods(self, recipe: Recipe) -> tuple[str, list[str]]:
        def describe(step: RecipeStep) -> str:
            tool = step.capability or step.adapter
            return f"{tool}: {step.description}"

        automated = [describe(s) for s in recipe.automated_steps]
        assisted = [describe(s) for s in recipe.assisted_steps]
        if automated:
            return automated[0], automated[1:] + assisted
        if assisted:
            return assisted[0], assisted[1:]
        if recipe.manual_steps:
            return f"manual: {recipe.manual_steps[0].description}", []
        return "Manual reviewer assessment.", []

    def _objective(self, finding: Finding, recipe: Recipe) -> str:
        if recipe.family is VerificationFamily.PATCH_LOCAL_CONFIG:
            return (
                "Confirm or refute the missing patch / local configuration using credentialed "
                "or administrative evidence (a remote scan cannot reproduce a local check)."
            )
        if recipe.family is VerificationFamily.INFORMATIONAL:
            return "Retain for context; classify what context this informational finding provides."
        return f"Independently verify: {finding.plugin_name}."

    def _sni(self, finding: Finding, recipe: Recipe, asset_hostname: str) -> list[str]:
        if recipe.family not in {VerificationFamily.TLS_CERTIFICATE, VerificationFamily.HTTP_WEB}:
            return []
        hostname = asset_hostname or self._finding_hostname(finding)
        if hostname:
            return [
                f"Use SNI/virtual host '{hostname}' when connecting; the certificate/response "
                "presented can depend on the SNI value.",
                "Do not validate a hostname mismatch using the IP address alone.",
            ]
        return [
            "No hostname/FQDN is available — only an IP. Obtain the intended hostname before "
            "validating certificate hostname/SNI conditions; do not judge a hostname mismatch "
            "from the IP alone.",
        ]

    def _finding_hostname(self, finding: Finding) -> str:
        props = finding.host_properties
        for key in ("host-fqdn", "host-rdns", "netbios-name"):
            value = props.get(key)
            if isinstance(value, list):
                value = value[0] if value else ""
            if value:
                return str(value)
        return ""

    def _checklist(
        self, finding: Finding, classification: Classification, recipe: Recipe
    ) -> list[str]:
        checklist = [
            "Confirm the target is within authorised scope before executing anything.",
            f"Disposition: {classification.disposition}. Nmap role: {recipe.nmap_role.value}.",
        ]
        if recipe.nmap_role.value == "inappropriate":
            checklist.append(
                "Do NOT use a remote port scan to confirm or invalidate this finding."
            )
        if classification.missing_capabilities:
            checklist.append(
                "Missing tools: " + ", ".join(classification.missing_capabilities)
                + " (absence does not remove the finding)."
            )
        for limitation in recipe.known_limitations:
            checklist.append(f"Limitation: {limitation}")
        return checklist
