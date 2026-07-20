"""The classification engine.

For every finding it selects a recipe using layered matching and explains why
that recipe was chosen and why others were not. It then assigns an explicit
:class:`Disposition`. Two rules are load-bearing:

* Every finding reaches at least the manual-review fallback — nothing is left
  unclassified.
* Local-check / patch / application findings are NEVER assigned remote-Nmap-only
  validation; their recipes mark Nmap ``inappropriate`` and route to
  credentialed / administrative / manual evidence.
"""

from __future__ import annotations

from vapt_verify.classification.models import Capabilities, Classification, RejectedRecipe
from vapt_verify.models.enums import Disposition
from vapt_verify.models.finding import Finding
from vapt_verify.models.recipe import (
    AuthRequirement,
    Recipe,
    SafetyClass,
    VerificationFamily,
)
from vapt_verify.recipes.library import RecipeLibrary


class Classifier:
    def __init__(self, library: RecipeLibrary, capabilities: Capabilities | None = None) -> None:
        self.library = library
        self.capabilities = capabilities or Capabilities()

    def classify(self, finding: Finding) -> Classification:
        selected, layer, rationale = self._select(finding)
        rejected = self._explain_rejections(finding, selected)
        disposition = self._assign_disposition(finding, selected)

        required = sorted(selected.all_required_capabilities())
        missing = sorted(self.capabilities.missing(set(required)))
        missing_info = self._missing_information(finding, selected)
        requirements = self._requirements(selected, missing, missing_info)

        return Classification(
            finding_id=finding.finding_id,
            family=selected.family.value,
            selected_recipe_id=selected.recipe_id,
            selected_recipe_title=selected.title,
            selection_layer=layer,
            selection_rationale=rationale,
            nmap_role=selected.nmap_role.value,
            auth_requirement=selected.auth_requirement.value,
            network_position=selected.network_position.value,
            safety_class=selected.safety_class.value,
            disposition=disposition.value,
            required_capabilities=required,
            optional_capabilities=sorted(selected.optional_capabilities),
            missing_capabilities=missing,
            missing_information=missing_info,
            expected_confirming_evidence=list(selected.positive_evidence),
            expected_contradictory_evidence=list(selected.negative_evidence),
            known_limitations=list(selected.known_limitations),
            verification_requirements=requirements,
            rejected_recipes=rejected,
        )

    # -- selection ----------------------------------------------------------

    def _select(self, finding: Finding) -> tuple[Recipe, int, str]:
        best: Recipe | None = None
        best_score = -1
        for recipe in self.library.recipes:  # already sorted by layer
            score = self._match_score(finding, recipe)
            if score <= 0:
                continue
            # Lower layer wins; within a layer, higher score wins.
            if best is None or recipe.selection_layer.value < best.selection_layer.value or (
                recipe.selection_layer.value == best.selection_layer.value and score > best_score
            ):
                best = recipe
                best_score = score
        if best is None:
            # Should never happen: the fallback matches everything.
            best = self._fallback()
            best_score = 1
        rationale = self._rationale(finding, best, best_score)
        return best, best.selection_layer.value, rationale

    def _match_score(self, finding: Finding, recipe: Recipe) -> int:
        # Manual fallback always matches (lowest priority).
        if recipe.selection_layer.value == 6:
            return 1

        name = finding.plugin_name.lower()
        text = " ".join([finding.description, finding.synopsis, finding.plugin_output]).lower()
        fam = finding.plugin_family.lower()

        plugin_hit = bool(
            recipe.plugin_ids and finding.plugin_id and finding.plugin_id in recipe.plugin_ids
        )
        name_hit = bool(recipe.name_indicators) and any(
            ind.lower() in name for ind in recipe.name_indicators
        )
        text_hit = bool(recipe.text_indicators) and any(
            ind.lower() in text for ind in recipe.text_indicators
        )
        family_hit = bool(recipe.plugin_families and fam) and any(
            pf.lower() in fam or fam in pf.lower() for pf in recipe.plugin_families
        )
        service_hit = bool(recipe.services and finding.service) and (
            finding.service.lower() in {s.lower() for s in recipe.services}
        )
        transport_ok = (not recipe.transports) or (finding.transport.value in recipe.transports)
        has_specific_signal = bool(
            recipe.plugin_ids or recipe.name_indicators or recipe.text_indicators
        )

        # Family-specific qualification --------------------------------------
        if recipe.family is VerificationFamily.INFORMATIONAL:
            return 5 if finding.is_informational else 0

        if recipe.family is VerificationFamily.PORT_SERVICE_EXPOSURE:
            return 3 if (finding.port > 0 and transport_ok) else 0

        if recipe.family is VerificationFamily.PATCH_LOCAL_CONFIG:
            # Qualifies only via host-level / plugin-family / specific name — never
            # via a network port or service, so a remote check can't own it.
            score = 0
            if finding.is_host_level:
                score += 30
            if family_hit:
                score += 25
            if name_hit:
                score += 15
            return score

        # Plugin-id exact is the strongest signal.
        if plugin_hit:
            return 100

        # Generic specific recipes -------------------------------------------
        score = 0
        if name_hit:
            score += 40
        if text_hit:
            score += 20
        if family_hit:
            score += 20
        if service_hit:
            if score > 0:
                score += 15  # service corroborates an indicator hit
            elif not has_specific_signal:
                score += 20  # a service-defined recipe qualifies by service alone
            # else: recipe declares name/plugin signals that did NOT hit — service
            # alone must not qualify it (prevents e.g. ssh-terrapin owning any ssh).
        if score > 0 and recipe.transports and not transport_ok:
            score = max(1, score - 25)
        return score

    def _rationale(self, finding: Finding, recipe: Recipe, score: int) -> str:
        reasons: list[str] = []
        if finding.plugin_id and finding.plugin_id in recipe.plugin_ids:
            reasons.append(f"plugin id {finding.plugin_id} is explicitly covered")
        if recipe.name_indicators and any(
            ind.lower() in finding.plugin_name.lower() for ind in recipe.name_indicators
        ):
            reasons.append("plugin name matched a name indicator")
        if recipe.plugin_families and finding.plugin_family and any(
            pf.lower() in finding.plugin_family.lower() for pf in recipe.plugin_families
        ):
            reasons.append(f"plugin family '{finding.plugin_family}' matched")
        if finding.is_host_level and recipe.family is VerificationFamily.PATCH_LOCAL_CONFIG:
            reasons.append("host-level (port 0) local-check finding")
        if finding.service and finding.service.lower() in {s.lower() for s in recipe.services}:
            reasons.append(f"service '{finding.service}' matched")
        if recipe.selection_layer.value == 6:
            reasons.append("no more specific recipe applied; using manual-review fallback")
        if recipe.family is VerificationFamily.INFORMATIONAL:
            reasons.append("finding is informational and retained for context")
        if not reasons:
            reasons.append("best available match by family/service heuristics")
        return (
            f"Selected '{recipe.recipe_id}' (layer {recipe.selection_layer.value}, "
            f"score {score}): " + "; ".join(reasons) + "."
        )

    def _explain_rejections(self, finding: Finding, selected: Recipe) -> list[RejectedRecipe]:
        rejected: list[RejectedRecipe] = []
        for recipe in self.library.recipes:
            if recipe.recipe_id == selected.recipe_id:
                continue
            score = self._match_score(finding, recipe)
            if score <= 0:
                continue
            if recipe.selection_layer.value > selected.selection_layer.value:
                reason = (
                    f"also matched but is less specific (layer "
                    f"{recipe.selection_layer.value} > {selected.selection_layer.value})"
                )
            elif recipe.selection_layer.value == selected.selection_layer.value:
                reason = "matched at the same layer with a lower score"
            else:
                reason = "matched a more specific layer but with a weaker signal"
            rejected.append(RejectedRecipe(recipe_id=recipe.recipe_id, reason=reason))
        return rejected[:6]

    # -- disposition --------------------------------------------------------

    def _assign_disposition(self, finding: Finding, recipe: Recipe) -> Disposition:
        if recipe.family is VerificationFamily.INFORMATIONAL or finding.is_informational:
            return Disposition.INFORMATIONAL_RETAINED
        if recipe.auth_requirement is AuthRequirement.ADMINISTRATIVE:
            return Disposition.ADMINISTRATIVE_EVIDENCE_REQUIRED
        if recipe.auth_requirement is AuthRequirement.CREDENTIALED:
            return Disposition.CREDENTIALED_VALIDATION_REQUIRED
        if recipe.recipe_id == "manual-review-fallback":
            return Disposition.MANUAL_VALIDATION_REQUIRED
        if recipe.family is VerificationFamily.APPLICATION_SECURITY:
            return Disposition.MANUAL_VALIDATION_REQUIRED
        if recipe.safety_class is SafetyClass.MANUAL:
            return Disposition.MANUAL_VALIDATION_REQUIRED

        # Recipe has some automated potential.
        required = recipe.all_required_capabilities()
        if recipe.automated_steps and not self.capabilities.missing(required):
            return Disposition.AUTOMATED_VERIFICATION_AVAILABLE
        # Assisted if there is any runnable step or an assisted step.
        runnable_optional = any(
            self.capabilities.has(s.capability) for s in recipe.automated_steps
        )
        if recipe.assisted_steps or runnable_optional:
            return Disposition.ASSISTED_VERIFICATION_AVAILABLE
        if recipe.automated_steps:
            # Needs a tool we do not have.
            return Disposition.TOOL_CAPABILITY_UNAVAILABLE
        return Disposition.MANUAL_VALIDATION_REQUIRED

    # -- helpers ------------------------------------------------------------

    def _missing_information(self, finding: Finding, recipe: Recipe) -> list[str]:
        missing: list[str] = []
        if recipe.family is VerificationFamily.TLS_CERTIFICATE:
            has_host = self._hostname_available(finding)
            if not has_host:
                missing.append(
                    "A hostname/FQDN is required for SNI and hostname validation; "
                    "only an IP is available."
                )
        if recipe.auth_requirement is AuthRequirement.CREDENTIALED and not finding.credentialed:
            missing.append("Credentials are required to reproduce this local-check finding.")
        return missing

    def _requirements(
        self, recipe: Recipe, missing_caps: list[str], missing_info: list[str]
    ) -> list[str]:
        reqs: list[str] = []
        if recipe.auth_requirement is not AuthRequirement.NONE:
            reqs.append(f"authentication: {recipe.auth_requirement.value}")
        reqs.append(f"network position: {recipe.network_position.value}")
        reqs.append(f"nmap role: {recipe.nmap_role.value}")
        if missing_caps:
            reqs.append("missing tools: " + ", ".join(missing_caps))
        reqs.extend(missing_info)
        return reqs

    def _hostname_available(self, finding: Finding) -> bool:
        props = finding.host_properties
        return any(props.get(key) for key in ("host-fqdn", "host-rdns", "netbios-name"))

    def _fallback(self) -> Recipe:
        fb = self.library.by_id("manual-review-fallback")
        if fb is None:
            raise RuntimeError("manual-review-fallback recipe is missing from the library")
        return fb
