"""Classification engine tests (task section 11; mandatory tests 13, 16, 17)."""

from __future__ import annotations

from pathlib import Path

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.classification.classifier import Classifier
from vapt_verify.classification.models import KNOWN_TOOLS, Capabilities
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.enums import Disposition
from vapt_verify.recipes.library import RecipeLibrary

FIXTURES = Path(__file__).parent / "fixtures"
ALL_TOOLS = Capabilities(available=set(KNOWN_TOOLS))


def _classifier(caps: Capabilities | None = None) -> Classifier:
    return Classifier(RecipeLibrary.load_builtin(), caps or ALL_TOOLS)


def _import(tmp_path: Path, *items: str, props_credentialed: bool = False) -> list:
    host = report_host(
        name="192.0.2.10",
        props=default_host_props("192.0.2.10", credentialed=props_credentialed),
        items=list(items),
    )
    path = tmp_path / "s.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    return NessusImporter(engagement_id="e").import_file(path).findings


def test_every_finding_reaches_a_recipe(tmp_path: Path) -> None:
    result = NessusImporter(engagement_id="e").import_file(FIXTURES / "sample_small.nessus")
    classifier = _classifier()
    for finding in result.findings:
        classification = classifier.classify(finding)
        assert classification.selected_recipe_id  # never empty
        assert classification.disposition != Disposition.PENDING_CLASSIFICATION.value


def test_manual_fallback_is_reachable() -> None:
    """A library with only the fallback still classifies any finding."""
    library = RecipeLibrary.load_builtin()
    fallback_only = RecipeLibrary([r for r in library.recipes if r.recipe_id == "manual-review-fallback"])
    classifier = Classifier(fallback_only, ALL_TOOLS)
    from vapt_verify.models.enums import Severity
    from vapt_verify.models.finding import Finding, SourceProvenance

    finding = Finding(finding_id="f", fingerprint="fp", asset_id="a",
                      provenance=SourceProvenance(), plugin_name="Anything At All",
                      severity=Severity.HIGH, port=8080)
    c = classifier.classify(finding)
    assert c.selected_recipe_id == "manual-review-fallback"
    assert c.disposition == Disposition.MANUAL_VALIDATION_REQUIRED.value


def test_local_check_not_assigned_remote_nmap_only(tmp_path: Path) -> None:
    """Task 22.13 — a credentialed local (port-0) check is never remote-Nmap-only."""
    item = report_item(
        plugin_id="123456",
        plugin_name="Ubuntu Security Update for OpenSSL",
        family="Ubuntu Local Security Checks",
        port=0,
        severity=3,
        cves=["CVE-2026-0001"],
    )
    findings = _import(tmp_path, item, props_credentialed=True)
    c = _classifier().classify(findings[0])
    assert c.family == "patch_local_config"
    assert c.nmap_role == "inappropriate"
    assert c.disposition in {
        Disposition.CREDENTIALED_VALIDATION_REQUIRED.value,
        Disposition.ADMINISTRATIVE_EVIDENCE_REQUIRED.value,
    }


def test_vmware_advisory_requests_administrative_evidence(tmp_path: Path) -> None:
    """Task 22.17 — a VMware advisory finding requests build/patch evidence."""
    item = report_item(
        plugin_id="200001",
        plugin_name="VMware ESXi Multiple Vulnerabilities (VMSA-2026-0001)",
        family="Misc.",
        port=443,
        protocol="tcp",
        severity=4,
    )
    findings = _import(tmp_path, item)
    c = _classifier().classify(findings[0])
    assert c.family == "hypervisor"
    assert c.disposition == Disposition.ADMINISTRATIVE_EVIDENCE_REQUIRED.value
    assert any("build" in e.lower() or "patch" in e.lower()
               for e in c.expected_confirming_evidence + c.known_limitations)


def test_ssh_enumeration_alone_does_not_confirm_terrapin(tmp_path: Path) -> None:
    """Task 22.16 — SSH algorithm enumeration is supporting evidence, not confirmation."""
    item = report_item(
        plugin_id="187315",
        plugin_name="SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)",
        family="Misc.",
        port=22,
        protocol="tcp",
        severity=2,
        cves=["CVE-2023-48795"],
    )
    findings = _import(tmp_path, item)
    recipe = RecipeLibrary.load_builtin().by_id("ssh-terrapin")
    assert recipe is not None
    c = _classifier().classify(findings[0])
    assert c.selected_recipe_id == "ssh-terrapin"
    assert c.nmap_role == "supporting"
    # A positive from enumeration is at most 'likely_confirmed', never 'confirmed'.
    assert recipe.verdict_suggestions.get("positive") == "likely_confirmed"


def test_missing_tool_becomes_capability_gap_not_removal(tmp_path: Path) -> None:
    """A finding whose tool is missing keeps a disposition; it is not dropped."""
    item = report_item(plugin_id="41028", plugin_name="SNMP Agent Default Community (public)",
                       family="SNMP", port=161, protocol="udp", severity=2)
    findings = _import(tmp_path, item)
    c = _classifier(Capabilities(available=set())).classify(findings[0])
    assert c.disposition in {
        Disposition.TOOL_CAPABILITY_UNAVAILABLE.value,
        Disposition.ASSISTED_VERIFICATION_AVAILABLE.value,
    }
    assert "snmpget" in c.missing_capabilities


def test_classification_is_explainable(tmp_path: Path) -> None:
    item = report_item(plugin_id="51192", plugin_name="SSL Certificate Cannot Be Trusted",
                       port=443, protocol="tcp", severity=2, svc_name="https")
    findings = _import(tmp_path, item)
    c = _classifier().classify(findings[0])
    assert c.selection_rationale
    assert c.rejected_recipes  # explains why other recipes were not chosen
    assert c.expected_confirming_evidence
