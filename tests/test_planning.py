"""Planning tests (task section 17; mandatory tests 14, 24)."""

from __future__ import annotations

from pathlib import Path

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.classification.classifier import Classifier
from vapt_verify.classification.models import KNOWN_TOOLS, Capabilities
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.planning.planner import Planner
from vapt_verify.recipes.library import RecipeLibrary

ALL_TOOLS = Capabilities(available=set(KNOWN_TOOLS))


def _plan_for(item: str, tmp_path: Path, *, fqdn: str = "", asset_hostname: str = ""):
    props = default_host_props("192.0.2.10", fqdn=fqdn)
    host = report_host(name="192.0.2.10", props=props, items=[item])
    path = tmp_path / "s.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    finding = NessusImporter(engagement_id="e").import_file(path).findings[0]
    library = RecipeLibrary.load_builtin()
    classification = Classifier(library, ALL_TOOLS).classify(finding)
    recipe = library.by_id(classification.selected_recipe_id)
    assert recipe is not None
    return Planner().plan(
        finding=finding, classification=classification, recipe=recipe,
        asset_hostname=asset_hostname,
    )


def test_tls_finding_with_hostname_generates_sni_aware_plan(tmp_path: Path) -> None:
    """Task 22.14 — a TLS finding with a hostname produces an SNI-aware plan."""
    item = report_item(plugin_id="51192", plugin_name="SSL Certificate Cannot Be Trusted",
                       port=443, protocol="tcp", severity=2, svc_name="https")
    plan = _plan_for(item, tmp_path, fqdn="web01.example-doc.test")
    assert plan.sni_vhost_requirements
    assert any("web01.example-doc.test" in r for r in plan.sni_vhost_requirements)


def test_tls_finding_without_hostname_flags_ip_only(tmp_path: Path) -> None:
    item = report_item(plugin_id="51192", plugin_name="SSL Certificate Cannot Be Trusted",
                       port=443, protocol="tcp", severity=2, svc_name="https")
    plan = _plan_for(item, tmp_path)  # no fqdn
    assert plan.sni_vhost_requirements
    assert any("hostname" in r.lower() or "ip" in r.lower() for r in plan.sni_vhost_requirements)


def test_local_check_plan_forbids_remote_scan(tmp_path: Path) -> None:
    item = report_item(plugin_id="123456", plugin_name="Ubuntu Security Update",
                       family="Ubuntu Local Security Checks", port=0, severity=3)
    plan = _plan_for(item, tmp_path)
    assert any("do not use a remote port scan" in c.lower() for c in plan.reviewer_checklist)


def test_legacy_export_warns_incomplete(tmp_path: Path, capsys) -> None:
    """Task 22.24 — legacy Nmap export warns it is incomplete."""
    from vapt_verify.cli.main import main

    base = str(tmp_path / "engagements")
    main(["engagement", "create", "--base", base, "--id", "e1"])
    main(["import", "--base", base, "--engagement", "e1",
          str(Path(__file__).parent / "fixtures" / "sample_small.nessus")])
    capsys.readouterr()
    rc = main(["legacy", "export-nmap", "--base", base, "--engagement", "e1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "WARNING" in out
    assert "not a complete" in out.lower()
    assert "vapt-verify coverage" in out
    # The port-0 patch finding has no Nmap recipe and must not appear as a command.
    assert "Ubuntu Security Update" not in out.split("=====")[-1] or "--script" not in out.split("Ubuntu")[-1]
