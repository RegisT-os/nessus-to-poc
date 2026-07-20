"""``vapt-verify`` command-line entry point.

The v0.1 CLI covers the lossless-import foundation: engagement creation, import
with a fail-closed reconciliation gate, inventory browsing and repository safety
scanning. Classification, planning, execution and reporting commands arrive in
later slices; they are declared in docs/ROADMAP.md.

Design note: ``run`` (adapter execution) is dry-run by default and is not yet
implemented in v0.1 — no verification action can be executed until the safe
adapter foundation (v0.3) lands.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Any

from vapt_verify import __version__
from vapt_verify.classification.classifier import Classifier
from vapt_verify.classification.models import Capabilities
from vapt_verify.coverage import compute_coverage
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement, TestingWindow
from vapt_verify.models.finding import Finding
from vapt_verify.planning.planner import Planner
from vapt_verify.recipes.legacy_migration import nmap_scripts_for_name
from vapt_verify.recipes.library import RecipeLibrary
from vapt_verify.reconciliation.gate import ReconciliationStatus, reconcile
from vapt_verify.security.client_data_check import scan_repository
from vapt_verify.workspace import EngagementWorkspace

# External tools the platform can *optionally* use in later slices. Their
# absence never removes a finding; it changes a finding's disposition.
_OPTIONAL_TOOLS = ["nmap", "openssl", "testssl.sh", "sslscan", "ssh-audit", "dig", "curl"]


def _workspace_root(base: str, engagement_id: str) -> Path:
    return Path(base) / engagement_id


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_version(_args: argparse.Namespace) -> int:
    print(f"vapt-verify {__version__}")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    print(f"vapt-verify {__version__}")
    print(f"python: {sys.version.split()[0]}")
    print("optional verification tools (absence never drops findings):")
    for tool in _OPTIONAL_TOOLS:
        location = shutil.which(tool)
        status = location if location else "not found"
        print(f"  {tool:<12} {status}")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    base = Path(args.base)
    base.mkdir(parents=True, exist_ok=True)
    print(f"Initialized engagements base at {base}/")
    print("Next: vapt-verify engagement create --id <id> --client-alias <alias>")
    return 0


def cmd_engagement_create(args: argparse.Namespace) -> int:
    root = _workspace_root(args.base, args.id)
    if (root / "engagement.yaml").exists() and not args.force:
        print(f"error: engagement already exists at {root} (use --force to overwrite)")
        return 2
    engagement = Engagement(
        engagement_id=args.id,
        client_alias=args.client_alias,
        engagement_type=args.type,
        assessment_type=args.assessment_type,
        authorisation_reference=args.authorisation_reference,
        testing_window=TestingWindow(),
    )
    ws = EngagementWorkspace.create(root, engagement)
    print(f"Created engagement '{args.id}' at {ws.root}/")
    print(f"  engagement.yaml: {ws.engagement_file}")
    return 0


def cmd_engagement_show(args: argparse.Namespace) -> int:
    root = _workspace_root(args.base, args.id)
    try:
        ws = EngagementWorkspace.load(root)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return 2
    print(ws.engagement().to_yaml())
    return 0


def cmd_import_dispatch(args: argparse.Namespace) -> int:
    """Route ``import status`` vs ``import <file>`` from a single positional."""
    if args.target == "status":
        return cmd_import_status(args)
    args.scan_file = args.target
    return cmd_import(args)


def cmd_import(args: argparse.Namespace) -> int:
    root = _workspace_root(args.base, args.engagement)
    try:
        ws = EngagementWorkspace.load(root)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        print("Create it first: vapt-verify engagement create --id <id>")
        return 2

    source = Path(args.scan_file)
    if not source.exists():
        print(f"error: scan file not found: {source}")
        return 2

    importer = NessusImporter(engagement_id=args.engagement)
    result = importer.import_file(source)
    report = reconcile(result, approved_suppressions=args.allow_suppressions)
    record = ws.persist_import(source_path=source, result=result, reconciliation=report)

    print(f"Imported {result.source_file} (import {result.import_id})")
    print(f"  source hosts:          {result.source_host_count}")
    print(f"  source report items:   {result.source_report_item_count}")
    print(f"  normalized findings:   {result.normalized_finding_count}")
    print(f"  parse failures:        {result.parse_failure_count}")
    print(f"  approved suppressions: {args.allow_suppressions}")
    print(f"  reconciliation status: {report.status.value}")
    for message in report.messages:
        print(f"    - {message}")
    print(f"  manifest:       {record.manifest_path}")
    print(f"  reconciliation: {record.reconciliation_path}")

    if report.status is ReconciliationStatus.IMBALANCED:
        print("FAILED: findings are unaccounted for. Import is not trustworthy.")
        return 1
    unacknowledged_exceptions = (
        report.status is ReconciliationStatus.BALANCED_WITH_EXCEPTIONS
        and not args.allow_parse_failures
    )
    if unacknowledged_exceptions:
        print(
            "FAILED CLOSED: import is balanced but has explicit exceptions. "
            "Review them, then re-run with --allow-parse-failures to acknowledge."
        )
        return 1
    print("OK: all source report items accounted for.")
    return 0


def cmd_import_status(args: argparse.Namespace) -> int:
    root = _workspace_root(args.base, args.engagement)
    try:
        ws = EngagementWorkspace.load(root)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return 2
    reports = ws.load_reconciliations()
    if not reports:
        print("No imports yet.")
        return 0
    total_source = 0
    total_norm = 0
    total_fail = 0
    for r in reports:
        total_source += r["source_report_item_count"]
        total_norm += r["normalized_finding_count"]
        total_fail += r["parse_failure_count"]
        print(
            f"- import {r['import_id']}: {r['source_file']} "
            f"[{r['status']}] source={r['source_report_item_count']} "
            f"normalized={r['normalized_finding_count']} failures={r['parse_failure_count']}"
        )
    print(
        f"TOTAL: source={total_source} normalized={total_norm} "
        f"failures={total_fail} accounted={total_norm + total_fail}"
    )
    if total_source != total_norm + total_fail:
        print("WARNING: aggregate accounting does not balance.")
        return 1
    return 0


def cmd_inventory_assets(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    assets = ws.load_assets()
    print(f"{len(assets)} asset(s):")
    for a in assets:
        ips = ", ".join(a.get("ip_addresses", [])) or "(no ip)"
        print(f"  {a['asset_id']}  key={a['primary_key']}  ips=[{ips}]  env={a.get('environment')}")
    return 0


def cmd_inventory_services(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    services = ws.load_services()
    print(f"{len(services)} service observation(s):")
    for s in services:
        print(
            f"  {s['service_id']}  {s['port']}/{s['transport']} "
            f"svc={s.get('service_name') or '?'}  source={s.get('observation_source')}"
        )
    return 0


def cmd_findings_list(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    findings = ws.load_findings()
    if args.severity:
        want = args.severity.upper()
        findings = [f for f in findings if f.get("severity_label", "").upper() == want]
    if args.port is not None:
        findings = [f for f in findings if f.get("port") == args.port]
    print(f"{len(findings)} finding(s):")
    for f in findings[: args.limit]:
        print(
            f"  {f['finding_id']}  [{f.get('severity_label')}] "
            f"{f.get('port')}/{f.get('transport')} plugin={f.get('plugin_id')} "
            f"{f.get('plugin_name')!r} disp={f.get('disposition')}"
        )
    if len(findings) > args.limit:
        print(f"  ... {len(findings) - args.limit} more (use --limit)")
    return 0


def cmd_findings_show(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    for f in ws.load_findings():
        if f["finding_id"] == args.finding_id:
            _print_finding(f)
            return 0
    print(f"error: finding {args.finding_id} not found")
    return 2


def cmd_capabilities(_args: argparse.Namespace) -> int:
    caps = Capabilities.detect()
    from vapt_verify.classification.models import KNOWN_TOOLS

    print("verification tool capabilities (absence never drops a finding):")
    for tool in KNOWN_TOOLS:
        mark = "available" if tool in caps.available else "missing"
        print(f"  {tool:<14} {mark}")
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    library = RecipeLibrary.load_builtin()
    caps = Capabilities.detect()
    classifier = Classifier(library, caps)

    rows = ws.load_findings()
    classifications: list[dict[str, object]] = []
    disposition_counts: dict[str, int] = {}
    for row in rows:
        finding = Finding.from_dict(row)
        result = classifier.classify(finding)
        row["disposition"] = result.disposition
        row["verification_requirements"] = result.verification_requirements
        classifications.append(result.to_dict())
        disposition_counts[result.disposition] = disposition_counts.get(result.disposition, 0) + 1

    ws.rewrite_findings(rows)
    ws.save_classifications(classifications)
    ws.append_audit_event({"event": "classify", "classified": len(rows)})

    print(f"Classified {len(rows)} finding(s). Dispositions:")
    for disposition, count in sorted(disposition_counts.items()):
        print(f"  {count:>4}  {disposition}")
    print("Every finding has an explicit disposition (no finding left unclassified).")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    for c in ws.load_classifications():
        if c["finding_id"] == args.finding_id:
            _print_classification(c)
            return 0
    print(f"error: no classification for {args.finding_id} (run 'vapt-verify classify' first)")
    return 2


def cmd_coverage(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    report = compute_coverage(ws.load_findings())
    print(f"Coverage: {report.accounted}/{report.total_imported} findings accounted for.")
    print(f"  classified:  {report.classified}")
    print(f"  unreviewed:  {report.unreviewed}")
    print("  by disposition:")
    for disposition, count in sorted(report.by_disposition.items()):
        print(f"    {count:>4}  {disposition}")
    print("  by verdict:")
    for verdict, count in sorted(report.by_verdict.items()):
        print(f"    {count:>4}  {verdict}")
    if not report.totals_balance:
        print("ERROR: coverage does not total back to imported findings.")
        return 1
    print("PRIMARY METRIC: accounted / imported = 100%.")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    library = RecipeLibrary.load_builtin()
    caps = Capabilities.detect()
    classifier = Classifier(library, caps)
    planner = Planner()
    assets = {a["asset_id"]: a for a in ws.load_assets()}

    rows = ws.load_findings()
    if args.finding:
        rows = [r for r in rows if r["finding_id"] == args.finding]
    if args.asset:
        rows = [r for r in rows if r["asset_id"] == args.asset]
    if not rows:
        print("No matching findings.")
        return 2

    written = 0
    for row in rows:
        finding = Finding.from_dict(row)
        classification = classifier.classify(finding)
        recipe = library.by_id(classification.selected_recipe_id)
        if recipe is None:
            continue
        asset = assets.get(finding.asset_id, {})
        hostnames = asset.get("fqdns", []) + asset.get("hostnames", [])
        plan = planner.plan(
            finding=finding,
            classification=classification,
            recipe=recipe,
            environment=asset.get("environment", "unknown"),
            asset_hostname=hostnames[0] if hostnames else "",
        )
        ws.save_plan(finding.finding_id, plan.to_dict())
        written += 1
        if args.finding:
            _print_plan(plan.to_dict())
    print(f"Wrote {written} verification plan(s) to {ws.plans_dir}/")
    return 0


def cmd_legacy_export_nmap(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    rows = ws.load_findings()
    lines: list[str] = []
    covered = 0
    for row in rows:
        finding = Finding.from_dict(row)
        scripts = nmap_scripts_for_name(finding.plugin_name)
        if not scripts or finding.port <= 0:
            continue
        covered += 1
        # Rendered for display only; real execution (v0.3) uses argument arrays.
        target = finding.asset_id
        ip = _finding_ip(row)
        if ip:
            target = ip
        proto_flag = "-sU" if finding.transport.value == "udp" else "-sT"
        script_arg = ",".join(scripts)
        lines.append(
            f"nmap {proto_flag} -Pn -p {finding.port} --script {script_arg} {target}"
            f"   # {finding.plugin_name}"
        )

    banner = (
        "============================================================\n"
        "WARNING: This export includes only findings with applicable\n"
        "Nmap recipes. It is NOT a complete verification of the scan.\n"
        f"{covered} of {len(rows)} findings have a legacy Nmap recipe.\n"
        "Use `vapt-verify coverage` to review ALL remaining findings.\n"
        "Nmap output NEVER by itself confirms or refutes a finding.\n"
        "============================================================"
    )
    print(banner)
    for line in lines:
        print(line)
    if args.output:
        Path(args.output).write_text(banner + "\n" + "\n".join(lines) + "\n", encoding="utf-8")
        print(f"\nWritten to {args.output}")
    return 0


def cmd_security_scan(args: argparse.Namespace) -> int:
    violations = scan_repository(args.root)
    if not violations:
        print("Client-data safety scan: OK (no violations).")
        return 0
    print(f"Client-data safety scan: {len(violations)} violation(s):")
    for v in violations:
        print(f"  [{v.severity}] {v.kind}: {v.path}\n      {v.message}")
    return 1


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _load_ws(args: argparse.Namespace) -> tuple[EngagementWorkspace | None, int]:
    root = _workspace_root(args.base, args.engagement)
    try:
        return EngagementWorkspace.load(root), 0
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return None, 2


def _finding_ip(row: dict[str, Any]) -> str:
    props = row.get("host_properties", {})
    ip = props.get("host-ip") if isinstance(props, dict) else ""
    if isinstance(ip, list):
        return str(ip[0]) if ip else ""
    return str(ip or "")


def _print_classification(c: dict[str, Any]) -> None:
    print(f"finding_id:   {c['finding_id']}")
    print(f"family:       {c['family']}")
    print(f"recipe:       {c['selected_recipe_id']} (layer {c['selection_layer']})")
    print(f"              {c['selected_recipe_title']}")
    print(f"rationale:    {c['selection_rationale']}")
    print(f"disposition:  {c['disposition']}")
    print(f"nmap role:    {c['nmap_role']}   auth: {c['auth_requirement']}")
    print(f"safety:       {c['safety_class']}")
    if c.get("missing_capabilities"):
        tools = ", ".join(c["missing_capabilities"])
        print(f"missing tools: {tools} (does not remove the finding)")
    if c.get("missing_information"):
        print("missing information:")
        for m in c["missing_information"]:
            print(f"    - {m}")
    if c.get("verification_requirements"):
        print("requirements:")
        for r in c["verification_requirements"]:
            print(f"    - {r}")
    if c.get("expected_confirming_evidence"):
        print("expected confirming evidence:")
        for e in c["expected_confirming_evidence"]:
            print(f"    - {e}")
    if c.get("known_limitations"):
        print("known limitations:")
        for lim in c["known_limitations"]:
            print(f"    - {lim}")
    if c.get("rejected_recipes"):
        print("why not other recipes:")
        for r in c["rejected_recipes"]:
            print(f"    - {r['recipe_id']}: {r['reason']}")


def _print_plan(p: dict[str, Any]) -> None:
    print(f"finding:      {p['finding_summary']} ({p['finding_id']})")
    print(f"objective:    {p['verification_objective']}")
    print(f"primary:      {p['primary_validation_method']}")
    for s in p.get("supporting_validation_methods", []):
        print(f"supporting:   {s}")
    for m in p.get("manual_fallback", []):
        print(f"manual:       {m}")
    if p.get("sni_vhost_requirements"):
        print("SNI/vhost:")
        for s in p["sni_vhost_requirements"]:
            print(f"    - {s}")
    print(f"tools:        {', '.join(p.get('required_tools', [])) or 'none'}")
    print(f"credentials:  {p['required_credentials']}   network: {p['required_network_position']}")
    print(f"safety:       {p['safety_classification']}   scope: {p['scope_decision']}")
    print("reviewer checklist:")
    for c in p.get("reviewer_checklist", []):
        print(f"    - {c}")


def _print_finding(f: dict[str, Any]) -> None:
    prov = f.get("provenance", {})
    prov = prov if isinstance(prov, dict) else {}
    print(f"finding_id:   {f['finding_id']}")
    print(f"fingerprint:  {f['fingerprint']}")
    print(f"asset_id:     {f['asset_id']}")
    print(f"plugin:       {f.get('plugin_id')} {f.get('plugin_name')!r} ({f.get('plugin_family')})")
    print(f"severity:     {f.get('severity_label')}  risk_factor={f.get('risk_factor')}")
    print(f"location:     port {f.get('port')}/{f.get('transport')} service={f.get('service')!r}")
    print(f"host-level:   {f.get('is_host_level')}")
    print(f"credentialed: {f.get('credentialed')}")
    print(f"cves:         {', '.join(f.get('cves', []) or []) or '(none)'}")
    print(f"disposition:  {f.get('disposition')}")
    print(f"verdict:      {f.get('verdict')}")
    src_hash = str(prov.get("source_file_hash"))[:12]
    print(f"source_file:  {prov.get('source_file')} (hash {src_hash})")
    dupes = f.get("duplicate_candidate_of") or []
    if dupes:
        print(f"duplicate candidates: {', '.join(dupes)}")
    output = str(f.get("plugin_output") or "")
    if output:
        print("plugin_output:")
        for line in output.splitlines():
            print(f"    {line}")


# ---------------------------------------------------------------------------
# argument parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vapt-verify",
        description="VAPT Verification Orchestrator — lossless import & verification planning.",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    def add_base(p: argparse.ArgumentParser) -> None:
        p.add_argument("--base", default="engagements", help="engagements base directory")

    def add_engagement(p: argparse.ArgumentParser) -> None:
        p.add_argument("--engagement", required=True, help="engagement id")

    sub.add_parser("version").set_defaults(func=cmd_version)
    sub.add_parser("doctor").set_defaults(func=cmd_doctor)

    p_init = sub.add_parser("init", help="initialize an engagements base directory")
    add_base(p_init)
    p_init.set_defaults(func=cmd_init)

    p_eng = sub.add_parser("engagement", help="manage engagements")
    eng_sub = p_eng.add_subparsers(dest="engagement_command", required=True)
    p_eng_create = eng_sub.add_parser("create", help="create an engagement workspace")
    add_base(p_eng_create)
    p_eng_create.add_argument("--id", required=True)
    p_eng_create.add_argument("--client-alias", default="")
    p_eng_create.add_argument("--type", default="")
    p_eng_create.add_argument("--assessment-type", default="")
    p_eng_create.add_argument("--authorisation-reference", default="")
    p_eng_create.add_argument("--force", action="store_true")
    p_eng_create.set_defaults(func=cmd_engagement_create)
    p_eng_show = eng_sub.add_parser("show", help="show an engagement's config")
    add_base(p_eng_show)
    p_eng_show.add_argument("--id", required=True)
    p_eng_show.set_defaults(func=cmd_engagement_show)

    p_import = sub.add_parser("import", help="import a scanner file (or 'import status')")
    add_base(p_import)
    add_engagement(p_import)
    p_import.add_argument("target", help="path to a .nessus file, or the literal 'status'")
    p_import.add_argument("--allow-parse-failures", action="store_true")
    p_import.add_argument("--allow-suppressions", type=int, default=0)
    p_import.set_defaults(func=cmd_import_dispatch)

    p_inv = sub.add_parser("inventory", help="browse normalized inventory")
    inv_sub = p_inv.add_subparsers(dest="inventory_command", required=True)
    p_inv_assets = inv_sub.add_parser("assets")
    add_base(p_inv_assets)
    add_engagement(p_inv_assets)
    p_inv_assets.set_defaults(func=cmd_inventory_assets)
    p_inv_services = inv_sub.add_parser("services")
    add_base(p_inv_services)
    add_engagement(p_inv_services)
    p_inv_services.set_defaults(func=cmd_inventory_services)

    p_find = sub.add_parser("findings", help="list or show findings")
    find_sub = p_find.add_subparsers(dest="findings_command", required=True)
    p_find_list = find_sub.add_parser("list")
    add_base(p_find_list)
    add_engagement(p_find_list)
    p_find_list.add_argument("--severity", default="")
    p_find_list.add_argument("--port", type=int, default=None)
    p_find_list.add_argument("--limit", type=int, default=50)
    p_find_list.set_defaults(func=cmd_findings_list)
    p_find_show = find_sub.add_parser("show")
    add_base(p_find_show)
    add_engagement(p_find_show)
    p_find_show.add_argument("finding_id")
    p_find_show.set_defaults(func=cmd_findings_show)

    sub.add_parser("capabilities", help="list available verification tools").set_defaults(
        func=cmd_capabilities
    )

    p_classify = sub.add_parser("classify", help="classify findings and assign dispositions")
    add_base(p_classify)
    add_engagement(p_classify)
    p_classify.set_defaults(func=cmd_classify)

    p_explain = sub.add_parser("explain", help="explain a finding's classification")
    add_base(p_explain)
    add_engagement(p_explain)
    p_explain.add_argument("finding_id")
    p_explain.set_defaults(func=cmd_explain)

    p_cov = sub.add_parser("coverage", help="coverage report (accounted / imported)")
    add_base(p_cov)
    add_engagement(p_cov)
    p_cov.set_defaults(func=cmd_coverage)

    p_plan = sub.add_parser("plan", help="build verification plans")
    add_base(p_plan)
    add_engagement(p_plan)
    p_plan.add_argument("--finding", default="")
    p_plan.add_argument("--asset", default="")
    p_plan.set_defaults(func=cmd_plan)

    p_legacy = sub.add_parser("legacy", help="legacy-compatibility commands")
    legacy_sub = p_legacy.add_subparsers(dest="legacy_command", required=True)
    p_legacy_nmap = legacy_sub.add_parser("export-nmap", help="export legacy-style Nmap commands")
    add_base(p_legacy_nmap)
    add_engagement(p_legacy_nmap)
    p_legacy_nmap.add_argument("--output", default="")
    p_legacy_nmap.set_defaults(func=cmd_legacy_export_nmap)

    p_sec = sub.add_parser("security", help="repository safety checks")
    sec_sub = p_sec.add_subparsers(dest="security_command", required=True)
    p_sec_scan = sec_sub.add_parser("scan", help="scan for client-data leaks")
    p_sec_scan.add_argument("--root", default=".")
    p_sec_scan.set_defaults(func=cmd_security_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        return cmd_version(args)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    result: int = func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
