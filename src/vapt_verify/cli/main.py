"""``vapt-verify`` command-line entry point.

The CLI spans the full workflow: engagement/profile setup, lossless import with
a fail-closed reconciliation gate, explainable classification and planning,
dry-run-by-default safe execution, review/decision recording, coverage and
reporting, backup/restore and repository safety scanning.

Design note: ``run`` (adapter execution) is dry-run by default; nothing is
executed against a target unless it is explicitly in the engagement scope and
``--approve`` is passed.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from vapt_verify import __version__
from vapt_verify.adapters import get_adapter
from vapt_verify.adapters.base import AdapterKind, ExecutionContext
from vapt_verify.classification.classifier import Classifier
from vapt_verify.classification.models import Capabilities
from vapt_verify.cli.console import configure_stdio, console_encoding
from vapt_verify.coverage import compute_coverage
from vapt_verify.execution.runner import Executor, OutcomeStatus
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.importers.source_file import (
    SourceFileError,
    inspect_source_file,
    normalize_user_path,
)
from vapt_verify.models.engagement import Engagement, TestingWindow
from vapt_verify.models.finding import Finding
from vapt_verify.models.recipe import Recipe
from vapt_verify.naming import disambiguate, finding_basename
from vapt_verify.planning.planner import Planner
from vapt_verify.recipes.legacy_migration import nmap_scripts_for_name
from vapt_verify.recipes.library import RecipeLibrary, RecipeLibraryError
from vapt_verify.reconciliation.gate import ReconciliationStatus, reconcile
from vapt_verify.security.client_data_check import scan_repository
from vapt_verify.workspace import EngagementWorkspace

# External tools the platform can *optionally* use in later slices. Their
# absence never removes a finding; it changes a finding's disposition.
_OPTIONAL_TOOLS = ["nmap", "openssl", "testssl.sh", "sslscan", "ssh-audit", "dig", "curl"]

#: The commands ``--help`` lists, in the order an engagement actually runs.
#:
#: Everything else stays fully invocable with its own ``--help``; it is simply
#: not in the way. Thirty-odd commands on one screen tells an operator nothing
#: about which five they need today, and the ones they need are always these.
#: ``vapt-verify commands`` prints the complete list.
CORE_COMMANDS = (
    "doctor",
    "prepare",
    "import",
    "select",
    "kit",
    "findings",
    "review",
    "poc",
    "coverage",
    "commands",
)

#: Every command, grouped for ``vapt-verify commands``. Kept as data so a new
#: command cannot be added without deciding where an operator would look for it.
COMMAND_GROUPS: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    (
        "Core workflow",
        "What a normal engagement uses, in order.",
        (
            ("doctor", "check this machine can build and run kits"),
            ("prepare", "Nessus file -> engagement -> Kali validation kit, in one step"),
            ("import", "add another scanner file to an existing engagement"),
            ("select", "choose which findings become capture scripts"),
            ("kit build", "generate the Kali Bash validation scripts"),
            ("kit import", "read the returned kit's captures back in, hashed"),
            ("findings", "list or show findings"),
            ("review", "record a disposition and verdict for a finding"),
            ("poc export", "export report-ready PoC documents"),
            ("coverage", "did any finding disappear? (accounted / imported)"),
        ),
    ),
    (
        "Engagement setup",
        "Needed once per engagement, or when working from a client profile.",
        (
            ("init", "initialize an engagements base directory"),
            ("engagement create", "create an engagement workspace"),
            ("engagement show", "show an engagement's config"),
            ("profile show", "show a profile"),
            ("profile apply", "create an engagement from a profile"),
            ("environments assign", "assign environments to assets"),
        ),
    ),
    (
        "Inspecting what was imported",
        "Reading the inventory without changing anything.",
        (
            ("inventory assets", "browse normalized assets"),
            ("inventory services", "browse normalized service observations"),
            ("classify", "classify findings and assign dispositions"),
            ("explain", "explain why a finding selected the recipe it did"),
            ("capabilities", "list verification tools available on this machine"),
            ("plan", "build per-finding / per-asset verification plans"),
        ),
    ),
    (
        "Running checks from this machine",
        "The in-process executor, for when you are already on the network.",
        (
            ("run", "run a verification adapter (dry-run by default)"),
            ("playbook list", "list installed playbooks"),
            ("playbook show", "show a playbook's steps and conditions"),
            ("playbook validate", "validate a playbook file"),
        ),
    ),
    (
        "Evidence",
        "Attaching, requesting and proving the integrity of evidence.",
        (
            ("evidence request", "show the evidence a finding requires"),
            ("evidence add", "attach externally-collected evidence"),
            ("evidence verify", "re-hash stored evidence (chain of custody)"),
        ),
    ),
    (
        "Reporting and comparison",
        "Deliverables, and comparing one scan against another.",
        (
            ("report", "generate markdown / json / csv reports"),
            ("retest", "compare two imports (retest)"),
            ("diff", "diff two import sets"),
            ("correlate", "link findings across scanners (never merges)"),
            ("identities", "candidate asset identities across sources"),
        ),
    ),
    (
        "Maintenance",
        "Schema, backups and repository safety.",
        (
            ("schema", "show / verify workspace schema version"),
            ("backup", "back up an engagement with an integrity manifest"),
            ("restore", "restore an engagement backup"),
            ("security scan", "scan the repository for client-data leaks"),
            ("legacy export-nmap", "export legacy-style Nmap commands"),
            ("version", "print version and exit"),
        ),
    ),
)


def _workspace_root(base: str, engagement_id: str) -> Path:
    return Path(base) / engagement_id


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_version(_args: argparse.Namespace) -> int:
    print(f"vapt-verify {__version__}")
    return 0


def cmd_commands(_args: argparse.Namespace) -> int:
    """Print every command, including the ones ``--help`` keeps out of the way."""
    width = max(
        len(name) for _title, _blurb, entries in COMMAND_GROUPS for name, _help in entries
    )
    print(f"vapt-verify {__version__} - every command\n")
    for title, blurb, entries in COMMAND_GROUPS:
        print(title)
        print(f"  {blurb}")
        for name, help_text in entries:
            print(f"    {name.ljust(width)}  {help_text}")
        print()
    print("`vapt-verify --help` lists the core workflow only. Every command above")
    print("works and has its own --help, whether or not it appears there.")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    """Environment diagnostics. Run this first when something 'doesn't work'."""
    ok = True
    print(f"vapt-verify {__version__}")
    print(f"python:           {sys.version.split()[0]} ({sys.executable})")
    print(f"platform:         {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"console encoding: {console_encoding()}")

    # The recipe library is the #1 install-related failure: without it,
    # classify/plan/run cannot resolve any recipe.
    print(f"recipe library:   {RecipeLibrary.builtin_location()}")
    try:
        library = RecipeLibrary.load_builtin()
        print(f"                  {len(library)} recipe(s) loaded  [OK]")
    except Exception as exc:
        ok = False
        print(f"                  FAILED: {exc}")

    print("optional verification tools (absence never drops findings):")
    for tool in _OPTIONAL_TOOLS:
        location = shutil.which(tool)
        print(f"  {tool:<12} {location if location else 'not found'}")

    # PATH is advisory, not a failure: an unactivated virtualenv is a normal,
    # working setup. Only genuinely broken state (above) sets ok=False.
    scripts_dir = Path(sys.executable).parent
    if shutil.which("vapt-verify") is None:
        on_disk = scripts_dir / ("vapt-verify.exe" if platform.system() == "Windows"
                                 else "vapt-verify")
        print("\nNOTE: 'vapt-verify' is not on PATH (normal if the venv is not activated).")
        if on_disk.exists():
            print(f"      The command is installed at: {on_disk}")
        print("      Invoke it either way with:")
        print(f"        {sys.executable} -m vapt_verify doctor")

    print("\nRESULT: " + ("environment looks healthy." if ok else "problems found (see above)."))
    return 0 if ok else 1


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


def _select_importer(fmt: str, source: Path, engagement_id: str) -> Any:
    from vapt_verify.importers.nessus_csv import NessusCsvImporter
    from vapt_verify.importers.nmap_xml import NmapXmlImporter
    from vapt_verify.importers.normalized_json import NormalizedJsonImporter

    if fmt == "auto":
        suffix = source.suffix.lower()
        fmt = {
            ".nessus": "nessus", ".csv": "nessus-csv", ".xml": "nmap-xml",
            ".jsonl": "normalized-json", ".json": "normalized-json",
        }.get(suffix, "nessus")
    importers = {
        "nessus": NessusImporter, "nessus-csv": NessusCsvImporter,
        "nmap-xml": NmapXmlImporter, "normalized-json": NormalizedJsonImporter,
    }
    cls = importers.get(fmt, NessusImporter)
    return cls(engagement_id=engagement_id)


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

    source = normalize_user_path(str(args.scan_file))
    # Preflight: catch BOM/UTF-16/not-actually-XML files with an actionable
    # message instead of an opaque XML ParseError traceback.
    try:
        info = inspect_source_file(source)
    except SourceFileError as exc:
        print(f"error: {exc}")
        return 2

    importer = _select_importer(getattr(args, "format", "auto"), source, args.engagement)
    print(f"  importer:              {importer.source_scanner}")
    if info.has_bom or info.detected_encoding != "utf-8":
        print(f"  source encoding:       {info.detected_encoding} (handled)")
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


def cmd_prepare(args: argparse.Namespace) -> int:
    """One-command path: Nessus file -> engagement -> Kali validation kit."""
    root = _workspace_root(args.base, args.engagement)
    if (root / "engagement.yaml").exists():
        print(f"error: engagement '{args.engagement}' already exists at {root}")
        print("Use a new engagement id, or use 'kit build' for the existing engagement.")
        return 2

    create_args = argparse.Namespace(
        base=args.base,
        id=args.engagement,
        client_alias=args.client_alias,
        type="",
        assessment_type="",
        authorisation_reference=args.authorisation_reference,
        force=False,
    )
    result = cmd_engagement_create(create_args)
    if result != 0:
        return result

    import_args = argparse.Namespace(
        base=args.base,
        engagement=args.engagement,
        scan_file=args.scan_file,
        format="nessus",
        allow_parse_failures=args.allow_parse_failures,
        allow_suppressions=0,
    )
    result = cmd_import(import_args)
    if result != 0:
        print("Kali kit not generated because the Nessus import did not pass reconciliation.")
        return result

    kit_args = argparse.Namespace(
        base=args.base,
        engagement=args.engagement,
        output=args.output,
        force=False,
        include_informational=args.include_informational,
        all_findings=True,  # a fresh engagement cannot have a saved selection yet
    )
    return cmd_kit_build(kit_args)


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
    # A selection narrows what gets *scripts*, never what coverage reports on.
    # Saying so here is what keeps "did anything disappear?" answerable.
    from vapt_verify.selection import Selection

    selection = Selection.load(ws.root)
    if selection is not None and selection.deselected_count:
        print(f"  capture selection: {selection.count}/{selection.total_findings} selected "
              f"for scripts ({selection.method}, by {selection.operator})")
        print(f"    {selection.deselected_count} deselected finding(s) are counted above and "
              "still need a disposition;")
        print("    deselection is a scoping decision, not a false-positive judgement.")

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


def _select_adapter(recipe: Recipe) -> tuple[str, dict[str, Any]]:
    """Pick the primary executable adapter for a recipe, else a manual one."""
    for step in list(recipe.automated_steps) + list(recipe.assisted_steps):
        adapter = get_adapter(step.adapter)
        if adapter is not None and adapter.kind is not AdapterKind.MANUAL:
            return step.adapter, dict(step.params)
    for step in recipe.manual_steps:
        if get_adapter(step.adapter) is not None:
            return step.adapter, dict(step.params)
    return "manual", {}


def cmd_run(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    rows = {r["finding_id"]: r for r in ws.load_findings()}
    row = rows.get(args.finding)
    if row is None:
        print(f"error: finding {args.finding} not found")
        return 2

    library = RecipeLibrary.load_builtin()
    classifier = Classifier(library, Capabilities.detect())
    finding = Finding.from_dict(row)
    classification = classifier.classify(finding)
    recipe = library.by_id(classification.selected_recipe_id)
    if recipe is None:
        print("error: no recipe for finding")
        return 2

    adapter_name, params = _select_adapter(recipe)
    adapter = get_adapter(adapter_name)
    if adapter is None:
        print(f"error: adapter '{adapter_name}' not available")
        return 2

    assets = {a["asset_id"]: a for a in ws.load_assets()}
    asset = assets.get(finding.asset_id, {})
    hostnames = asset.get("fqdns", []) + asset.get("hostnames", [])
    target = _finding_ip(row) or asset.get("primary_key", finding.asset_id)
    if hostnames:
        params.setdefault("vhost", hostnames[0])

    ctx = ExecutionContext(
        finding_id=finding.finding_id,
        asset_id=finding.asset_id,
        engagement_id=args.engagement,
        target=target,
        port=finding.port,
        transport=finding.transport.value,
        params=params,
        operator=args.operator,
        timeout=float(args.timeout),
    )
    executor = Executor(capabilities=Capabilities.detect(), evidence_root=ws.evidence_dir)
    outcome = executor.run(
        ctx=ctx, adapter=adapter, engagement=ws.engagement(), dry_run=not args.approve
    )

    print(f"finding:   {finding.finding_id}  ({finding.plugin_name})")
    print(f"adapter:   {outcome.adapter}")
    print(f"status:    {outcome.status.value}")
    if outcome.planned_command:
        print(f"command:   {' '.join(outcome.planned_command)}")
    print(f"scope:     {outcome.scope_decision.get('reason', '')}")
    for note in outcome.notes:
        print(f"note:      {note}")
    if outcome.status is OutcomeStatus.EXECUTED and outcome.evidence is not None:
        ws.append_evidence(outcome.evidence.to_dict())
        ws.append_audit_event({
            "event": "run", "finding_id": finding.finding_id, "adapter": outcome.adapter,
            "evidence_id": outcome.evidence.evidence_id, "operator": args.operator,
        })
        print(f"evidence:  {outcome.evidence.evidence_id} (sha256 {outcome.evidence.sha256[:12]})")
        print(f"suggested: {outcome.suggested_verdict or '(none - reviewer decides)'}")
        print("NOTE: the exit code did not set a verdict; a reviewer must decide.")
    print("finding retained:", outcome.finding_retained)
    return 0


def cmd_kit_build(args: argparse.Namespace) -> int:
    from vapt_verify.kit import OnsiteKitBuilder

    ws, err = _load_ws(args)
    if ws is None:
        return err
    output = Path(args.output) if args.output else (ws.root / "kali-kit")
    from vapt_verify.selection import Selection

    selection = Selection.load(ws.root)
    if selection is not None and args.all_findings:
        print(f"A selection of {selection.count}/{selection.total_findings} finding(s) "
              "exists but --all-findings was passed; covering everything.")
        selection = None
    if selection is not None:
        print(f"Using saved selection: {selection.count} of {selection.total_findings} "
              f"finding(s) ({selection.method}, by {selection.operator}).")
        if selection.deselected_count:
            print(f"  {selection.deselected_count} deselected finding(s) get no scripts; "
                  "they remain in the engagement and still need a disposition.")
    result = OnsiteKitBuilder(ws).build(
        output,
        force=args.force,
        include_informational=args.include_informational,
        only_finding_ids=set(selection.selected_ids) if selection else None,
        selection_summary=selection.summary() if selection else "",
    )
    ws.append_audit_event(
        {
            "event": "kali_kit_build",
            "finding_count": result.finding_count,
            "executable_step_count": result.executable_count,
            "manual_step_count": result.manual_count,
            "scope_configured": result.scope_configured,
            "out_of_scope_step_count": result.out_of_scope_count,
            "unusable_target_step_count": result.unusable_target_count,
            "output": str(result.root),
        }
    )
    print(f"Kali validation kit written to {result.root}/")
    print(f"  Nessus findings:     {result.finding_count}")
    print(f"  executable scripts:  {result.executable_count}")
    print(f"  manual evidence:     {result.manual_count}")
    if result.out_of_scope_count:
        print(f"  out of scope:        {result.out_of_scope_count} step(s) -- generated and "
              "labelled, but the scripts refuse to run")
    if result.unusable_target_count:
        print(f"  unusable target:     {result.unusable_target_count} step(s) -- the scanner "
              "address is not a valid IP or hostname; listed as manual work")
    if not result.scope_configured:
        print("warning: this engagement declares no approved scope, so no target could be "
              "checked against one.")
        print(f"  Set approved_cidrs / approved_targets / approved_hostnames in "
              f"{ws.engagement_file}, or apply a profile, to have the kit check for you.")
    print("Next: copy the whole kit to Kali, read commands.md, then run ./run-all.sh")
    return 0


def cmd_kit_import(args: argparse.Namespace) -> int:
    from vapt_verify.kit import OnsiteEvidenceImporter

    ws, err = _load_ws(args)
    if ws is None:
        return err
    summary = OnsiteEvidenceImporter(ws).import_kit(
        normalize_user_path(args.kit_dir), operator_override=args.operator
    )
    print(f"Imported Kali evidence captures: {summary.imported}")
    if summary.skipped_duplicates:
        print(f"Skipped duplicate captures:      {summary.skipped_duplicates}")
    for error in summary.errors:
        print(f"error: {error}")

    if summary.outstanding_manual_steps:
        print(f"\n  manual evidence still outstanding: "
              f"{len(summary.outstanding_manual_steps)}")
        for entry in summary.outstanding_manual_steps[:10]:
            print(f"    - {entry}")
        if len(summary.outstanding_manual_steps) > 10:
            print(f"    ... and {len(summary.outstanding_manual_steps) - 10} more")

    if summary.findings_without_evidence:
        print(f"\n  findings still with NO evidence: "
              f"{len(summary.findings_without_evidence)}")
        print("    These remain in the inventory and still require a disposition;")
        print("    missing evidence is never a false positive.")
        for finding_id in summary.findings_without_evidence[:10]:
            print(f"    - {finding_id}")
        if len(summary.findings_without_evidence) > 10:
            print(f"    ... and {len(summary.findings_without_evidence) - 10} more")

    if summary.imported:
        print("\nNOTE: no verdict was set. Evidence records what a tool observed; a "
              "reviewer decides what it means.")
        print("Next: vapt-verify review --finding <id> ...   then   vapt-verify poc export")
    return 1 if summary.errors else 0


def cmd_evidence_request(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    rows = {r["finding_id"]: r for r in ws.load_findings()}
    row = rows.get(args.finding)
    if row is None:
        print(f"error: finding {args.finding} not found")
        return 2
    library = RecipeLibrary.load_builtin()
    finding = Finding.from_dict(row)
    classification = Classifier(library, Capabilities.detect()).classify(finding)
    recipe = library.by_id(classification.selected_recipe_id)
    print(f"finding:      {finding.finding_id} ({finding.plugin_name})")
    print(f"disposition:  {classification.disposition}")
    print("evidence required:")
    steps = recipe.manual_steps if recipe else []
    if steps:
        for step in steps:
            print(f"  - [{step.adapter}] {step.description}")
    else:
        print("  - Manual reviewer assessment.")
    return 0


def cmd_evidence_add(args: argparse.Namespace) -> int:
    ws, err = _load_ws(args)
    if ws is None:
        return err
    source = Path(args.file)
    if not source.exists():
        print(f"error: evidence file not found: {source}")
        return 2
    from vapt_verify.models.evidence import Evidence
    from vapt_verify.utilities.hashing import sha256_file

    rows = {r["finding_id"]: r for r in ws.load_findings()}
    row = rows.get(args.finding)
    if row is None:
        print(f"error: finding {args.finding} not found")
        return 2
    import shutil as _shutil
    import uuid as _uuid

    evidence_id = _uuid.uuid4().hex
    dest_dir = ws.evidence_dir / row["asset_id"] / args.finding
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"external_{evidence_id[:8]}_{source.name}"
    _shutil.copy2(source, dest)
    evidence = Evidence(
        evidence_id=evidence_id,
        finding_id=args.finding,
        engagement_id=args.engagement,
        asset_id=row["asset_id"],
        adapter="external",
        tool_name=args.tool or "external",
        operator=args.operator,
        parsed_observations={"note": args.note},
        raw_evidence_path=str(dest),
        sha256=sha256_file(dest),
        sanitization_status="operator_supplied",
        review_notes=args.note,
    )
    ws.append_evidence(evidence.to_dict())
    ws.append_audit_event({"event": "evidence_add", "finding_id": args.finding,
                           "evidence_id": evidence_id, "operator": args.operator})
    print(f"Attached evidence {evidence_id} (sha256 {evidence.sha256[:12]}) to {args.finding}")
    return 0


def cmd_playbook_list(args: argparse.Namespace) -> int:
    from vapt_verify.playbooks import PlaybookLibrary, validate_library

    library = PlaybookLibrary.load_builtin()
    if not library.playbooks:
        print("No playbooks are installed.")
        return 2
    problems = validate_library(library)
    print(f"{len(library)} playbook(s):")
    for playbook in library.playbooks:
        status = "INVALID" if playbook.playbook_id in problems else "ok"
        scope = ", ".join(playbook.recipe_ids or playbook.families) or "(unscoped)"
        print(f"  [{status:>7}] {playbook.playbook_id:<24} {len(playbook.steps)} step(s)"
              f"  {playbook.title}")
        print(f"            applies to: {scope}")
    if problems:
        print(f"\n{len(problems)} playbook(s) failed validation; run "
              "'vapt-verify playbook validate' for details.")
        return 1
    return 0


def cmd_playbook_show(args: argparse.Namespace) -> int:
    from vapt_verify.playbooks import PlaybookLibrary, describe_playbook, validate_playbook

    library = PlaybookLibrary.load_builtin()
    playbook = library.by_id(args.playbook)
    if playbook is None:
        print(f"error: no playbook with id {args.playbook!r}")
        print("Available: " + ", ".join(p.playbook_id for p in library.playbooks))
        return 2
    for line in describe_playbook(playbook):
        print(line)
    problems = validate_playbook(playbook)
    if problems:
        print("\nVALIDATION PROBLEMS:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    return 0


def cmd_playbook_validate(args: argparse.Namespace) -> int:
    from vapt_verify.playbooks import PlaybookLibrary, validate_library

    if args.path:
        library = PlaybookLibrary.load_dirs([Path(args.path)])
        source = args.path
    else:
        library = PlaybookLibrary.load_builtin()
        source = PlaybookLibrary.builtin_location()
    print(f"Validating {len(library)} playbook(s) from {source}")
    problems = validate_library(library)
    if not problems:
        print("OK: every playbook's steps are runnable and every condition can fire.")
        return 0
    for playbook_id, entries in sorted(problems.items()):
        print(f"\n{playbook_id}:")
        for entry in entries:
            print(f"  - {entry}")
    print(f"\nFAILED: {len(problems)} playbook(s) have problems.")
    print("A condition that can never be true is not a no-op: the step silently")
    print("never runs, which looks exactly like a step that does not apply.")
    return 1


def cmd_select(args: argparse.Namespace) -> int:
    """Choose which findings become capture scripts."""
    from vapt_verify.cli.picker import run_picker
    from vapt_verify.selection import (
        Selection,
        SelectionCriteria,
        select_by_criteria,
        sort_key,
    )

    ws, err = _load_ws(args)
    if ws is None:
        return err
    rows = ws.load_findings()
    if not rows:
        print("No findings imported yet.")
        return 2

    existing = Selection.load(ws.root)

    if args.clear:
        if Selection.clear(ws.root):
            ws.append_audit_event({"event": "selection_clear", "operator": args.operator})
            print("Selection cleared. All findings are covered again.")
        else:
            print("No selection was set; all findings are already covered.")
        return 0

    if args.show:
        if existing is None:
            print(f"No selection set: all {len(rows)} finding(s) are covered.")
            return 0
        _print_selection(existing, rows)
        return 0

    try:
        criteria = SelectionCriteria.parse(
            severity=args.severity, host=args.host, plugin=args.plugin,
            service=args.service, port=args.port, search=args.search,
            finding=args.finding,
        )
    except ValueError as exc:
        print(f"error: {exc}")
        return 2

    interactive = args.interactive or (criteria.is_empty and not args.all)
    if interactive:
        preselected = set(existing.selected_ids) if existing and args.add else set()
        if not criteria.is_empty:
            # Criteria on an interactive run pre-tick the matching rows, so
            # "the criticals, plus a couple more" is one pass instead of two.
            preselected |= {r["finding_id"] for r in rows if criteria.matches(r)}
        print(f"Selecting findings for engagement '{args.engagement}' "
              f"({len(rows)} imported).")
        chosen = run_picker(rows, preselected=preselected)
        if chosen is None:
            return 1
        selection = Selection(
            engagement_id=args.engagement,
            selected_ids=[
                r["finding_id"] for r in sorted(rows, key=sort_key)
                if r["finding_id"] in chosen
            ],
            total_findings=len(rows),
            operator=args.operator,
            criteria=criteria,
            method="interactive",
            note=args.note,
            last_operation="picked interactively",
        )
    else:
        selection = select_by_criteria(
            rows, criteria, engagement_id=args.engagement,
            operator=args.operator, note=args.note,
        )
        matched = len(selection.selected_ids)
        if (args.add or args.remove) and not matched:
            # Say so rather than silently reprinting an unchanged selection.
            print(f"Nothing matched {criteria.describe()}; the selection is unchanged.")
            return 2
        if args.add and existing:
            merged = set(existing.selected_ids) | set(selection.selected_ids)
            selection.selected_ids = [
                r["finding_id"] for r in sorted(rows, key=sort_key)
                if r["finding_id"] in merged
            ]
            selection.method = "edited"
            selection.note = args.note or existing.note
            selection.last_operation = (
                f"added {matched} finding(s) matching: {criteria.describe()}"
            )
        elif args.remove and existing:
            remaining = set(existing.selected_ids) - set(selection.selected_ids)
            removed = len(existing.selected_ids) - len(remaining)
            selection.selected_ids = [
                r["finding_id"] for r in sorted(rows, key=sort_key)
                if r["finding_id"] in remaining
            ]
            selection.method = "edited"
            selection.note = args.note or existing.note
            selection.last_operation = (
                f"removed {removed} finding(s) matching: {criteria.describe()}"
            )

    if not selection.selected_ids:
        print("That would select no findings, so the selection was not changed.")
        print("Run 'vapt-verify select --engagement "
              f"{args.engagement} --show' to see the current selection, or "
              "--clear to cover everything again.")
        return 2

    selection.save(ws.root)
    ws.append_audit_event({
        "event": "selection_set",
        "operator": args.operator,
        "method": selection.method,
        "selected": selection.count,
        "total": selection.total_findings,
        "criteria": selection.criteria.describe(),
    })
    _print_selection(selection, rows)
    print("\nNext:")
    print(f"  vapt-verify kit build --engagement {args.engagement} --output <dir>")
    print("It uses this selection automatically; pass --all-findings to ignore it.")
    return 0


def _print_selection(selection: Any, rows: list[dict[str, Any]]) -> None:
    from vapt_verify.selection import finding_host, sort_key

    chosen = set(selection.selected_ids)
    print(f"Selection: {selection.count} of {selection.total_findings} finding(s)"
          f"  [{selection.method}, by {selection.operator}]")
    if selection.last_operation:
        print(f"  last change: {selection.last_operation}")
    elif not selection.criteria.is_empty:
        print(f"  criteria:    {selection.criteria.describe()}")
    if selection.note:
        print(f"  note:        {selection.note}")
    print("")
    for row in sorted((r for r in rows if r["finding_id"] in chosen), key=sort_key):
        port = row.get("port", 0) or 0
        location = f"{port}/{row.get('transport', '')}" if port else "host"
        print(f"  [x] {row.get('severity_label', '')!s:<13} "
              f"{finding_host(row):<16} {location:<10} {row.get('plugin_name', '')}")
    if selection.deselected_count:
        print(f"\n  {selection.deselected_count} finding(s) deselected. They remain in the")
        print("  engagement, are NOT false positives, and still require a disposition.")
        print("  'vapt-verify coverage' still reports against every imported finding.")


def _apply_selection(
    ws: EngagementWorkspace,
    rows: list[dict[str, Any]],
    *,
    all_findings: bool,
    label: str,
) -> list[dict[str, Any]]:
    """Filter to the saved selection, saying so rather than silently narrowing."""
    from vapt_verify.selection import Selection

    selection = Selection.load(ws.root)
    if selection is None:
        return rows
    if all_findings:
        print(f"A selection of {selection.count}/{selection.total_findings} finding(s) "
              "exists but --all-findings was passed; covering everything.")
        return rows
    filtered = selection.apply(rows)
    print(f"Using saved selection: {len(filtered)} of {len(rows)} finding(s) "
          f"({selection.method}, by {selection.operator}).")
    if selection.deselected_count:
        print(f"  {selection.deselected_count} deselected finding(s) are excluded from this "
              f"{label}; they remain in the engagement and still need a disposition.")
    return filtered


def cmd_profile_show(args: argparse.Namespace) -> int:
    from vapt_verify.profiles.loader import load_profile

    try:
        profile = load_profile(args.path)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return 2
    eng = profile.engagement
    print(f"profile:        {profile.path}")
    print(f"engagement_id:  {eng.engagement_id}")
    print(f"client_alias:   {eng.client_alias}")
    print(f"type:           {eng.engagement_type}")
    print(f"approved_cidrs: {', '.join(eng.approved_cidrs) or '(none)'}")
    print(f"environments:   {len(profile.environment_rules)}")
    for rule in profile.environment_rules:
        crit = " [CRITICAL]" if rule.critical else ""
        print(f"  - {rule.name}{crit}: cidrs={rule.cidrs} hostnames={rule.hostname_patterns}")
    return 0


def cmd_profile_apply(args: argparse.Namespace) -> int:
    import shutil as _shutil

    from vapt_verify.profiles.loader import load_profile

    try:
        profile = load_profile(args.path)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return 2
    engagement = profile.engagement
    if args.id:
        engagement.engagement_id = args.id
    root = _workspace_root(args.base, engagement.engagement_id)
    if (root / "engagement.yaml").exists() and not args.force:
        print(f"error: engagement already exists at {root} (use --force)")
        return 2
    ws = EngagementWorkspace.create(root, engagement)
    for name in ("environments.yaml", "reporting.yaml", "scope.yaml"):
        src = profile.path / name
        if src.exists():
            _shutil.copy2(src, ws.root / name)
    print(f"Applied profile '{profile.path}' -> engagement '{engagement.engagement_id}'")
    print(f"  workspace: {ws.root}/")
    print("Environment rules and reporting preferences copied into the workspace.")
    return 0


def cmd_environments_assign(args: argparse.Namespace) -> int:
    import yaml as _yaml

    from vapt_verify.profiles.environments import EnvironmentMapper, EnvironmentRule

    ws, err = _load_ws(args)
    if ws is None:
        return err
    if not ws.environments_file.exists():
        print("error: no environments.yaml in the workspace (apply a profile first)")
        return 2
    env_data = _yaml.safe_load(ws.environments_file.read_text(encoding="utf-8")) or {}
    rules = [
        EnvironmentRule(
            name=item["name"], cidrs=list(item.get("cidrs", [])),
            hostname_patterns=list(item.get("hostname_patterns", [])),
            critical=bool(item.get("critical", False)),
        )
        for item in env_data.get("environments", [])
    ]
    mapper = EnvironmentMapper(rules)

    assets = ws.load_assets()
    assigned = 0
    candidates: list[str] = []
    for asset in assets:
        result = mapper.assign(
            ips=asset.get("ip_addresses", []),
            hostnames=asset.get("hostnames", []) + asset.get("fqdns", []),
            asset_env=asset.get("environment", "unknown"),
        )
        if result.environment != "unknown":
            asset["environment"] = result.environment
            assigned += 1
        if result.candidate:
            note = "; ".join(result.notes)
            candidates.append(f"{asset['asset_id']} -> candidate '{result.candidate}' ({note})")
    ws.rewrite_assets(assets)
    ws.append_audit_event({"event": "environments_assign", "assigned": assigned})
    print(f"Assigned environments to {assigned}/{len(assets)} asset(s).")
    for line in candidates:
        print(f"  NEEDS CONFIRMATION: {line}")
    return 0


def cmd_retest(args: argparse.Namespace) -> int:
    from vapt_verify.retest import compare

    ws, err = _load_ws(args)
    if ws is None:
        return err
    findings = ws.load_findings()
    by_import: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        imp = f.get("provenance", {}).get("import_id", "")
        by_import.setdefault(imp, []).append(f)
    imports = list(by_import.keys())
    if len(imports) < 2:
        print("Need at least two imports to retest.")
        return 2
    baseline_id = args.baseline or imports[0]
    latest_id = args.latest or imports[-1]
    result = compare(
        baseline=by_import.get(baseline_id, []),
        latest=by_import.get(latest_id, []),
        baseline_import=baseline_id, latest_import=latest_id,
    )
    out = result.to_dict()
    print(f"Retest: baseline={baseline_id[:8]} latest={latest_id[:8]}")
    print(f"  still reported:     {out['counts']['still_reported']}")
    print(f"  no longer reported: {out['counts']['no_longer_reported']}")
    print(f"  newly reported:     {out['counts']['newly_reported']}")
    if result.no_longer_reported:
        print("  NOTE: 'no longer reported' findings are retained for review "
              "(candidate service-not-observed / possibly remediated), never deleted.")
    report_path = ws.root / "reports" / "retest.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    import json as _json

    report_path.write_text(_json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(f"  written: {report_path}")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    from vapt_verify.review.engine import ReviewEngine, ReviewError, detect_contradiction

    ws, err = _load_ws(args)
    if ws is None:
        return err
    rows = ws.load_findings()
    finding = next((r for r in rows if r["finding_id"] == args.finding), None)
    if finding is None:
        print(f"error: finding {args.finding} not found")
        return 2

    finding_evidence = [e for e in ws.load_evidence() if e.get("finding_id") == args.finding]
    contradiction, description = detect_contradiction(finding_evidence)

    # Display mode: no verdict supplied.
    if not args.verdict:
        print(f"finding:   {finding['finding_id']} ({finding.get('plugin_name')})")
        print(f"verdict:   {finding.get('verdict')}")
        print(f"evidence:  {len(finding_evidence)} record(s)")
        if contradiction:
            print(f"CONTRADICTION: {description}")
        decisions = [d for d in ws.load_decisions() if d.get("finding_id") == args.finding]
        for d in decisions:
            print(f"  decision: {d['verdict']} by {d['reviewer']}: {d['reviewer_rationale']}")
        return 0

    engine = ReviewEngine()
    try:
        decision = engine.record_decision(
            finding=finding,
            verdict=args.verdict,
            reviewer=args.reviewer,
            rationale=args.rationale,
            reviewer_roles=set(args.role),
            supporting_evidence_ids=args.supporting,
            contradicting_evidence_ids=args.contradicting,
            confidence=args.confidence,
        )
    except ReviewError as exc:
        print(f"REVIEW DENIED: {exc}")
        return 2

    ws.rewrite_findings(rows)
    ws.append_decision(decision.to_dict())
    ws.append_audit_event({
        "event": "review", "finding_id": args.finding, "verdict": decision.verdict,
        "reviewer": args.reviewer,
    })
    print(f"Recorded: {finding['finding_id']} -> {decision.verdict} by {args.reviewer}")
    if contradiction:
        print(f"NOTE (surfaced, not resolved): {description}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from vapt_verify.reporting.generator import ReportGenerator

    ws, err = _load_ws(args)
    if ws is None:
        return err
    gen = ReportGenerator(ws)
    out_dir = ws.root / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    fmts = ["markdown", "json", "csv", "html"] if args.format == "all" else [args.format]
    written: list[str] = []
    renderers = {
        "markdown": ("report.md", gen.markdown),
        "json": ("report.json", gen.json_report),
        "csv": ("verification_matrix.csv", gen.csv_matrix),
        "html": ("dashboard.html", gen.html_dashboard),
    }
    for fmt in fmts:
        filename, render = renderers[fmt]
        out_path = out_dir / filename
        out_path.write_text(render(), encoding="utf-8")
        written.append(str(out_path))
    for line in written:
        print(f"wrote {line}")
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    from vapt_verify.schema import SCHEMA_VERSION, is_current

    print(f"current schema version: {SCHEMA_VERSION}")
    if args.engagement:
        ws, err = _load_ws(args)
        if ws is None:
            return err
        found = ws.schema_version()
        state = "current" if is_current(found) else "NEEDS MIGRATION"
        print(f"engagement '{args.engagement}' schema: {found} ({state})")
        if not is_current(found):
            return 1
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    from vapt_verify.backup import create_backup

    ws, err = _load_ws(args)
    if ws is None:
        return err
    dest = create_backup(ws.root, args.output or None)
    print(f"Backup written: {dest}")
    print("A backup_manifest.json with per-file SHA-256 is embedded for integrity checking.")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    from vapt_verify.backup import restore_backup

    restored, errors = restore_backup(args.archive, args.base)
    print(f"Restored to: {restored}")
    if errors:
        print(f"INTEGRITY ERRORS ({len(errors)}):")
        for e in errors[:20]:
            print(f"  - {e}")
        return 1
    print("Integrity verified: all files match the backup manifest hashes.")
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    from vapt_verify.correlation import CorrelationEngine

    ws, err = _load_ws(args)
    if ws is None:
        return err
    findings = ws.load_findings()
    assets = ws.load_assets()
    report = CorrelationEngine().correlate(findings=findings, assets=assets)
    payload = report.to_dict()
    path = ws.save_correlation(payload)
    ws.append_audit_event({
        "event": "correlate",
        "finding_groups": len(report.finding_groups),
        "cross_scanner_groups": len(report.cross_scanner_groups),
    })

    counts = payload["counts"]
    print(f"Correlated {report.total_findings} finding(s) across "
          f"{len(report.scanners)} scanner(s): {', '.join(report.scanners) or '(none)'}")
    print(f"  finding groups:        {counts['finding_groups']}")
    print(f"  cross-scanner groups:  {counts['cross_scanner_groups']}")
    print(f"  grouped findings:      {counts['grouped_findings']}")
    print(f"  singleton findings:    {counts['singleton_findings']}")
    print(f"  asset identities:      {counts['asset_identities']}")
    print(f"  accounted:             {counts['accounted_findings']}/{report.total_findings}")
    if args.show:
        for group in report.finding_groups[: args.limit]:
            print(f"\n  [{group.confidence}] {group.group_id}  ({group.basis.value})")
            print(f"    {group.summary}")
            print(f"    members: {', '.join(group.member_finding_ids)}")
            print(f"    why: {group.rationale}")
    print(f"\n  written: {path}")
    if not report.totals_balance:
        print("ERROR: correlation did not account for every finding.")
        return 1
    print("OK: grouped + singletons = all findings. Nothing was merged or removed;")
    print("    groups are links over the findings, which remain independent records.")
    return 0


def cmd_identities(args: argparse.Namespace) -> int:
    from vapt_verify.correlation import CorrelationEngine

    ws, err = _load_ws(args)
    if ws is None:
        return err
    identities = CorrelationEngine().correlate_assets(ws.load_assets())
    if not identities:
        print("No candidate asset identities (no asset records share an IP, FQDN or MAC).")
        return 0
    print(f"{len(identities)} candidate asset identit(ies) - NOT merged, review required:")
    for identity in identities:
        print(f"\n  [{identity.confidence}] {identity.identity_id} ({identity.basis.value})")
        print(f"    assets:    {', '.join(identity.member_asset_ids)}")
        print(f"    ips:       {', '.join(identity.ip_addresses) or '(none)'}")
        print(f"    hostnames: {', '.join(identity.hostnames) or '(none)'}")
        for note in identity.notes:
            print(f"    note: {note}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    import json as _json

    from vapt_verify.correlation import ChangeKind, diff_import_sets

    ws, err = _load_ws(args)
    if ws is None:
        return err
    findings = ws.load_findings()
    by_import: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_import.setdefault(f.get("provenance", {}).get("import_id", ""), []).append(f)
    imports = list(by_import.keys())
    if len(imports) < 2:
        print("Need at least two imports to diff. Import another scan first.")
        return 2

    baseline_id = args.baseline or imports[0]
    latest_id = args.latest or imports[-1]
    if baseline_id not in by_import or latest_id not in by_import:
        print(f"error: unknown import id. Available: {', '.join(i[:12] for i in imports)}")
        return 2

    result = diff_import_sets(
        baseline=by_import[baseline_id], latest=by_import[latest_id],
        baseline_label=baseline_id, latest_label=latest_id,
    )
    payload = result.to_dict()
    counts = payload["counts"]
    print(f"Diff: baseline={baseline_id[:12]} ({result.baseline_count}) -> "
          f"latest={latest_id[:12]} ({result.latest_count})")
    for kind in ChangeKind:
        print(f"  {kind.value:<22} {counts[kind.value]}")
    if counts[ChangeKind.NO_LONGER_REPORTED.value]:
        print("\n  NOTE: 'no longer reported' findings are RETAINED. This is not evidence of")
        print("        remediation and not a false positive; a reviewer must assess them.")
        for entry in result.of_kind(ChangeKind.NO_LONGER_REPORTED)[: args.limit]:
            print(f"    - {entry.summary} [{entry.baseline_severity}]")

    out = ws.root / "reports" / "diff.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"\n  written: {out}")
    if not result.totals_balance:
        print("ERROR: diff did not account for every finding on both sides.")
        return 1
    return 0


def cmd_poc_export(args: argparse.Namespace) -> int:
    from vapt_verify.reporting.poc import PocBuilder, poc_index_markdown, poc_json
    from vapt_verify.security.redaction import Redactor

    ws, err = _load_ws(args)
    if ws is None:
        return err
    # Redaction is ON by default: these documents are the client-facing
    # deliverable. --no-redact exports raw and the document says so.
    redactor = None if args.no_redact else Redactor()
    builder = PocBuilder(ws, redactor=redactor)

    if args.finding:
        finding_ids = [args.finding]
    else:
        rows = ws.load_findings()
        if args.with_evidence_only:
            with_ev = {e.get("finding_id") for e in ws.load_evidence()}
            rows = [r for r in rows if r["finding_id"] in with_ev]
        if args.skip_informational:
            rows = [
                r for r in rows
                if str(r.get("severity_label", "")).upper() != "INFORMATIONAL"
            ]
        finding_ids = [r["finding_id"] for r in rows]
    if not finding_ids:
        print("No matching findings. (Use --all, or capture evidence first with 'run'.)")
        return 2

    out_dir = Path(args.output) if args.output else (ws.root / "reports" / "poc")
    out_dir.mkdir(parents=True, exist_ok=True)

    documents = []
    for finding_id in finding_ids:
        document = builder.build(finding_id, max_output_lines=args.max_output_lines)
        if document is None:
            print(f"warning: finding {finding_id} not found; skipped")
            continue
        documents.append(document)

    # Readable, severity-sorted filenames. A directory of poc-<hash>.md files
    # cannot be sorted by importance, read at a glance, or handed to a client.
    names = disambiguate(
        (
            d.finding_id,
            finding_basename(
                severity=d.severity, target=d.target, port=d.port,
                transport=d.transport, title=d.title,
            ),
            d.plugin_id,
        )
        for d in documents
    )

    written: list[str] = []
    for document in documents:
        stem = names[document.finding_id]
        if args.format in {"markdown", "all"}:
            path = out_dir / f"{stem}.md"
            path.write_text(document.to_markdown(), encoding="utf-8")
            written.append(str(path))
        if args.format in {"html", "all"}:
            path = out_dir / f"{stem}.html"
            path.write_text(document.to_html(), encoding="utf-8")
            written.append(str(path))

    if args.format in {"json", "all"} and documents:
        path = out_dir / "poc.json"
        path.write_text(poc_json(documents), encoding="utf-8")
        written.append(str(path))
    if len(documents) > 1 and args.format in {"markdown", "all"}:
        path = out_dir / "index.md"
        path.write_text(poc_index_markdown(documents), encoding="utf-8")
        written.append(str(path))

    with_evidence = sum(1 for d in documents if d.has_evidence)
    reviewed = sum(1 for d in documents if d.is_reviewed)
    masked = sum(sum(d.redaction_counts.values()) for d in documents)
    print(f"Exported {len(documents)} PoC document(s) to {out_dir}/")
    print(f"  with captured evidence: {with_evidence}")
    print(f"  reviewed (verdict set): {reviewed}")
    if args.no_redact:
        print("  sanitization:           NOT APPLIED (--no-redact) - review before sharing")
    else:
        print(f"  sanitization:           redaction applied, {masked} item(s) masked")
        print("                          (evidence files unmodified and still verifiable)")
    if with_evidence < len(documents):
        print(f"  evidence requests:      {len(documents) - with_evidence} "
              "(exported as requests, NOT as proofs)")
    if args.print_doc and documents:
        print("\n" + "=" * 70)
        print(documents[0].to_markdown())
    elif written:
        for written_path in written[:6]:
            print(f"  wrote {written_path}")
        if len(written) > 6:
            print(f"  ... and {len(written) - 6} more")
    return 0


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    from vapt_verify.security.integrity import IntegrityStatus, verify_evidence

    ws, err = _load_ws(args)
    if ws is None:
        return err
    rows = ws.load_evidence()
    if args.finding:
        rows = [e for e in rows if e.get("finding_id") == args.finding]
    if not rows:
        print("No evidence recorded yet.")
        return 0

    report = verify_evidence(rows)
    counts = report.to_dict()["counts"]
    print(f"Verified {len(report.checks)} evidence record(s):")
    for status in IntegrityStatus:
        print(f"  {status.value:<14} {counts[status.value]}")

    for check in report.of_status(IntegrityStatus.MODIFIED):
        print(f"\n  MODIFIED: {check.evidence_id} ({check.adapter}) for {check.finding_id}")
        print(f"    path:     {check.path}")
        print(f"    recorded: {check.recorded_sha256}")
        print(f"    computed: {check.computed_sha256}")
    for check in report.of_status(IntegrityStatus.MISSING):
        print(f"\n  MISSING:  {check.evidence_id} -> {check.path}")

    ws.append_audit_event({
        "event": "evidence_verify", "checked": len(report.checks),
        "is_intact": report.is_intact,
    })
    if not report.is_intact:
        print("\nFAILED: evidence integrity could not be confirmed. Chain of custody is broken "
              "for the records listed above; do not rely on them without investigation.")
        return 1
    print("\nOK: every stored evidence file matches its recorded SHA-256.")
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
        description=(
            "Convert scanner findings into Kali validation scripts and evidence-backed PoCs."
        ),
        epilog=(
            "A normal engagement, in order:\n"
            "  1. prepare <scan.nessus> --engagement <id>   import + build the kit\n"
            "  2. select --engagement <id>                  narrow to what you will verify\n"
            "  3. kit build --engagement <id>               regenerate scripts for that set\n"
            "     ... copy the kit to Kali, read commands.md, run ./run-all.sh, copy it back\n"
            "  4. kit import --engagement <id> --kit-dir <dir>   captures back in, hashed\n"
            "  5. review --engagement <id> --finding <id>   record a disposition (a human, "
            "not a tool)\n"
            "  6. poc export --engagement <id>              the deliverable\n"
            "  7. coverage --engagement <id>                did any finding disappear?\n"
            "\n"
            "This screen lists the core workflow. There are more commands - profiles, "
            "correlation,\nbackup, playbooks, in-process execution - and they all work: "
            "run `vapt-verify commands`."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument("--traceback", action="store_true",
                        help="show the full stack trace on unexpected errors")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add_command(name: str, **kwargs: Any) -> argparse.ArgumentParser:
        """Register a top-level command, listing only the core workflow in --help.

        Thirty-odd commands in one help screen tells an operator nothing about
        which five they need. Hiding one is a presentation decision and nothing
        more: every command below stays fully invocable, keeps its own
        ``--help``, and is listed by ``vapt-verify commands``.
        """
        if name not in CORE_COMMANDS:
            # argparse renders a literal "==SUPPRESS==" for a subparser choice
            # whose help is SUPPRESS; it only omits the row when `help` is
            # absent, because that is what decides whether a choice
            # pseudo-action is created at all.
            kwargs.pop("help", None)
        return sub.add_parser(name, **kwargs)

    def add_base(p: argparse.ArgumentParser) -> None:
        p.add_argument("--base", default="engagements", help="engagements base directory")

    def add_engagement(p: argparse.ArgumentParser) -> None:
        p.add_argument("--engagement", required=True, help="engagement id")

    add_command("version").set_defaults(func=cmd_version)
    add_command("doctor", help="check this machine can build and run kits").set_defaults(
        func=cmd_doctor
    )
    add_command(
        "commands", help="list every command, including the ones --help hides"
    ).set_defaults(func=cmd_commands)

    p_prepare = add_command(
        "prepare", help="turn a Nessus file into a Kali validation kit"
    )
    add_base(p_prepare)
    p_prepare.add_argument("scan_file", help="path to the .nessus file")
    p_prepare.add_argument("--engagement", required=True, help="new engagement id")
    p_prepare.add_argument("--client-alias", default="")
    p_prepare.add_argument("--authorisation-reference", default="")
    p_prepare.add_argument(
        "--output", default="", help="kit directory (default: engagement/kali-kit)"
    )
    p_prepare.add_argument("--allow-parse-failures", action="store_true")
    p_prepare.add_argument(
        "--include-informational", action="store_true",
        help="also generate validation scripts for informational findings "
             "(default: list them, do not scan them)",
    )
    p_prepare.set_defaults(func=cmd_prepare)

    p_init = add_command("init", help="initialize an engagements base directory")
    add_base(p_init)
    p_init.set_defaults(func=cmd_init)

    p_eng = add_command("engagement", help="manage engagements")
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

    p_import = add_command("import", help="import a scanner file (or 'import status')")
    add_base(p_import)
    add_engagement(p_import)
    p_import.add_argument("target", help="path to a scan file, or the literal 'status'")
    p_import.add_argument("--format", default="auto",
                          choices=["auto", "nessus", "nessus-csv", "nmap-xml", "normalized-json"])
    p_import.add_argument("--allow-parse-failures", action="store_true")
    p_import.add_argument("--allow-suppressions", type=int, default=0)
    p_import.set_defaults(func=cmd_import_dispatch)

    p_inv = add_command("inventory", help="browse normalized inventory")
    inv_sub = p_inv.add_subparsers(dest="inventory_command", required=True)
    p_inv_assets = inv_sub.add_parser("assets")
    add_base(p_inv_assets)
    add_engagement(p_inv_assets)
    p_inv_assets.set_defaults(func=cmd_inventory_assets)
    p_inv_services = inv_sub.add_parser("services")
    add_base(p_inv_services)
    add_engagement(p_inv_services)
    p_inv_services.set_defaults(func=cmd_inventory_services)

    p_find = add_command("findings", help="list or show findings")
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

    add_command("capabilities", help="list available verification tools").set_defaults(
        func=cmd_capabilities
    )

    p_classify = add_command("classify", help="classify findings and assign dispositions")
    add_base(p_classify)
    add_engagement(p_classify)
    p_classify.set_defaults(func=cmd_classify)

    p_explain = add_command("explain", help="explain a finding's classification")
    add_base(p_explain)
    add_engagement(p_explain)
    p_explain.add_argument("finding_id")
    p_explain.set_defaults(func=cmd_explain)

    p_cov = add_command("coverage", help="coverage report (accounted / imported)")
    add_base(p_cov)
    add_engagement(p_cov)
    p_cov.set_defaults(func=cmd_coverage)

    p_plan = add_command("plan", help="build verification plans")
    add_base(p_plan)
    add_engagement(p_plan)
    p_plan.add_argument("--finding", default="")
    p_plan.add_argument("--asset", default="")
    p_plan.set_defaults(func=cmd_plan)

    p_run = add_command("run", help="run a verification adapter (dry-run by default)")
    add_base(p_run)
    add_engagement(p_run)
    p_run.add_argument("--finding", required=True)
    p_run.add_argument("--approve", action="store_true",
                       help="actually execute (default is dry-run)")
    p_run.add_argument("--operator", default="unknown")
    p_run.add_argument("--timeout", type=float, default=120.0)
    p_run.set_defaults(func=cmd_run)

    p_pb = add_command(
        "playbook", help="declarative ordered verification pipelines"
    )
    pb_sub = p_pb.add_subparsers(dest="playbook_command", required=True)
    p_pb_list = pb_sub.add_parser("list", help="list installed playbooks")
    p_pb_list.set_defaults(func=cmd_playbook_list)
    p_pb_show = pb_sub.add_parser("show", help="show a playbook's steps and conditions")
    p_pb_show.add_argument("playbook", help="playbook id")
    p_pb_show.set_defaults(func=cmd_playbook_show)
    p_pb_validate = pb_sub.add_parser(
        "validate", help="check that every step can run and every condition can fire"
    )
    p_pb_validate.add_argument("--path", default="",
                               help="validate a directory of playbook YAML instead of the "
                                    "installed library")
    p_pb_validate.set_defaults(func=cmd_playbook_validate)

    p_select = add_command(
        "select",
        help="choose which findings become capture scripts (interactive by default)",
    )
    add_base(p_select)
    add_engagement(p_select)
    p_select.add_argument("--interactive", action="store_true",
                          help="pick from a list (the default when no criteria are given)")
    p_select.add_argument("--all", action="store_true", help="select every finding")
    p_select.add_argument("--severity", default="",
                          help="comma-separated severities, e.g. CRITICAL,HIGH")
    p_select.add_argument("--host", default="", help="comma-separated hosts/IPs")
    p_select.add_argument("--plugin", default="", help="comma-separated Nessus plugin ids")
    p_select.add_argument("--service", default="", help="comma-separated service names")
    p_select.add_argument("--port", default="", help="comma-separated ports")
    p_select.add_argument("--search", default="",
                          help="substring of the finding name/synopsis/service")
    p_select.add_argument("--finding", action="append", default=[],
                          help="an explicit finding id (repeatable)")
    p_select.add_argument("--add", action="store_true",
                          help="add matches to the current selection instead of replacing it")
    p_select.add_argument("--remove", action="store_true",
                          help="remove matches from the current selection")
    p_select.add_argument("--show", action="store_true", help="print the current selection")
    p_select.add_argument("--clear", action="store_true",
                          help="drop the selection so every finding is covered again")
    p_select.add_argument("--note", default="", help="why this scope was chosen")
    p_select.add_argument("--operator", default="unknown")
    p_select.set_defaults(func=cmd_select)

    p_kit = add_command("kit", help="build a Kali kit or import its returned evidence")
    kit_sub = p_kit.add_subparsers(dest="kit_command", required=True)
    p_kit_build = kit_sub.add_parser("build", help="generate Kali Bash validation scripts")
    add_base(p_kit_build)
    add_engagement(p_kit_build)
    p_kit_build.add_argument("--output", default="")
    p_kit_build.add_argument(
        "--force", action="store_true", help="refresh generated files; preserve evidence/"
    )
    p_kit_build.add_argument(
        "--all-findings", action="store_true",
        help="ignore any saved selection and cover every finding",
    )
    p_kit_build.add_argument(
        "--include-informational", action="store_true",
        help="also generate validation scripts for informational findings "
             "(default: list them, do not scan them)",
    )
    p_kit_build.set_defaults(func=cmd_kit_build)
    p_kit_import = kit_sub.add_parser(
        "import", help="verify and import evidence captured on Kali"
    )
    add_base(p_kit_import)
    add_engagement(p_kit_import)
    p_kit_import.add_argument("kit_dir", help="returned Kali kit directory")
    p_kit_import.add_argument("--operator", default="", help="override captured operator")
    p_kit_import.set_defaults(func=cmd_kit_import)

    p_ev = add_command("evidence", help="manage evidence")
    ev_sub = p_ev.add_subparsers(dest="evidence_command", required=True)
    p_ev_req = ev_sub.add_parser("request", help="show the evidence a finding requires")
    add_base(p_ev_req)
    add_engagement(p_ev_req)
    p_ev_req.add_argument("finding")
    p_ev_req.set_defaults(func=cmd_evidence_request)
    p_ev_add = ev_sub.add_parser("add", help="attach externally-collected evidence")
    add_base(p_ev_add)
    add_engagement(p_ev_add)
    p_ev_add.add_argument("finding")
    p_ev_add.add_argument("--file", required=True)
    p_ev_add.add_argument("--tool", default="")
    p_ev_add.add_argument("--note", default="")
    p_ev_add.add_argument("--operator", default="unknown")
    p_ev_add.set_defaults(func=cmd_evidence_add)
    p_ev_verify = ev_sub.add_parser(
        "verify", help="re-hash stored evidence against recorded SHA-256 (chain of custody)"
    )
    add_base(p_ev_verify)
    add_engagement(p_ev_verify)
    p_ev_verify.add_argument("--finding", default="", help="limit to one finding")
    p_ev_verify.set_defaults(func=cmd_evidence_verify)

    p_legacy = add_command("legacy", help="legacy-compatibility commands")
    legacy_sub = p_legacy.add_subparsers(dest="legacy_command", required=True)
    p_legacy_nmap = legacy_sub.add_parser("export-nmap", help="export legacy-style Nmap commands")
    add_base(p_legacy_nmap)
    add_engagement(p_legacy_nmap)
    p_legacy_nmap.add_argument("--output", default="")
    p_legacy_nmap.set_defaults(func=cmd_legacy_export_nmap)

    p_profile = add_command("profile", help="engagement profiles")
    profile_sub = p_profile.add_subparsers(dest="profile_command", required=True)
    p_profile_show = profile_sub.add_parser("show", help="show a profile")
    p_profile_show.add_argument("path")
    p_profile_show.set_defaults(func=cmd_profile_show)
    p_profile_apply = profile_sub.add_parser("apply", help="create an engagement from a profile")
    add_base(p_profile_apply)
    p_profile_apply.add_argument("path")
    p_profile_apply.add_argument("--id", default="")
    p_profile_apply.add_argument("--force", action="store_true")
    p_profile_apply.set_defaults(func=cmd_profile_apply)

    p_env = add_command("environments", help="environment mapping")
    env_sub = p_env.add_subparsers(dest="environments_command", required=True)
    p_env_assign = env_sub.add_parser("assign", help="assign environments to assets")
    add_base(p_env_assign)
    add_engagement(p_env_assign)
    p_env_assign.set_defaults(func=cmd_environments_assign)

    p_retest = add_command("retest", help="compare two imports (retest)")
    add_base(p_retest)
    add_engagement(p_retest)
    p_retest.add_argument("--baseline", default="")
    p_retest.add_argument("--latest", default="")
    p_retest.set_defaults(func=cmd_retest)

    p_report = add_command("report", help="generate reports")
    add_base(p_report)
    add_engagement(p_report)
    p_report.add_argument("--format", choices=["markdown", "json", "csv", "html", "all"],
                          default="all")
    p_report.set_defaults(func=cmd_report)

    p_review = add_command("review", help="review a finding and record a decision")
    add_base(p_review)
    add_engagement(p_review)
    p_review.add_argument("finding")
    p_review.add_argument("--verdict", default="", help="omit to show current state")
    p_review.add_argument("--reviewer", default="unknown")
    p_review.add_argument("--rationale", default="")
    p_review.add_argument("--role", action="append", default=[],
                          help="reviewer role (repeatable); 'lead'/'approver' may approve FPs")
    p_review.add_argument("--supporting", action="append", default=[])
    p_review.add_argument("--contradicting", action="append", default=[])
    p_review.add_argument("--confidence", default="medium")
    p_review.set_defaults(func=cmd_review)

    p_poc = add_command("poc", help="export report-ready PoC documents")
    poc_sub = p_poc.add_subparsers(dest="poc_command", required=True)
    p_poc_export = poc_sub.add_parser(
        "export", help="assemble scanner claim + command + capture + verdict per finding"
    )
    add_base(p_poc_export)
    add_engagement(p_poc_export)
    p_poc_export.add_argument("--finding", default="", help="a single finding id")
    p_poc_export.add_argument("--all", action="store_true", help="every finding (default)")
    p_poc_export.add_argument("--with-evidence-only", action="store_true",
                              help="skip findings that have no captured evidence")
    p_poc_export.add_argument("--skip-informational", action="store_true",
                              help="omit informational findings from the exported pack")
    p_poc_export.add_argument("--format", choices=["markdown", "html", "json", "all"],
                              default="markdown")
    p_poc_export.add_argument("--output", default="", help="output directory")
    p_poc_export.add_argument("--max-output-lines", type=int, default=60)
    p_poc_export.add_argument(
        "--no-redact", action="store_true",
        help="export raw, without masking credentials/keys/tokens (default: redact)",
    )
    p_poc_export.add_argument("--print", dest="print_doc", action="store_true",
                              help="also print the first document to stdout")
    p_poc_export.set_defaults(func=cmd_poc_export)

    p_corr = add_command("correlate", help="link findings across scanners (never merges)")
    add_base(p_corr)
    add_engagement(p_corr)
    p_corr.add_argument("--show", action="store_true", help="print each group")
    p_corr.add_argument("--limit", type=int, default=20)
    p_corr.set_defaults(func=cmd_correlate)

    p_ident = add_command("identities", help="candidate asset identities across sources")
    add_base(p_ident)
    add_engagement(p_ident)
    p_ident.set_defaults(func=cmd_identities)

    p_diff = add_command("diff", help="diff two import sets")
    add_base(p_diff)
    add_engagement(p_diff)
    p_diff.add_argument("--baseline", default="")
    p_diff.add_argument("--latest", default="")
    p_diff.add_argument("--limit", type=int, default=20)
    p_diff.set_defaults(func=cmd_diff)

    p_schema = add_command("schema", help="show/verify schema version")
    add_base(p_schema)
    p_schema.add_argument("--engagement", default="")
    p_schema.set_defaults(func=cmd_schema)

    p_backup = add_command("backup", help="back up an engagement (with integrity manifest)")
    add_base(p_backup)
    add_engagement(p_backup)
    p_backup.add_argument("--output", default="")
    p_backup.set_defaults(func=cmd_backup)

    p_restore = add_command("restore", help="restore an engagement backup")
    add_base(p_restore)
    p_restore.add_argument("archive")
    p_restore.set_defaults(func=cmd_restore)

    p_sec = add_command("security", help="repository safety checks")
    sec_sub = p_sec.add_subparsers(dest="security_command", required=True)
    p_sec_scan = sec_sub.add_parser("scan", help="scan for client-data leaks")
    p_sec_scan.add_argument("--root", default=".")
    p_sec_scan.set_defaults(func=cmd_security_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Make output encoding-proof before anything can print (Windows cp1252).
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        return cmd_version(args)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2

    show_traceback = bool(getattr(args, "traceback", False))
    try:
        result: int = func(args)
    except KeyboardInterrupt:
        print("\nInterrupted by operator. No further action was taken.")
        return 130
    except SourceFileError as exc:
        print(f"error: {exc}")
        return 2
    except RecipeLibraryError as exc:
        print(f"error: {exc}")
        return 2
    except (OSError, ValueError) as exc:
        # Operator-facing failure: report it plainly rather than dumping a
        # traceback, but keep the full detail one flag away.
        if show_traceback:
            raise
        print(f"error: {type(exc).__name__}: {exc}")
        print("Re-run with --traceback for the full stack trace, "
              "or run 'vapt-verify doctor' to check the environment.")
        return 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
