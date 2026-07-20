"""Report generation from a persisted engagement workspace (task section 20/21).

Reports lead with **coverage** (accounted / imported), never an automation
percentage, and use defensible language. Four renderings share one data model:
Markdown, JSON, a CSV verification matrix and a self-contained HTML dashboard.
"""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass
from typing import Any

from vapt_verify.coverage import compute_coverage
from vapt_verify.workspace import EngagementWorkspace


@dataclass
class ReportData:
    engagement: dict[str, Any]
    coverage: dict[str, Any]
    findings: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    decisions: list[dict[str, Any]]
    reconciliations: list[dict[str, Any]]


class ReportGenerator:
    def __init__(self, workspace: EngagementWorkspace) -> None:
        self.ws = workspace

    def gather(self) -> ReportData:
        findings = self.ws.load_findings()
        return ReportData(
            engagement=self.ws.engagement().to_dict(),
            coverage=compute_coverage(findings).to_dict(),
            findings=findings,
            evidence=self.ws.load_evidence(),
            decisions=self.ws.load_decisions(),
            reconciliations=self.ws.load_reconciliations(),
        )

    # -- JSON ---------------------------------------------------------------

    def json_report(self) -> str:
        data = self.gather()
        evidence_by_finding: dict[str, int] = {}
        for e in data.evidence:
            evidence_by_finding[e.get("finding_id", "")] = (
                evidence_by_finding.get(e.get("finding_id", ""), 0) + 1
            )
        return json.dumps(
            {
                "engagement": data.engagement,
                "coverage": data.coverage,
                "finding_count": len(data.findings),
                "evidence_count": len(data.evidence),
                "decision_count": len(data.decisions),
                "evidence_by_finding": evidence_by_finding,
                "findings": data.findings,
            },
            indent=2,
            sort_keys=True,
        )

    # -- CSV verification matrix -------------------------------------------

    def csv_matrix(self) -> str:
        data = self.gather()
        counts: dict[str, int] = {}
        for e in data.evidence:
            fid = e.get("finding_id", "")
            counts[fid] = counts.get(fid, 0) + 1
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "finding_id", "plugin_id", "plugin_name", "asset_id", "port", "transport",
            "severity", "disposition", "verdict", "evidence_count",
        ])
        for f in data.findings:
            writer.writerow([
                f.get("finding_id", ""), f.get("plugin_id", ""), f.get("plugin_name", ""),
                f.get("asset_id", ""), f.get("port", ""), f.get("transport", ""),
                f.get("severity_label", ""), f.get("disposition", ""), f.get("verdict", ""),
                counts.get(f.get("finding_id", ""), 0),
            ])
        return out.getvalue()

    # -- Markdown -----------------------------------------------------------

    def markdown(self) -> str:
        data = self.gather()
        cov = data.coverage
        eng = data.engagement
        title = eng.get("client_alias") or eng.get("engagement_id")
        lines: list[str] = []
        lines.append(f"# Verification Report — {title}")
        lines.append("")
        lines.append(f"- Engagement: `{eng.get('engagement_id')}`  ")
        lines.append(f"- Type: {eng.get('engagement_type') or 'n/a'}  ")
        lines.append(f"- Data classification: {eng.get('data_classification')}")
        lines.append("")
        lines.append("## Coverage (primary metric)")
        lines.append("")
        lines.append(f"**Accounted for: {cov['accounted']} / {cov['total_imported']} findings "
                     f"({'BALANCED' if cov['totals_balance'] else 'IMBALANCED'}).**")
        lines.append("")
        lines.append("| Disposition | Count |")
        lines.append("| --- | ---: |")
        for k, v in sorted(cov["by_disposition"].items()):
            lines.append(f"| {k} | {v} |")
        lines.append("")
        lines.append("| Verdict | Count |")
        lines.append("| --- | ---: |")
        for k, v in sorted(cov["by_verdict"].items()):
            lines.append(f"| {k} | {v} |")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        lines.append("| Finding | Sev | Port | Disposition | Verdict |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in data.findings:
            name = str(f.get("plugin_name", ""))[:60]
            lines.append(
                f"| {name} | {f.get('severity_label')} | {f.get('port')}/{f.get('transport')} "
                f"| {f.get('disposition')} | {f.get('verdict')} |"
            )
        lines.append("")
        lines.append("## Evidence index")
        lines.append("")
        if data.evidence:
            lines.append("| Evidence | Finding | Adapter | Exit | SHA-256 |")
            lines.append("| --- | --- | --- | --- | --- |")
            for e in data.evidence:
                lines.append(
                    f"| {e.get('evidence_id', '')[:8]} | {e.get('finding_id', '')[:12]} "
                    f"| {e.get('adapter')} | {e.get('exit_code')} | {str(e.get('sha256'))[:12]} |"
                )
        else:
            lines.append("_No execution evidence recorded yet._")
        lines.append("")
        lines.append("## Note on interpretation")
        lines.append("")
        lines.append(
            "Coverage — not automation — is the quality metric. A tool exit code never sets a "
            "verdict; a closed port means the service was not observable, not that a finding is a "
            "false positive; and no finding was removed without an explicit, reviewable "
            "disposition.")
        lines.append("")
        return "\n".join(lines)

    # -- HTML dashboard (self-contained) -----------------------------------

    def html_dashboard(self) -> str:
        data = self.gather()
        cov = data.coverage
        eng = data.engagement

        def rows(d: dict[str, int]) -> str:
            return "".join(
                f"<tr><td>{html.escape(str(k))}</td><td class='n'>{v}</td></tr>"
                for k, v in sorted(d.items())
            )

        finding_rows = "".join(
            "<tr>"
            f"<td>{html.escape(str(f.get('plugin_name', ''))[:80])}</td>"
            f"<td>{html.escape(str(f.get('severity_label', '')))}</td>"
            f"<td>{f.get('port')}/{html.escape(str(f.get('transport', '')))}</td>"
            f"<td>{html.escape(str(f.get('disposition', '')))}</td>"
            f"<td>{html.escape(str(f.get('verdict', '')))}</td>"
            "</tr>"
            for f in data.findings
        )
        balanced = "BALANCED" if cov["totals_balance"] else "IMBALANCED"
        title = html.escape(str(eng.get("client_alias") or eng.get("engagement_id")))
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verification Report — {title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.4; }}
  h1 {{ margin-bottom: .2rem; }}
  .metric {{ font-size: 1.4rem; font-weight: 700; margin: 1rem 0; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; overflow-x: auto; }}
  th, td {{ border: 1px solid #8886; padding: .3rem .5rem; text-align: left; font-size: .9rem; }}
  td.n, th.n {{ text-align: right; }}
  .wrap {{ overflow-x: auto; }}
  .muted {{ opacity: .75; font-size: .85rem; }}
</style></head>
<body>
<h1>Verification Report — {title}</h1>
<div class="muted">Engagement <code>{html.escape(str(eng.get('engagement_id')))}</code>
 · classification {html.escape(str(eng.get('data_classification')))}</div>
<div class="metric">Coverage: {cov['accounted']} / {cov['total_imported']} findings accounted for
 ({balanced})</div>
<div class="wrap"><h2>By disposition</h2><table>
<tr><th>Disposition</th><th class="n">Count</th></tr>
{rows(cov['by_disposition'])}</table></div>
<div class="wrap"><h2>By verdict</h2><table>
<tr><th>Verdict</th><th class="n">Count</th></tr>
{rows(cov['by_verdict'])}</table></div>
<div class="wrap"><h2>Findings ({len(data.findings)})</h2>
<table>
<tr><th>Finding</th><th>Sev</th><th>Port</th><th>Disposition</th><th>Verdict</th></tr>
{finding_rows}</table></div>
<p class="muted">Coverage, not automation, is the quality metric. A tool exit code never sets a
verdict; a closed port means the service was not observable, not that a finding is a false
positive. No finding was removed without an explicit, reviewable disposition.</p>
</body></html>
"""
