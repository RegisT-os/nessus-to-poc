"""Per-finding PoC (proof-of-concept) document builder.

Assembles one report-ready document per finding that pairs, in order:

1. the original scanner claim (with source file + hash, so it is traceable),
2. what verification was performed (exact argv command, operator, timestamps),
3. the captured output, verbatim,
4. the parsed observations,
5. the reviewer's verdict and rationale,
6. integrity data (evidence SHA-256 and path),
7. the limitations of the method used.

Methodology guardrails baked into the output (docs/METHODOLOGY.md):

* **No evidence, no proof.** A finding with no captured evidence produces an
  *evidence request* document that says so plainly and lists what is needed. It
  never renders as an empty PoC that could be mistaken for a completed one.
* **Unreviewed is stated, not implied.** If no reviewer has assigned a verdict,
  the document says the capture is unreviewed rather than presenting it as a
  confirmation.
* **The method's limits travel with the evidence.** Where the selected recipe
  marks Nmap as supporting/inappropriate, or lists known limitations, those
  appear in the document so a reader cannot over-read the capture.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Any

from vapt_verify.models.enums import Verdict

# How much captured output to inline before truncating (full text always
# remains in the evidence file, which is referenced by path and hash).
DEFAULT_MAX_OUTPUT_LINES = 60


@dataclass
class PocEvidenceBlock:
    evidence_id: str
    adapter: str
    tool_name: str
    command: str
    operator: str
    start_timestamp: str
    end_timestamp: str
    exit_code: int | None
    timed_out: bool
    output: str
    truncated: bool
    observations: dict[str, Any] = field(default_factory=dict)
    sha256: str = ""
    raw_evidence_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "adapter": self.adapter,
            "tool_name": self.tool_name,
            "command": self.command,
            "operator": self.operator,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "output": self.output,
            "truncated": self.truncated,
            "observations": self.observations,
            "sha256": self.sha256,
            "raw_evidence_path": self.raw_evidence_path,
        }


@dataclass
class PocDocument:
    finding_id: str
    title: str
    severity: str
    asset_id: str
    target: str
    port: int
    transport: str
    # Original scanner claim
    scanner: str
    plugin_id: str
    plugin_output: str
    synopsis: str
    source_file: str
    source_file_hash: str
    scan_date: str
    # Verification
    evidence: list[PocEvidenceBlock] = field(default_factory=list)
    # Review
    verdict: str = Verdict.UNREVIEWED.value
    reviewer: str = ""
    reviewer_rationale: str = ""
    decision_timestamp: str = ""
    # Method context
    method_summary: str = ""
    nmap_role: str = ""
    limitations: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    engagement_id: str = ""
    # Sanitization. Redaction is applied to this *document* only; the stored
    # evidence files keep their original bytes and remain hash-verifiable.
    redacted: bool = False
    redaction_counts: dict[str, int] = field(default_factory=dict)

    @property
    def sanitization_status(self) -> str:
        if not self.redacted:
            return "unsanitized"
        return "redacted" if self.redaction_counts else "redaction_applied_no_matches"

    @property
    def redaction_note(self) -> str:
        if not self.redacted:
            return (
                "Redaction was NOT applied to this document. Review it for credentials, "
                "keys, tokens or internal identifiers before sharing externally."
            )
        if not self.redaction_counts:
            return "Redaction was applied; no sensitive patterns matched."
        total = sum(self.redaction_counts.values())
        detail = ", ".join(
            f"{name} x{count}" for name, count in sorted(self.redaction_counts.items())
        )
        return (
            f"Redaction applied: {total} item(s) masked ({detail}). The stored evidence "
            "files are unmodified and remain verifiable against their recorded SHA-256."
        )

    @property
    def has_evidence(self) -> bool:
        return bool(self.evidence)

    @property
    def is_reviewed(self) -> bool:
        return self.verdict != Verdict.UNREVIEWED.value

    @property
    def status_line(self) -> str:
        """One-line, non-overclaiming statement of where this PoC stands."""
        if not self.has_evidence:
            return (
                "EVIDENCE REQUEST - no verification evidence has been captured for this "
                "finding yet. This document states what is required; it is not a proof."
            )
        if not self.is_reviewed:
            return (
                "CAPTURED, NOT REVIEWED - evidence exists but no reviewer has assigned a "
                "verdict. The capture below does not by itself confirm the finding."
            )
        return f"REVIEWED - verdict: {self.verdict}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "engagement_id": self.engagement_id,
            "title": self.title,
            "severity": self.severity,
            "asset_id": self.asset_id,
            "target": self.target,
            "port": self.port,
            "transport": self.transport,
            "status": self.status_line,
            "has_evidence": self.has_evidence,
            "is_reviewed": self.is_reviewed,
            "scanner_claim": {
                "scanner": self.scanner,
                "plugin_id": self.plugin_id,
                "synopsis": self.synopsis,
                "plugin_output": self.plugin_output,
                "source_file": self.source_file,
                "source_file_hash": self.source_file_hash,
                "scan_date": self.scan_date,
            },
            "verification": [e.to_dict() for e in self.evidence],
            "review": {
                "verdict": self.verdict,
                "reviewer": self.reviewer,
                "rationale": self.reviewer_rationale,
                "timestamp": self.decision_timestamp,
            },
            "method": {
                "summary": self.method_summary,
                "nmap_role": self.nmap_role,
                "limitations": self.limitations,
                "required_evidence": self.required_evidence,
            },
            "sanitization": {
                "status": self.sanitization_status,
                "redacted": self.redacted,
                "counts": self.redaction_counts,
                "note": self.redaction_note,
            },
        }

    # -- renderers ----------------------------------------------------------

    def to_markdown(self) -> str:
        loc = f"{self.port}/{self.transport}" if self.port else "host-level (port 0)"
        out: list[str] = []
        out.append(f"# PoC: {self.title}")
        out.append("")
        out.append(f"> **{self.status_line}**")
        out.append("")
        out.append("| | |\n| --- | --- |")
        out.append(f"| Finding ID | `{self.finding_id}` |")
        out.append(f"| Severity | {self.severity} |")
        out.append(f"| Target | `{self.target}` ({self.asset_id}) |")
        out.append(f"| Location | {loc} |")
        out.append(f"| Engagement | {self.engagement_id} |")
        out.append(f"| Sanitization | {self.sanitization_status} |")
        out.append("")
        out.append(f"_{self.redaction_note}_")
        out.append("")

        out.append("## 1. Original scanner claim")
        out.append("")
        out.append(f"- **Scanner:** {self.scanner}  ")
        out.append(f"- **Plugin ID:** {self.plugin_id or '(none)'}  ")
        out.append(f"- **Scan date:** {self.scan_date or '(not recorded)'}  ")
        out.append(f"- **Source file:** `{self.source_file}` "
                   f"(SHA-256 `{self.source_file_hash[:16]}...`)")
        out.append("")
        if self.synopsis:
            out.append(f"{self.synopsis}")
            out.append("")
        if self.plugin_output:
            out.append("Scanner output:")
            out.append("")
            out.append("```text")
            out.append(self.plugin_output.strip())
            out.append("```")
            out.append("")

        out.append("## 2. Independent verification")
        out.append("")
        if not self.has_evidence:
            out.append("**No verification evidence has been captured for this finding.**")
            out.append("")
            if self.method_summary:
                out.append(f"Planned method: {self.method_summary}")
                out.append("")
            if self.required_evidence:
                out.append("Evidence required before this finding can be resolved:")
                out.append("")
                for item in self.required_evidence:
                    out.append(f"- {item}")
                out.append("")
        for index, block in enumerate(self.evidence, start=1):
            out.append(f"### 2.{index} {block.tool_name} (`{block.adapter}`)")
            out.append("")
            out.append(f"- **Operator:** {block.operator}  ")
            out.append(f"- **Started:** {block.start_timestamp}  ")
            out.append(f"- **Finished:** {block.end_timestamp}  ")
            out.append(f"- **Exit code:** {block.exit_code}"
                       f"{' (TIMED OUT)' if block.timed_out else ''}  ")
            out.append(f"- **Evidence SHA-256:** `{block.sha256}`")
            out.append("")
            out.append("Command executed:")
            out.append("")
            out.append("```console")
            out.append(f"$ {block.command}")
            out.append("```")
            out.append("")
            out.append("Captured output:")
            out.append("")
            out.append("```text")
            out.append(block.output.rstrip() or "(no output)")
            if block.truncated:
                out.append("... [truncated - see full evidence file]")
            out.append("```")
            out.append("")
            if block.observations:
                out.append("Parsed observations:")
                out.append("")
                for key, value in sorted(block.observations.items()):
                    out.append(f"- `{key}`: {value}")
                out.append("")
            if block.raw_evidence_path:
                out.append(f"Full evidence: `{block.raw_evidence_path}`")
                out.append("")

        out.append("## 3. Assessment")
        out.append("")
        out.append(f"- **Verdict:** {self.verdict}  ")
        out.append(f"- **Reviewer:** {self.reviewer or '(none - not yet reviewed)'}  ")
        if self.decision_timestamp:
            out.append(f"- **Decided:** {self.decision_timestamp}")
        out.append("")
        if self.reviewer_rationale:
            out.append(f"**Rationale:** {self.reviewer_rationale}")
        else:
            out.append(
                "_No reviewer rationale recorded. A tool exit code does not constitute a "
                "verdict; this finding still requires reviewer assessment._"
            )
        out.append("")

        out.append("## 4. Limitations of this verification")
        out.append("")
        if self.nmap_role:
            out.append(f"- Nmap's role for this finding class: **{self.nmap_role}**.")
        for limitation in self.limitations:
            out.append(f"- {limitation}")
        out.append(
            "- Absence of a reproduction is not proof of absence: it may reflect network "
            "position, filtering, credentials, virtual-host/SNI selection, or post-scan "
            "remediation."
        )
        out.append("")
        return "\n".join(out)

    def to_html(self) -> str:
        def esc(value: object) -> str:
            return html.escape(str(value))

        blocks: list[str] = []
        for block in self.evidence:
            obs = "".join(
                f"<li><code>{esc(k)}</code>: {esc(v)}</li>"
                for k, v in sorted(block.observations.items())
            )
            blocks.append(
                f"<h3>{esc(block.tool_name)} <span class='muted'>({esc(block.adapter)})</span></h3>"
                f"<p class='muted'>operator {esc(block.operator)} &middot; "
                f"{esc(block.start_timestamp)} &rarr; {esc(block.end_timestamp)} &middot; "
                f"exit {esc(block.exit_code)}</p>"
                f"<pre class='cmd'>$ {esc(block.command)}</pre>"
                f"<pre class='out'>{esc(block.output.rstrip() or '(no output)')}"
                f"{'&#10;... [truncated]' if block.truncated else ''}</pre>"
                f"{f'<ul>{obs}</ul>' if obs else ''}"
                f"<p class='muted'>SHA-256 <code>{esc(block.sha256)}</code></p>"
            )
        if not blocks:
            blocks.append(
                "<p><strong>No verification evidence has been captured for this "
                "finding.</strong></p>"
                + (
                    "<ul>" + "".join(f"<li>{esc(r)}</li>" for r in self.required_evidence) + "</ul>"
                    if self.required_evidence
                    else ""
                )
            )

        limitations = "".join(f"<li>{esc(x)}</li>" for x in self.limitations)
        loc = f"{self.port}/{self.transport}" if self.port else "host-level (port 0)"
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PoC - {esc(self.title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 60rem; line-height: 1.45; }}
  .status {{ padding: .6rem .8rem; border-left: 4px solid currentColor; margin: 1rem 0;
             background: color-mix(in srgb, currentColor 8%, transparent); font-weight: 600; }}
  pre {{ padding: .7rem; overflow-x: auto; background: #8881; border-radius: 4px; }}
  pre.cmd {{ font-weight: 600; }}
  table {{ border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ border: 1px solid #8886; padding: .3rem .6rem; text-align: left; }}
  .muted {{ opacity: .75; font-size: .9rem; }}
</style></head><body>
<h1>PoC: {esc(self.title)}</h1>
<div class="status">{esc(self.status_line)}</div>
<table>
<tr><th>Finding ID</th><td><code>{esc(self.finding_id)}</code></td></tr>
<tr><th>Severity</th><td>{esc(self.severity)}</td></tr>
<tr><th>Target</th><td><code>{esc(self.target)}</code></td></tr>
<tr><th>Location</th><td>{esc(loc)}</td></tr>
<tr><th>Sanitization</th><td>{esc(self.sanitization_status)}</td></tr>
</table>
<p class="muted">{esc(self.redaction_note)}</p>
<h2>1. Original scanner claim</h2>
<p class="muted">{esc(self.scanner)} &middot; plugin {esc(self.plugin_id or 'n/a')} &middot;
 source <code>{esc(self.source_file)}</code> (SHA-256 {esc(self.source_file_hash[:16])}...)</p>
<p>{esc(self.synopsis)}</p>
<pre>{esc(self.plugin_output.strip() or '(no scanner output recorded)')}</pre>
<h2>2. Independent verification</h2>
{''.join(blocks)}
<h2>3. Assessment</h2>
<p><strong>Verdict:</strong> {esc(self.verdict)}<br>
<strong>Reviewer:</strong> {esc(self.reviewer or '(none - not yet reviewed)')}</p>
<p>{esc(self.reviewer_rationale) or
   '<em>No reviewer rationale recorded. A tool exit code does not constitute a verdict.</em>'}</p>
<h2>4. Limitations</h2>
<ul>{limitations}
<li>Absence of a reproduction is not proof of absence: it may reflect network position,
filtering, credentials, virtual-host/SNI selection, or post-scan remediation.</li></ul>
</body></html>
"""


class PocBuilder:
    """Builds :class:`PocDocument` objects from a persisted workspace.

    ``redactor`` masks sensitive spans in the *rendered document only*; the
    stored evidence files are never rewritten, so they stay verifiable against
    their recorded hashes. Pass ``redactor=None`` to export raw (the document
    then says explicitly that redaction was not applied).
    """

    def __init__(self, workspace: Any, redactor: Any | None = None) -> None:
        self.ws = workspace
        self.redactor = redactor

    def build(
        self, finding_id: str, *, max_output_lines: int = DEFAULT_MAX_OUTPUT_LINES
    ) -> PocDocument | None:
        finding = next(
            (f for f in self.ws.load_findings() if f["finding_id"] == finding_id), None
        )
        if finding is None:
            return None

        assets = {a["asset_id"]: a for a in self.ws.load_assets()}
        asset = assets.get(finding.get("asset_id", ""), {})
        target = ""
        props = finding.get("host_properties", {})
        if isinstance(props, dict):
            raw_ip = props.get("host-ip")
            target = str(raw_ip[0] if isinstance(raw_ip, list) and raw_ip else raw_ip or "")
        if not target:
            target = str(asset.get("primary_key", finding.get("asset_id", "")))

        provenance = finding.get("provenance", {}) or {}
        document = PocDocument(
            finding_id=finding_id,
            engagement_id=self.ws.root.name,
            title=str(finding.get("plugin_name", "(unnamed finding)")),
            severity=str(finding.get("severity_label", "")),
            asset_id=str(finding.get("asset_id", "")),
            target=target,
            port=int(finding.get("port", 0) or 0),
            transport=str(finding.get("transport", "")),
            scanner=str(provenance.get("source_scanner", "unknown")),
            plugin_id=str(finding.get("plugin_id", "")),
            plugin_output=str(finding.get("plugin_output", "")),
            synopsis=str(finding.get("synopsis", "")),
            source_file=str(provenance.get("source_file", "")),
            source_file_hash=str(provenance.get("source_file_hash", "")),
            scan_date=str(provenance.get("scan_date", "")),
            verdict=str(finding.get("verdict", Verdict.UNREVIEWED.value)),
        )

        document.evidence = [
            self._evidence_block(e, max_output_lines)
            for e in self.ws.load_evidence()
            if e.get("finding_id") == finding_id
        ]

        decisions = [d for d in self.ws.load_decisions() if d.get("finding_id") == finding_id]
        if decisions:
            latest = decisions[-1]
            document.verdict = str(latest.get("verdict", document.verdict))
            document.reviewer = str(latest.get("reviewer", ""))
            document.reviewer_rationale = str(latest.get("reviewer_rationale", ""))
            document.decision_timestamp = str(latest.get("timestamp", ""))

        self._attach_method_context(document, finding)
        self._apply_redaction(document)
        return document

    def _apply_redaction(self, document: PocDocument) -> None:
        """Mask sensitive spans in the document. Evidence files are untouched."""
        if self.redactor is None:
            document.redacted = False
            return
        document.redacted = True
        counts: dict[str, int] = {}

        def merge(by_rule: dict[str, int]) -> None:
            for name, count in by_rule.items():
                counts[name] = counts.get(name, 0) + count

        claim = self.redactor.redact(document.plugin_output)
        document.plugin_output = claim.text
        merge(claim.by_rule)

        for block in document.evidence:
            output = self.redactor.redact(block.output)
            block.output = output.text
            merge(output.by_rule)
            command = self.redactor.redact(block.command)
            block.command = command.text
            merge(command.by_rule)
            block.observations, obs = self.redactor.redact_mapping(block.observations)
            merge(obs.by_rule)

        rationale = self.redactor.redact(document.reviewer_rationale)
        document.reviewer_rationale = rationale.text
        merge(rationale.by_rule)

        document.redaction_counts = counts

    def _evidence_block(self, e: dict[str, Any], max_lines: int) -> PocEvidenceBlock:
        combined = (e.get("stdout") or "") + (
            ("\n" + e["stderr"]) if e.get("stderr") else ""
        )
        lines = combined.splitlines()
        truncated = len(lines) > max_lines
        return PocEvidenceBlock(
            evidence_id=str(e.get("evidence_id", "")),
            adapter=str(e.get("adapter", "")),
            tool_name=str(e.get("tool_name") or e.get("adapter", "")),
            command=str(e.get("sanitized_command", "")),
            operator=str(e.get("operator", "")),
            start_timestamp=str(e.get("start_timestamp", "")),
            end_timestamp=str(e.get("end_timestamp", "")),
            exit_code=e.get("exit_code"),
            timed_out=bool(e.get("timed_out", False)),
            output="\n".join(lines[:max_lines]),
            truncated=truncated,
            observations=dict(e.get("parsed_observations", {}) or {}),
            sha256=str(e.get("sha256", "")),
            raw_evidence_path=str(e.get("raw_evidence_path", "")),
        )

    def _attach_method_context(self, document: PocDocument, finding: dict[str, Any]) -> None:
        """Carry the selected recipe's limits into the document."""
        from vapt_verify.classification.classifier import Classifier
        from vapt_verify.classification.models import Capabilities
        from vapt_verify.models.finding import Finding
        from vapt_verify.recipes.library import RecipeLibrary

        try:
            library = RecipeLibrary.load_builtin()
            classification = Classifier(library, Capabilities.detect()).classify(
                Finding.from_dict(finding)
            )
        except Exception:
            return
        recipe = library.by_id(classification.selected_recipe_id)
        document.nmap_role = classification.nmap_role
        document.limitations = list(classification.known_limitations)
        document.method_summary = classification.selected_recipe_title
        if recipe is not None:
            document.required_evidence = [
                f"[{step.adapter}] {step.description}" for step in recipe.manual_steps
            ] or list(classification.expected_confirming_evidence)


def poc_index_markdown(documents: list[PocDocument]) -> str:
    """A contents page for a bundle of exported PoCs."""
    lines = ["# PoC index", "", "| Finding | Severity | Target | Evidence | Verdict |",
             "| --- | --- | --- | ---: | --- |"]
    for doc in documents:
        lines.append(
            f"| {doc.title} | {doc.severity} | `{doc.target}` | "
            f"{len(doc.evidence)} | {doc.verdict} |"
        )
    lines.append("")
    reviewed = sum(1 for d in documents if d.is_reviewed)
    with_evidence = sum(1 for d in documents if d.has_evidence)
    lines.append(
        f"{len(documents)} finding(s): {with_evidence} with captured evidence, "
        f"{reviewed} reviewed. Findings without evidence are exported as evidence "
        f"requests, not as proofs."
    )
    lines.append("")
    return "\n".join(lines)


def poc_json(documents: list[PocDocument]) -> str:
    return json.dumps([d.to_dict() for d in documents], indent=2, sort_keys=True)
