"""Import-set diffing (v2.0).

Compares two sets of normalized findings — typically two imports of the same
scope, or the same scope seen by two different scanners.

The v2.0 guardrail: **"no longer reported" is a state, never a deletion.** A
finding present in the baseline and absent from the latest set is reported as
``no_longer_reported`` and keeps its full record; it never disappears and it is
never auto-classified as a false positive or as remediated. Interpreting it
remains a reviewer decision (see docs/METHODOLOGY.md).

Matching is correlation-aware rather than fingerprint-only, so a diff still
works when the two sets come from different scanners: findings are matched on
plugin+location, then shared CVE+location, then normalized title+location.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vapt_verify.correlation.engine import normalize_title


class ChangeKind(Enum):
    STILL_REPORTED = "still_reported"
    NO_LONGER_REPORTED = "no_longer_reported"
    NEWLY_REPORTED = "newly_reported"
    SEVERITY_CHANGED = "severity_changed"


@dataclass
class DiffEntry:
    kind: ChangeKind
    match_key: str
    summary: str
    baseline_finding_ids: list[str] = field(default_factory=list)
    latest_finding_ids: list[str] = field(default_factory=list)
    baseline_severity: str = ""
    latest_severity: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "match_key": self.match_key,
            "summary": self.summary,
            "baseline_finding_ids": self.baseline_finding_ids,
            "latest_finding_ids": self.latest_finding_ids,
            "baseline_severity": self.baseline_severity,
            "latest_severity": self.latest_severity,
            "note": self.note,
        }


@dataclass
class ImportSetDiff:
    baseline_label: str
    latest_label: str
    baseline_count: int
    latest_count: int
    entries: list[DiffEntry] = field(default_factory=list)

    def of_kind(self, kind: ChangeKind) -> list[DiffEntry]:
        return [e for e in self.entries if e.kind is kind]

    @property
    def accounted_baseline(self) -> int:
        """Every baseline finding appears in exactly one entry."""
        return sum(
            len(e.baseline_finding_ids)
            for e in self.entries
            if e.kind is not ChangeKind.NEWLY_REPORTED
        )

    @property
    def accounted_latest(self) -> int:
        return sum(
            len(e.latest_finding_ids)
            for e in self.entries
            if e.kind is not ChangeKind.NO_LONGER_REPORTED
        )

    @property
    def totals_balance(self) -> bool:
        return (
            self.accounted_baseline == self.baseline_count
            and self.accounted_latest == self.latest_count
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline_label,
            "latest": self.latest_label,
            "baseline_count": self.baseline_count,
            "latest_count": self.latest_count,
            "counts": {k.value: len(self.of_kind(k)) for k in ChangeKind},
            "accounted_baseline": self.accounted_baseline,
            "accounted_latest": self.accounted_latest,
            "totals_balance": self.totals_balance,
            "entries": [e.to_dict() for e in self.entries],
            "interpretation_note": (
                "'no_longer_reported' means the latest scan did not report the condition. "
                "It is NOT evidence of remediation and NOT a false positive; the original "
                "finding is retained and requires reviewer assessment."
            ),
        }


def _match_keys(finding: dict[str, Any]) -> list[str]:
    """Correlation-aware match keys, strongest first."""
    asset = str(finding.get("asset_id", ""))
    port = int(finding.get("port", 0) or 0)
    transport = str(finding.get("transport", ""))
    location = f"{asset}:{port}:{transport}"
    keys: list[str] = []
    plugin_id = str(finding.get("plugin_id", "") or "")
    if plugin_id:
        keys.append(f"pl:{plugin_id}:{location}")
    for cve in sorted({str(c).strip().upper() for c in finding.get("cves", []) if str(c).strip()}):
        keys.append(f"cve:{cve}:{location}")
    title = normalize_title(str(finding.get("plugin_name", "")))
    if title:
        keys.append(f"ti:{title}:{location}")
    return keys or [f"id:{finding.get('finding_id', '')}"]


def _index(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        for key in _match_keys(finding):
            index[key].append(finding)
    return index


def diff_import_sets(
    *,
    baseline: list[dict[str, Any]],
    latest: list[dict[str, Any]],
    baseline_label: str = "baseline",
    latest_label: str = "latest",
) -> ImportSetDiff:
    """Diff two finding sets, retaining every record on both sides."""
    result = ImportSetDiff(
        baseline_label=baseline_label,
        latest_label=latest_label,
        baseline_count=len(baseline),
        latest_count=len(latest),
    )
    latest_index = _index(latest)
    matched_latest: set[str] = set()
    matched_baseline: set[str] = set()

    for finding in baseline:
        fid = finding["finding_id"]
        if fid in matched_baseline:
            continue
        partner: dict[str, Any] | None = None
        used_key = ""
        for key in _match_keys(finding):
            for candidate in latest_index.get(key, []):
                if candidate["finding_id"] not in matched_latest:
                    partner, used_key = candidate, key
                    break
            if partner is not None:
                break

        name = str(finding.get("plugin_name", "(unnamed)"))
        if partner is None:
            matched_baseline.add(fid)
            result.entries.append(
                DiffEntry(
                    kind=ChangeKind.NO_LONGER_REPORTED,
                    match_key=_match_keys(finding)[0],
                    summary=name,
                    baseline_finding_ids=[fid],
                    baseline_severity=str(finding.get("severity_label", "")),
                    note=(
                        "Not reported in the latest set. The finding is retained; this is not "
                        "evidence of remediation and not a false positive."
                    ),
                )
            )
            continue

        matched_baseline.add(fid)
        matched_latest.add(partner["finding_id"])
        base_sev = str(finding.get("severity_label", ""))
        new_sev = str(partner.get("severity_label", ""))
        kind = ChangeKind.SEVERITY_CHANGED if base_sev != new_sev else ChangeKind.STILL_REPORTED
        result.entries.append(
            DiffEntry(
                kind=kind,
                match_key=used_key,
                summary=name,
                baseline_finding_ids=[fid],
                latest_finding_ids=[partner["finding_id"]],
                baseline_severity=base_sev,
                latest_severity=new_sev,
                note=(
                    "Severity differs between the two sets; confirm which assessment applies."
                    if kind is ChangeKind.SEVERITY_CHANGED
                    else ""
                ),
            )
        )

    for finding in latest:
        fid = finding["finding_id"]
        if fid in matched_latest:
            continue
        result.entries.append(
            DiffEntry(
                kind=ChangeKind.NEWLY_REPORTED,
                match_key=_match_keys(finding)[0],
                summary=str(finding.get("plugin_name", "(unnamed)")),
                latest_finding_ids=[fid],
                latest_severity=str(finding.get("severity_label", "")),
                note="Present in the latest set only.",
            )
        )
    return result
