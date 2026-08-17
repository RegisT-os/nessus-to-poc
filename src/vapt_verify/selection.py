"""Choosing which findings become PoC capture scripts.

Generating commands for all 200 findings in a scan is rarely what an operator
wants at the client site. This module lets them pick -- by severity, host,
plugin, free text, explicit id, or interactively -- and saves that choice so
``kit build`` and ``poc export`` both honour the same set.

The load-bearing rule: **a selection is a scoping decision, not a deletion.**
Deselecting a finding does not remove it from the inventory, does not give it a
disposition, and does not make it a false positive. Every artefact generated
from a selection states how many findings were left out, and ``coverage`` still
reports against the full imported set. The question "did any finding disappear?"
must still answer "no -- 180 were deselected by <operator> on <date>, and they
are all still here awaiting a disposition."
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SELECTION_SCHEMA = "vapt-verify/selection/1"


@dataclass
class SelectionCriteria:
    """A declarative description of what to select.

    Recorded alongside the result so a reader can tell a deliberate
    "CRITICAL and HIGH only" from an arbitrary hand-picked list.
    """

    severities: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    search: str = ""
    finding_ids: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not any([
            self.severities, self.hosts, self.plugins, self.services,
            self.ports, self.search, self.finding_ids,
        ])

    def describe(self) -> str:
        parts = []
        if self.severities:
            parts.append("severity in " + ",".join(self.severities))
        if self.hosts:
            parts.append("host in " + ",".join(self.hosts))
        if self.plugins:
            parts.append("plugin in " + ",".join(self.plugins))
        if self.services:
            parts.append("service in " + ",".join(self.services))
        if self.ports:
            parts.append("port in " + ",".join(str(p) for p in self.ports))
        if self.search:
            parts.append(f"name/synopsis contains {self.search!r}")
        if self.finding_ids:
            parts.append(f"{len(self.finding_ids)} explicit finding id(s)")
        return "; ".join(parts) or "no criteria"

    def matches(self, row: dict[str, Any]) -> bool:
        """Criteria are OR'd across kinds: any match selects the finding.

        Operators think in additive terms -- "the criticals, plus everything on
        the DMZ box, plus that one SSL finding" -- so intersecting would produce
        an empty set for exactly the request they meant.
        """
        if self.finding_ids and row.get("finding_id") in self.finding_ids:
            return True
        if self.severities and str(row.get("severity_label", "")).upper() in self.severities:
            return True
        if self.plugins and str(row.get("plugin_id", "")) in self.plugins:
            return True
        if self.services and str(row.get("service", "")).lower() in self.services:
            return True
        if self.ports and int(row.get("port", 0) or 0) in self.ports:
            return True
        if self.hosts and finding_host(row).lower() in self.hosts:
            return True
        if self.search:
            haystack = " ".join([
                str(row.get("plugin_name", "")),
                str(row.get("synopsis", "")),
                str(row.get("service", "")),
            ]).lower()
            if self.search.lower() in haystack:
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "severities": list(self.severities),
            "hosts": list(self.hosts),
            "plugins": list(self.plugins),
            "services": list(self.services),
            "ports": list(self.ports),
            "search": self.search,
            "finding_ids": list(self.finding_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SelectionCriteria:
        return cls(
            severities=[s.upper() for s in data.get("severities", [])],
            hosts=[h.lower() for h in data.get("hosts", [])],
            plugins=[str(p) for p in data.get("plugins", [])],
            services=[s.lower() for s in data.get("services", [])],
            ports=[int(p) for p in data.get("ports", [])],
            search=data.get("search", ""),
            finding_ids=list(data.get("finding_ids", [])),
        )

    @classmethod
    def parse(
        cls,
        *,
        severity: str = "",
        host: str = "",
        plugin: str = "",
        service: str = "",
        port: str = "",
        search: str = "",
        finding: list[str] | None = None,
    ) -> SelectionCriteria:
        """Build criteria from comma-separated CLI values."""

        def split(value: str) -> list[str]:
            return [v.strip() for v in value.split(",") if v.strip()]

        ports: list[int] = []
        for raw in split(port):
            try:
                ports.append(int(raw))
            except ValueError as exc:
                raise ValueError(f"not a port number: {raw!r}") from exc

        return cls(
            severities=[s.upper() for s in split(severity)],
            hosts=[h.lower() for h in split(host)],
            plugins=split(plugin),
            services=[s.lower() for s in split(service)],
            ports=ports,
            search=search.strip(),
            finding_ids=list(finding or []),
        )


@dataclass
class Selection:
    """The findings chosen for capture, plus how and by whom."""

    engagement_id: str
    selected_ids: list[str] = field(default_factory=list)
    total_findings: int = 0
    operator: str = "unknown"
    created_at: str = field(default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat())
    criteria: SelectionCriteria = field(default_factory=SelectionCriteria)
    method: str = "criteria"  # "criteria" | "interactive" | "all" | "edited"
    note: str = ""
    #: What the last change did, in words. After an ``--add``/``--remove`` the
    #: stored criteria describe *that operation*, not the resulting set, and
    #: showing them as if they described the selection is a lie an operator
    #: would act on. This says which it is.
    last_operation: str = ""

    @property
    def count(self) -> int:
        return len(self.selected_ids)

    @property
    def deselected_count(self) -> int:
        return max(0, self.total_findings - self.count)

    @property
    def covers_everything(self) -> bool:
        return self.deselected_count == 0

    def contains(self, finding_id: str) -> bool:
        return finding_id in set(self.selected_ids)

    def apply(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chosen = set(self.selected_ids)
        return [r for r in rows if r.get("finding_id") in chosen]

    def summary(self) -> str:
        """One line stating the scope decision, for generated artefacts."""
        if self.covers_everything:
            return f"All {self.total_findings} imported finding(s) are covered."
        return (
            f"{self.count} of {self.total_findings} imported finding(s) selected by "
            f"{self.operator} on {self.created_at[:10]}. The remaining "
            f"{self.deselected_count} were deselected: they remain in the engagement, "
            "are not false positives, and still require a disposition."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SELECTION_SCHEMA,
            "engagement_id": self.engagement_id,
            "selected_ids": list(self.selected_ids),
            "selected_count": self.count,
            "total_findings": self.total_findings,
            "deselected_count": self.deselected_count,
            "operator": self.operator,
            "created_at": self.created_at,
            "criteria": self.criteria.to_dict(),
            "criteria_description": self.criteria.describe(),
            "method": self.method,
            "note": self.note,
            "last_operation": self.last_operation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Selection:
        return cls(
            engagement_id=data.get("engagement_id", ""),
            selected_ids=list(data.get("selected_ids", [])),
            total_findings=int(data.get("total_findings", 0)),
            operator=data.get("operator", "unknown"),
            created_at=data.get("created_at", ""),
            criteria=SelectionCriteria.from_dict(data.get("criteria", {})),
            method=data.get("method", "criteria"),
            note=data.get("note", ""),
            last_operation=data.get("last_operation", ""),
        )

    # -- persistence --------------------------------------------------------

    @staticmethod
    def path_for(workspace_root: str | Path) -> Path:
        return Path(workspace_root) / "normalized" / "selection.json"

    def save(self, workspace_root: str | Path) -> Path:
        path = self.path_for(workspace_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return path

    @classmethod
    def load(cls, workspace_root: str | Path) -> Selection | None:
        path = cls.path_for(workspace_root)
        if not path.exists():
            return None
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    @classmethod
    def clear(cls, workspace_root: str | Path) -> bool:
        path = cls.path_for(workspace_root)
        if path.exists():
            path.unlink()
            return True
        return False


def finding_host(row: dict[str, Any]) -> str:
    """The target address recorded on a finding, for display and host matching."""
    props = row.get("host_properties", {})
    if isinstance(props, dict):
        value = props.get("host-ip") or props.get("host-fqdn") or ""
        if isinstance(value, list):
            value = value[0] if value else ""
        if value:
            return str(value)
    return str(row.get("asset_id", ""))


def select_by_criteria(
    rows: list[dict[str, Any]],
    criteria: SelectionCriteria,
    *,
    engagement_id: str,
    operator: str = "unknown",
    note: str = "",
) -> Selection:
    matched = [r for r in rows if criteria.matches(r)] if not criteria.is_empty else list(rows)
    return Selection(
        engagement_id=engagement_id,
        selected_ids=[r["finding_id"] for r in matched],
        total_findings=len(rows),
        operator=operator,
        criteria=criteria,
        method="criteria" if not criteria.is_empty else "all",
        note=note,
        last_operation=(
            f"selected everything matching: {criteria.describe()}"
            if not criteria.is_empty
            else "selected every imported finding"
        ),
    )


def sort_key(row: dict[str, Any]) -> tuple[int, str, int, str]:
    """Worst-first, then grouped by host and port -- the order an operator reads."""
    severity = -int(row.get("severity", 0) or 0)
    return (
        severity,
        finding_host(row),
        int(row.get("port", 0) or 0),
        str(row.get("plugin_name", "")),
    )
