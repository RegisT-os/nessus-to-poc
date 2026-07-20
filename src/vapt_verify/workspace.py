"""Engagement workspace and evidence-bundle layout (task section 18).

A workspace is a directory tree rooted at ``engagements/<engagement_id>/``. It
holds the immutable original imports, the normalized JSONL inventory, import
manifests and reconciliation records. Original imported files are never
modified: they are copied in and hashed.

The whole ``engagements/`` tree is git-ignored — it can contain real client
findings and must never be committed.
"""

from __future__ import annotations

import datetime as _dt
import json
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vapt_verify import __version__
from vapt_verify.importers.base import ImportResult
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation.gate import ReconciliationReport
from vapt_verify.utilities.jsonl import append_jsonl, read_jsonl


@dataclass
class ImportRecord:
    """Summary of a persisted import, returned to callers/CLI."""

    import_id: str
    original_path: Path
    manifest_path: Path
    reconciliation_path: Path


class EngagementWorkspace:
    """Filesystem home for one engagement's imports, inventory and evidence."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # -- layout -------------------------------------------------------------

    @property
    def engagement_file(self) -> Path:
        return self.root / "engagement.yaml"

    @property
    def scope_file(self) -> Path:
        return self.root / "scope.yaml"

    @property
    def imports_originals(self) -> Path:
        return self.root / "imports" / "originals"

    @property
    def imports_manifests(self) -> Path:
        return self.root / "imports" / "manifests"

    @property
    def normalized_dir(self) -> Path:
        return self.root / "normalized"

    @property
    def assets_file(self) -> Path:
        return self.normalized_dir / "assets.jsonl"

    @property
    def services_file(self) -> Path:
        return self.normalized_dir / "services.jsonl"

    @property
    def findings_file(self) -> Path:
        return self.normalized_dir / "findings.jsonl"

    @property
    def reconciliation_dir(self) -> Path:
        return self.root / "reconciliation"

    @property
    def audit_log(self) -> Path:
        return self.root / "audit" / "import_audit.jsonl"

    def _all_dirs(self) -> list[Path]:
        return [
            self.imports_originals,
            self.imports_manifests,
            self.normalized_dir,
            self.reconciliation_dir,
            self.reconciliation_dir / "parse_failures",
            self.root / "plans",
            self.root / "reports",
            self.root / "audit",
            self.root / "logs",
        ]

    def ensure_layout(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for d in self._all_dirs():
            d.mkdir(parents=True, exist_ok=True)

    # -- lifecycle ----------------------------------------------------------

    @classmethod
    def create(cls, root: str | Path, engagement: Engagement) -> EngagementWorkspace:
        ws = cls(root)
        ws.ensure_layout()
        engagement.evidence_root = str(ws.root)
        engagement.save(ws.engagement_file)
        if not ws.scope_file.exists():
            ws.scope_file.write_text(
                "# Scope enforcement is implemented in v0.3. Until then this file\n"
                "# documents intended scope only and is NOT enforced.\n"
                "approved_cidrs: []\napproved_hostnames: []\nexcluded_targets: []\n",
                encoding="utf-8",
            )
        return ws

    @classmethod
    def load(cls, root: str | Path) -> EngagementWorkspace:
        ws = cls(root)
        if not ws.engagement_file.exists():
            raise FileNotFoundError(f"No engagement.yaml under {ws.root}")
        return ws

    def engagement(self) -> Engagement:
        return Engagement.load(self.engagement_file)

    # -- import persistence -------------------------------------------------

    def persist_import(
        self,
        *,
        source_path: str | Path,
        result: ImportResult,
        reconciliation: ReconciliationReport,
    ) -> ImportRecord:
        self.ensure_layout()
        source_path = Path(source_path)
        stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        short_hash = result.source_file_hash[:12]

        # 1. Preserve the original, never modifying it.
        original_dest = self.imports_originals / f"{stamp}_{short_hash}_{source_path.name}"
        shutil.copy2(source_path, original_dest)

        # 2. Append normalized inventory (append => repeated scans stay distinct).
        append_jsonl(self.assets_file, (a.to_dict() for a in result.assets))
        append_jsonl(self.services_file, (s.to_dict() for s in result.services))
        append_jsonl(self.findings_file, (f.to_dict() for f in result.findings))

        # 3. Write the import manifest.
        manifest = {
            "import_id": result.import_id,
            "source_scanner": result.source_scanner,
            "source_file": result.source_file,
            "preserved_original": str(original_dest.relative_to(self.root)),
            "source_file_hash": result.source_file_hash,
            "import_timestamp": result.import_timestamp,
            "tool_versions": {
                "vapt_verify": __version__,
                "python": platform.python_version(),
                "importer": "nessus_xml",
            },
            "counts": {
                "source_host_count": result.source_host_count,
                "source_report_item_count": result.source_report_item_count,
                "normalized_finding_count": result.normalized_finding_count,
                "asset_count": len(result.assets),
                "service_count": len(result.services),
                "parse_failure_count": result.parse_failure_count,
            },
            "statistics": reconciliation.statistics,
            "reconciliation": {
                "status": reconciliation.status.value,
                "is_balanced": reconciliation.is_balanced,
                "unexplained_difference": reconciliation.unexplained_difference,
            },
            "warnings": result.warnings,
        }
        manifest_path = self.imports_manifests / f"{result.import_id}.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        # 4. Write the reconciliation record and any parse failures.
        reconciliation_path = self.reconciliation_dir / f"{result.import_id}.json"
        reconciliation_path.write_text(
            json.dumps(reconciliation.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        if result.parse_failures:
            pf_path = self.reconciliation_dir / "parse_failures" / f"{result.import_id}.json"
            pf_path.write_text(
                json.dumps(
                    [pf.to_dict() for pf in result.parse_failures], indent=2, sort_keys=True
                ),
                encoding="utf-8",
            )

        # 5. Append an immutable audit entry.
        self._append_audit(result, reconciliation, original_dest)

        return ImportRecord(
            import_id=result.import_id,
            original_path=original_dest,
            manifest_path=manifest_path,
            reconciliation_path=reconciliation_path,
        )

    def _append_audit(
        self,
        result: ImportResult,
        reconciliation: ReconciliationReport,
        original_dest: Path,
    ) -> None:
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "event": "import",
            "timestamp": _dt.datetime.now(_dt.UTC).isoformat(),
            "import_id": result.import_id,
            "source_file": result.source_file,
            "source_file_hash": result.source_file_hash,
            "preserved_original": str(original_dest.relative_to(self.root)),
            "source_report_item_count": result.source_report_item_count,
            "normalized_finding_count": result.normalized_finding_count,
            "parse_failure_count": result.parse_failure_count,
            "reconciliation_status": reconciliation.status.value,
        }
        with open(self.audit_log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    # -- inventory reads ----------------------------------------------------

    def load_findings(self) -> list[dict[str, Any]]:
        return list(read_jsonl(self.findings_file))

    def load_assets(self) -> list[dict[str, Any]]:
        """Return deduplicated assets (union by asset_id across imports)."""
        merged: dict[str, dict[str, Any]] = {}
        for row in read_jsonl(self.assets_file):
            merged[row["asset_id"]] = row
        return list(merged.values())

    def load_services(self) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for row in read_jsonl(self.services_file):
            merged[row["service_id"]] = row
        return list(merged.values())

    def load_reconciliations(self) -> list[dict[str, Any]]:
        reports: list[dict[str, Any]] = []
        if self.reconciliation_dir.exists():
            for path in sorted(self.reconciliation_dir.glob("*.json")):
                reports.append(json.loads(path.read_text(encoding="utf-8")))
        return reports
