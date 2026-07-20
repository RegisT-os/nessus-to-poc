"""Normalized JSON(L) reimport.

Round-trips a previously exported normalized finding set (``findings.jsonl`` or a
JSON array of finding dicts) back into an ImportResult, preserving each finding's
id, fingerprint and provenance. This makes normalized exports a stable
interchange format between engagements/tools.
"""

from __future__ import annotations

import datetime as _dt
import json
import uuid
from pathlib import Path
from typing import Any

from vapt_verify.importers.base import ImportResult
from vapt_verify.models.asset import Asset
from vapt_verify.models.enums import ObservationSource
from vapt_verify.models.finding import Finding
from vapt_verify.models.service import ServiceObservation
from vapt_verify.utilities.hashing import sha256_file
from vapt_verify.utilities.ids import service_id


class NormalizedJsonImporter:
    source_scanner = "normalized-json"

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id

    def _read(self, path: Path) -> list[dict[str, Any]]:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        if text[0] == "[":
            data = json.loads(text)
            return list(data) if isinstance(data, list) else []
        # JSONL
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def import_file(self, path: str | Path) -> ImportResult:
        source = Path(path)
        file_hash = sha256_file(source)
        rows = self._read(source)
        import_id = uuid.uuid4().hex
        now = _dt.datetime.now(_dt.UTC).isoformat()

        result = ImportResult(
            import_id=import_id, source_scanner=self.source_scanner,
            source_file=source.name, source_file_hash=file_hash, import_timestamp=now,
        )
        result.source_report_item_count = len(rows)

        assets: dict[str, Asset] = {}
        service_keys: set[str] = set()
        for row in rows:
            finding = Finding.from_dict(row)
            result.findings.append(finding)
            self._ensure_asset(assets, finding)
            if finding.port > 0:
                sid = service_id(finding.asset_id, port=finding.port,
                                 transport=finding.transport.value)
                if sid not in service_keys:
                    service_keys.add(sid)
                    result.services.append(ServiceObservation(
                        service_id=sid, asset_id=finding.asset_id, port=finding.port,
                        transport=finding.transport, service_name=finding.service,
                        observation_source=ObservationSource.SCANNER_REFERENCED,
                        observation_timestamp=now, confidence="reimported",
                    ))
        result.source_host_count = len(assets)
        result.assets = list(assets.values())
        return result

    def _ensure_asset(self, assets: dict[str, Asset], finding: Finding) -> None:
        if finding.asset_id in assets:
            return
        props = finding.host_properties
        ip = props.get("host-ip") if isinstance(props, dict) else ""
        ips = [str(ip)] if ip else []
        assets[finding.asset_id] = Asset(
            asset_id=finding.asset_id,
            primary_key=str(ip or finding.asset_id),
            ip_addresses=ips,
            source_provenance=["normalized-json:reimport"],
        )
