"""Nmap XML (-oX) importer.

A discovery import: each *open* port becomes an informational service-exposure
finding with ``source_scanner = "nmap"``. This never contaminates the core
model — it produces the same normalized Finding shape as every other importer,
and open ports here are genuine verification-observed exposure, recorded as
informational findings for inventory/context (task section 12.16).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from defusedxml.ElementTree import iterparse

from vapt_verify.importers.base import ImportResult
from vapt_verify.importers.common import normalize_records
from vapt_verify.utilities.hashing import sha256_file


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[1] if "}" in tag else tag


class NmapXmlImporter:
    source_scanner = "nmap"

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id

    def import_file(self, path: str | Path) -> ImportResult:
        source = Path(path)
        file_hash = sha256_file(source)
        records: list[dict[str, Any]] = []

        current_addr = ""
        current_hostnames: list[str] = []
        context = iterparse(str(source), events=("start", "end"))
        for event, elem in context:
            tag = _localname(elem.tag)
            if event == "start" and tag == "host":
                current_addr = ""
                current_hostnames = []
            elif event == "end" and tag == "address":
                if elem.get("addrtype") in {"ipv4", "ipv6"}:
                    current_addr = elem.get("addr", "")
            elif event == "end" and tag == "hostname":
                name = elem.get("name")
                if name:
                    current_hostnames.append(name)
            elif event == "end" and tag == "port":
                record = self._port_record(elem, current_addr, current_hostnames)
                if record is not None:
                    records.append(record)
            elif event == "end" and tag == "host":
                elem.clear()

        return normalize_records(
            engagement_id=self.engagement_id,
            source_scanner=self.source_scanner,
            source_file=source.name,
            source_file_hash=file_hash,
            records=records,
        )

    def _port_record(
        self, elem: Any, addr: str, hostnames: list[str]
    ) -> dict[str, Any] | None:
        state = ""
        service = ""
        product = ""
        version = ""
        for child in elem:
            ctag = _localname(child.tag)
            if ctag == "state":
                state = child.get("state", "")
            elif ctag == "service":
                service = child.get("name", "")
                product = child.get("product", "")
                version = child.get("version", "")
        if state != "open":
            return None
        port = int(elem.get("portid", "0") or 0)
        proto = elem.get("protocol", "tcp")
        banner = " ".join(p for p in [product, version] if p)
        return {
            "host_ip": addr,
            "hostnames": hostnames,
            "port": port,
            "transport": proto,
            "service": service,
            "plugin_id": "nmap-open-port",
            "plugin_name": f"Open port {port}/{proto}" + (f" ({service})" if service else ""),
            "plugin_family": "Nmap Service Detection",
            "severity": 0,  # informational: exposure/context, not a vulnerability
            "plugin_output": f"State: open  Service: {service or '?'}  {banner}".strip(),
            "source_scanner": self.source_scanner,
            "raw": {"portid": str(port), "protocol": proto, "service": service, "banner": banner},
        }
