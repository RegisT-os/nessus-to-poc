"""Additional importer tests (task section 23, v0.8).

Every importer is lossless and reconciles, and none contaminates the core
finding model — they all produce the same normalized Finding shape.
"""

from __future__ import annotations

from pathlib import Path

from vapt_verify.importers.nessus_csv import NessusCsvImporter
from vapt_verify.importers.nmap_xml import NmapXmlImporter
from vapt_verify.importers.normalized_json import NormalizedJsonImporter
from vapt_verify.models.enums import Transport
from vapt_verify.reconciliation import reconcile

CSV_CONTENT = """Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output
51192,,6.5,Medium,192.0.2.10,tcp,443,SSL Certificate Cannot Be Trusted,syn,desc,sol,out
123456,CVE-2026-0001,7.5,High,192.0.2.10,tcp,0,Ubuntu Security Update,syn,desc,sol,pkg output
41028,,5.0,Medium,192.0.2.20,udp,161,SNMP Default Community,syn,desc,sol,public
"""

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="web01.example-doc.test"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
      <port protocol="udp" portid="161"><state state="open"/><service name="snmp"/></port>
    </ports>
  </host>
</nmaprun>
"""


def test_nessus_csv_is_lossless(tmp_path: Path) -> None:
    path = tmp_path / "scan.csv"
    path.write_text(CSV_CONTENT, encoding="utf-8")
    result = NessusCsvImporter(engagement_id="e").import_file(path)
    assert result.source_report_item_count == 3
    assert result.normalized_finding_count == 3
    # port-0 host finding retained; udp retained
    assert any(f.port == 0 for f in result.findings)
    assert any(f.transport is Transport.UDP for f in result.findings)
    assert reconcile(result).is_balanced


def test_nmap_xml_only_open_ports_become_findings(tmp_path: Path) -> None:
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML, encoding="utf-8")
    result = NmapXmlImporter(engagement_id="e").import_file(path)
    # two open ports (443/tcp, 161/udp); the closed 22/tcp is not a finding
    assert result.normalized_finding_count == 2
    ports = {f.port for f in result.findings}
    assert ports == {443, 161}
    assert all(f.is_informational for f in result.findings)
    assert reconcile(result).is_balanced


def test_normalized_json_round_trips(tmp_path: Path) -> None:
    # Import a Nessus file, export findings as JSONL, reimport.
    from vapt_verify.importers.nessus_xml import NessusImporter
    from vapt_verify.utilities.jsonl import write_jsonl

    fixtures = Path(__file__).parent / "fixtures" / "sample_small.nessus"
    original = NessusImporter(engagement_id="e").import_file(fixtures)
    export = tmp_path / "findings.jsonl"
    write_jsonl(export, (f.to_dict() for f in original.findings))

    reimported = NormalizedJsonImporter(engagement_id="e").import_file(export)
    assert reimported.normalized_finding_count == original.normalized_finding_count
    # ids and fingerprints are preserved across the round trip
    orig_ids = {f.finding_id for f in original.findings}
    new_ids = {f.finding_id for f in reimported.findings}
    assert orig_ids == new_ids
    assert reconcile(reimported).is_balanced
