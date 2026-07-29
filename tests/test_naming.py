"""Exported files are named for humans, not for hashes.

`poc-de8cd6735c0a4cc5913c741b.md` is an unusable deliverable: it cannot be
sorted by importance, scanned by eye, or handed to a client. These tests pin
the readable scheme and the properties it has to keep -- stability across
re-exports, uniqueness, and safety on Windows filesystems.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nessus_builder import default_host_props, nessus_document, report_host, report_item
from vapt_verify.cli.main import main
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.naming import (
    disambiguate,
    finding_basename,
    host_dir,
    host_name,
    location,
    severity_prefix,
    slug,
)
from vapt_verify.reconciliation.gate import reconcile
from vapt_verify.workspace import EngagementWorkspace

# --- the pieces -------------------------------------------------------------


def test_slug_is_readable_not_mangled() -> None:
    assert slug("SSL Certificate Cannot Be Trusted") == "SSL-Certificate-Cannot-Be-Trusted"
    assert slug("SNMP Agent Default Community Name (public)") == (
        "SNMP-Agent-Default-Community-Name-public"
    )
    assert slug("") == "unnamed"


def test_slug_truncates_on_a_word_boundary() -> None:
    long = "A Very Long Plugin Name That Keeps Going And Going Beyond The Limit"
    result = slug(long, max_length=30)
    assert len(result) <= 30
    assert not result.endswith("-")
    # Degrades to whole words rather than a mid-word stump.
    assert result in long.replace(" ", "-")


def test_host_keeps_its_dots() -> None:
    """`192-0-2-10` is not an IP address anyone recognises at a glance."""
    assert host_name("192.0.2.10") == "192.0.2.10"
    assert host_name("web01.example-doc.test") == "web01.example-doc.test"
    assert host_name("") == ""
    assert host_dir("") == "unknown-host"


def test_host_name_strips_path_and_shell_characters() -> None:
    for hostile in ["../../etc/passwd", "a/b", "a\\b", "a;rm -rf /", "a\x00b"]:
        cleaned = host_dir(hostile)
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert ".." not in cleaned
        assert cleaned.strip()


def test_windows_reserved_device_names_are_escaped() -> None:
    """A file called `con.md` cannot be opened on Windows."""
    assert host_dir("CON") == "CON-host"
    assert finding_basename(
        severity="LOW", target="", port=0, transport="", title="x",
    ).startswith("4-LOW")


def test_severity_prefix_sorts_worst_first() -> None:
    names = [
        severity_prefix(s)
        for s in ["LOW", "CRITICAL", "INFORMATIONAL", "HIGH", "MEDIUM"]
    ]
    assert sorted(names) == [
        "1-CRITICAL", "2-HIGH", "3-MEDIUM", "4-LOW", "5-INFORMATIONAL",
    ]
    # Alphabetical severity names would file INFORMATIONAL between HIGH and LOW.
    assert sorted(["LOW", "CRITICAL", "INFORMATIONAL", "HIGH", "MEDIUM"]) != [
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
    ]


def test_unknown_severity_sorts_last_not_first() -> None:
    assert severity_prefix("WEIRD").startswith("9-")


def test_host_level_findings_say_host_not_port_zero() -> None:
    assert location(0, "tcp") == "host"
    assert location(443, "tcp") == "443-tcp"
    assert location(161, "udp") == "161-udp"
    assert location(443, "none") == "443"


# --- collisions -------------------------------------------------------------


def test_names_are_left_clean_when_they_do_not_collide() -> None:
    resolved = disambiguate([
        ("f1", "3-MEDIUM_192.0.2.10_443-tcp_A", "1"),
        ("f2", "3-MEDIUM_192.0.2.10_22-tcp_B", "2"),
    ])
    assert resolved == {
        "f1": "3-MEDIUM_192.0.2.10_443-tcp_A",
        "f2": "3-MEDIUM_192.0.2.10_22-tcp_B",
    }


def test_colliding_names_are_disambiguated_by_plugin_id() -> None:
    """Two plugins can report the same condition at the same location."""
    resolved = disambiguate([
        ("f1", "3-MEDIUM_192.0.2.10_443-tcp_Same", "51192"),
        ("f2", "3-MEDIUM_192.0.2.10_443-tcp_Same", "57582"),
    ])
    assert len(set(resolved.values())) == 2
    assert "plugin51192" in resolved["f1"]
    assert "plugin57582" in resolved["f2"]


def test_identical_plugin_and_name_still_never_collide() -> None:
    """The last resort must not silently overwrite an exported file."""
    resolved = disambiguate([
        ("finding-aaaaaaaa", "same", "1"),
        ("finding-bbbbbbbb", "same", "1"),
        ("finding-cccccccc", "same", "1"),
    ])
    assert len(set(resolved.values())) == 3


def test_names_are_stable_across_runs() -> None:
    """A re-export must update the same file, not accumulate copies."""
    entries = [
        ("f1", "3-MEDIUM_192.0.2.10_443-tcp_Same", "51192"),
        ("f2", "3-MEDIUM_192.0.2.10_443-tcp_Same", "57582"),
        ("f3", "4-LOW_192.0.2.10_22-tcp_Other", "90317"),
    ]
    assert disambiguate(entries) == disambiguate(entries)


# --- end to end -------------------------------------------------------------

ITEMS: list[dict[str, object]] = [
    {"plugin_id": "51192", "plugin_name": "SSL Certificate Cannot Be Trusted",
     "port": 443, "protocol": "tcp", "severity": 2, "svc_name": "https"},
    {"plugin_id": "123456", "plugin_name": "Ubuntu Security Update for OpenSSL",
     "port": 0, "severity": 3, "family": "Ubuntu Local Security Checks"},
    {"plugin_id": "10287", "plugin_name": "Traceroute Information",
     "port": 0, "severity": 0, "family": "General"},
]


@pytest.fixture
def ws(tmp_path: Path) -> EngagementWorkspace:
    host = report_host(
        name="192.0.2.10",
        props=default_host_props("192.0.2.10"),
        items=[report_item(**i) for i in ITEMS],  # type: ignore[arg-type]
    )
    path = tmp_path / "scan.nessus"
    path.write_text(nessus_document(hosts=[host]), encoding="utf-8")
    workspace = EngagementWorkspace.create(
        tmp_path / "engagements" / "e1",
        Engagement(engagement_id="e1", approved_cidrs=["192.0.2.0/24"]),
    )
    result = NessusImporter(engagement_id="e1").import_file(path)
    workspace.persist_import(source_path=path, result=result, reconciliation=reconcile(result))
    return workspace


def test_poc_export_filenames_are_readable_and_sorted(
    ws: EngagementWorkspace, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["poc", "export", "--base", str(tmp_path / "engagements"),
                 "--engagement", "e1", "--format", "markdown"]) == 0
    names = sorted(p.name for p in (ws.root / "reports" / "poc").glob("*.md")
                   if p.name != "index.md")
    assert names == [
        "2-HIGH_192.0.2.10_host_Ubuntu-Security-Update-for-OpenSSL.md",
        "3-MEDIUM_192.0.2.10_443-tcp_SSL-Certificate-Cannot-Be-Trusted.md",
        "5-INFORMATIONAL_192.0.2.10_host_Traceroute-Information.md",
    ]
    # Sorting the directory puts the worst finding first, which is the point.
    assert names[0].startswith("2-HIGH")


def test_poc_export_is_idempotent_not_accumulating(
    ws: EngagementWorkspace, tmp_path: Path
) -> None:
    base = str(tmp_path / "engagements")
    for _ in range(3):
        assert main(["poc", "export", "--base", base, "--engagement", "e1",
                     "--format", "markdown"]) == 0
    assert len(list((ws.root / "reports" / "poc").glob("*.md"))) == 4  # 3 + index


def test_poc_export_can_skip_informational(
    ws: EngagementWorkspace, tmp_path: Path
) -> None:
    assert main(["poc", "export", "--base", str(tmp_path / "engagements"),
                 "--engagement", "e1", "--format", "markdown",
                 "--skip-informational"]) == 0
    names = [p.name for p in (ws.root / "reports" / "poc").glob("*.md")]
    assert not [n for n in names if n.startswith("5-INFORMATIONAL")]
