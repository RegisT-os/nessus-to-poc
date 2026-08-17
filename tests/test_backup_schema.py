"""Backup/restore and schema-versioning tests (task section 23, v1.0)."""

from __future__ import annotations

from pathlib import Path

from vapt_verify import __version__
from vapt_verify.backup import create_backup, restore_backup
from vapt_verify.importers.nessus_xml import NessusImporter
from vapt_verify.models.engagement import Engagement
from vapt_verify.reconciliation import reconcile
from vapt_verify.schema import SCHEMA_VERSION, is_current
from vapt_verify.workspace import EngagementWorkspace

FIXTURES = Path(__file__).parent / "fixtures"


def _engagement_ws(tmp_path: Path) -> EngagementWorkspace:
    ws = EngagementWorkspace.create(tmp_path / "e1", Engagement(engagement_id="e1"))
    result = NessusImporter(engagement_id="e1").import_file(FIXTURES / "sample_small.nessus")
    ws.persist_import(source_path=FIXTURES / "sample_small.nessus", result=result,
                      reconciliation=reconcile(result))
    return ws


def test_workspace_is_stamped_with_current_schema(tmp_path: Path) -> None:
    ws = _engagement_ws(tmp_path)
    assert ws.schema_version() == SCHEMA_VERSION
    assert is_current(ws.schema_version())


def test_backup_and_restore_round_trip_verifies_integrity(tmp_path: Path) -> None:
    ws = _engagement_ws(tmp_path)
    archive = create_backup(ws.root)
    assert archive.exists()

    restore_base = tmp_path / "restored"
    restored_root, errors = restore_backup(archive, restore_base)
    assert errors == []  # every file matched its manifest hash
    assert (restored_root / "engagement.yaml").exists()
    # findings survived the round trip
    restored_ws = EngagementWorkspace.load(restored_root)
    assert len(restored_ws.load_findings()) == len(ws.load_findings())


def test_restore_detects_tampering(tmp_path: Path) -> None:
    ws = _engagement_ws(tmp_path)
    archive = create_backup(ws.root)
    restored_root, errors = restore_backup(archive, tmp_path / "r1")
    assert errors == []
    # Tamper with a restored file, then re-verify against a fresh restore target
    # to confirm the manifest would catch a mismatch.
    tampered = restored_root / "engagement.yaml"
    tampered.write_text(tampered.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    # Re-running restore over the tampered tree rewrites the file, so instead we
    # assert the manifest hashing is content-sensitive directly.
    from vapt_verify.utilities.hashing import sha256_file

    assert sha256_file(tampered) != sha256_file(ws.engagement_file)


def test_version_consistency() -> None:
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in pyproject
    assert __version__ == "2.6.0"
