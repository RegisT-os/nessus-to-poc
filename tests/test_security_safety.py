"""Repository safety / client-data checker tests (task tests 30 & 31)."""

from __future__ import annotations

from pathlib import Path

from vapt_verify.security.client_data_check import (
    classify_ip,
    scan_files,
    scan_repository,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_documentation_ranges_are_recognised() -> None:
    assert classify_ip("192.0.2.10") == "documentation"
    assert classify_ip("198.51.100.5") == "documentation"
    assert classify_ip("203.0.113.9") == "documentation"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("10.1.2.3") == "private"


def test_public_ip_in_example_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "profiles" / "examples").mkdir(parents=True)
    bad = tmp_path / "profiles" / "examples" / "engagement.yaml"
    bad.write_text("approved_cidrs: [8.8.8.8/32]\n", encoding="utf-8")
    violations = scan_files(tmp_path, ["profiles/examples/engagement.yaml"])
    kinds = {v.kind for v in violations}
    assert "non_documentation_ip" in kinds


def test_private_rfc1918_ip_in_example_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "profiles" / "examples").mkdir(parents=True)
    bad = tmp_path / "profiles" / "examples" / "hosts.yaml"
    bad.write_text("- 10.20.30.40\n", encoding="utf-8")
    violations = scan_files(tmp_path, ["profiles/examples/hosts.yaml"])
    assert any(v.kind == "non_documentation_ip" for v in violations)


def test_tracked_private_profile_is_flagged(tmp_path: Path) -> None:
    priv = tmp_path / "profiles" / "private" / "mbsb"
    priv.mkdir(parents=True)
    (priv / "engagement.yaml").write_text("client_alias: RealClient\n", encoding="utf-8")
    violations = scan_files(tmp_path, ["profiles/private/mbsb/engagement.yaml"])
    assert any(v.kind == "private_profile_tracked" for v in violations)


def test_gitkeep_in_private_is_allowed(tmp_path: Path) -> None:
    priv = tmp_path / "profiles" / "private"
    priv.mkdir(parents=True)
    (priv / ".gitkeep").write_text("", encoding="utf-8")
    violations = scan_files(tmp_path, ["profiles/private/.gitkeep"])
    assert not any(v.kind == "private_profile_tracked" for v in violations)


def test_real_nessus_outside_fixtures_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "client.nessus").write_text("<x/>", encoding="utf-8")
    violations = scan_files(tmp_path, ["data/client.nessus"])
    assert any(v.kind == "scanner_export_tracked" for v in violations)


def test_fixture_nessus_is_allowed(tmp_path: Path) -> None:
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "s.nessus").write_text("<x/>", encoding="utf-8")
    violations = scan_files(tmp_path, ["tests/fixtures/s.nessus"])
    assert not any(v.kind == "scanner_export_tracked" for v in violations)


def test_missing_gitignore_rule_is_flagged(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    violations = scan_repository(tmp_path)
    assert any(v.kind == "gitignore_missing_private" for v in violations)


def _repo_files() -> list[str]:
    files: list[str] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(REPO_ROOT).parts
        if any(
            p in {".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", "engagements"}
            for p in parts
        ):
            continue
        files.append(str(path.relative_to(REPO_ROOT)))
    return files


def test_this_repository_content_is_clean() -> None:
    """Task 31 — the committed content of THIS repo contains no client data."""
    violations = scan_files(REPO_ROOT, _repo_files())
    assert violations == [], f"repository safety violations: {[v.to_dict() for v in violations]}"


def test_gitignore_excludes_private_profiles() -> None:
    text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "profiles/private/" in text
