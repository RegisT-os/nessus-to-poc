"""Cross-platform (notably Windows) compatibility regressions.

Each test here pins a real failure that made the tool unusable on Windows:

1. Recipes were not shipped as package data, so any non-editable ``pip install``
   crashed with "manual-review-fallback recipe is missing".
2. Non-ASCII characters in CLI output raised ``UnicodeEncodeError`` on legacy
   cp1252/cp437 consoles -- including on ``--help``.
3. ``.nessus`` files re-saved with a BOM or as UTF-16 failed to parse.
4. An HTML error page saved as ``.nessus`` produced an opaque XML ParseError.
5. Paths pasted from Explorer ("Copy as path") are wrapped in double quotes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vapt_verify.cli.console import ascii_safe, configure_stdio
from vapt_verify.cli.main import main
from vapt_verify.importers.source_file import (
    SourceFileError,
    inspect_source_file,
    normalize_user_path,
)
from vapt_verify.recipes.library import RecipeLibrary

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "sample_small.nessus"


# --- 1. recipe packaging ---------------------------------------------------

def test_builtin_recipes_load_from_package_data() -> None:
    """Recipes must resolve via importlib.resources, not a repo-relative path."""
    library = RecipeLibrary.load_builtin()
    assert len(library) > 0
    # The fallback recipe must always be present; its absence was the crash.
    assert library.by_id("manual-review-fallback") is not None


def test_recipe_library_location_is_inside_the_package() -> None:
    location = RecipeLibrary.builtin_location()
    assert "vapt_verify" in location.replace("\\", "/")
    assert Path(location).exists()


def test_recipes_are_declared_as_package_data() -> None:
    """pyproject must ship recipes/data/*.yaml or installs silently lose them."""
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "recipes/data/*.yaml" in pyproject


def test_env_override_can_add_recipes(tmp_path: Path, monkeypatch) -> None:
    extra = tmp_path / "recipes"
    extra.mkdir()
    (extra / "custom.yaml").write_text(
        "recipes:\n"
        "  - recipe_id: custom-test\n"
        "    version: '1'\n"
        "    family: generic\n"
        "    selection_layer: 2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VAPT_VERIFY_RECIPES_DIR", str(extra))
    library = RecipeLibrary.load_builtin()
    assert library.by_id("custom-test") is not None
    # Built-ins are still present (override layers on top, never replaces).
    assert library.by_id("manual-review-fallback") is not None


# --- 2. console encoding ---------------------------------------------------

def test_cli_output_strings_are_ascii() -> None:
    """CLI source must not emit characters a cp1252 console cannot encode."""
    source = (
        Path(__file__).resolve().parents[1] / "src" / "vapt_verify" / "cli" / "main.py"
    ).read_text(encoding="utf-8")
    non_ascii = {ch for ch in source if ord(ch) > 127}
    assert not non_ascii, f"non-ASCII characters in CLI output: {sorted(non_ascii)}"


def test_help_does_not_crash_under_legacy_codepage(tmp_path: Path) -> None:
    """`--help` under cp1252 must not raise UnicodeEncodeError (exit 0)."""
    proc = subprocess.run(
        [sys.executable, "-m", "vapt_verify", "--help"],
        capture_output=True,
        text=True,
        env={"PYTHONIOENCODING": "cp1252", "PATH": "/usr/bin:/bin"},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "UnicodeEncodeError" not in proc.stderr


def test_configure_stdio_is_idempotent_and_safe() -> None:
    configure_stdio()
    configure_stdio()  # must not raise on a second call


def test_ascii_safe_folds_typographic_characters() -> None:
    assert ascii_safe("a \u2014 b") == "a -- b"
    assert ascii_safe("x \u2192 y") == "x -> y"
    assert ascii_safe("plain") == "plain"


# --- 3/4. source-file preflight -------------------------------------------

def test_utf8_bom_file_is_accepted(tmp_path: Path) -> None:
    target = tmp_path / "bom.nessus"
    target.write_bytes(b"\xef\xbb\xbf" + SAMPLE.read_bytes())
    info = inspect_source_file(target)
    assert info.has_bom and info.detected_encoding == "utf-8-sig"


def test_utf16_file_is_detected(tmp_path: Path) -> None:
    target = tmp_path / "u16.nessus"
    target.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-16")
    info = inspect_source_file(target)
    assert info.detected_encoding.startswith("utf-16")


def test_html_masquerading_as_nessus_is_rejected_clearly(tmp_path: Path) -> None:
    target = tmp_path / "bad.nessus"
    target.write_text("<!DOCTYPE html><html><body>Sign in</body></html>", encoding="utf-8")
    with pytest.raises(SourceFileError, match="HTML page"):
        inspect_source_file(target)


def test_empty_file_is_rejected_clearly(tmp_path: Path) -> None:
    target = tmp_path / "empty.nessus"
    target.write_bytes(b"")
    with pytest.raises(SourceFileError, match="empty"):
        inspect_source_file(target)


def test_non_xml_nessus_is_rejected_clearly(tmp_path: Path) -> None:
    target = tmp_path / "db.nessus"
    target.write_bytes(b"SQLite format 3\x00binary junk")
    with pytest.raises(SourceFileError, match="does not start with an XML tag"):
        inspect_source_file(target)


def test_missing_file_is_rejected_clearly(tmp_path: Path) -> None:
    with pytest.raises(SourceFileError, match="not found"):
        inspect_source_file(tmp_path / "nope.nessus")


# --- 5. Windows path ergonomics -------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        # Explorer's "Copy as path" wraps in double quotes; the quotes must go.
        ('"C:\\scans\\report.nessus"', "C:\\scans\\report.nessus"),
        ("'C:/scans/report.nessus'", "C:/scans/report.nessus"),
        ("  /data/report.nessus  ", "/data/report.nessus"),
    ],
)
def test_quoted_and_padded_paths_are_normalized(raw: str, expected: str) -> None:
    # Compare as text: separator handling is the platform's job, quote/whitespace
    # stripping is ours.
    assert normalize_user_path(raw) == Path(expected)


def test_import_accepts_a_quoted_path(tmp_path: Path, capsys) -> None:
    base = str(tmp_path / "engagements")
    main(["engagement", "create", "--base", base, "--id", "e1"])
    capsys.readouterr()
    rc = main(["import", "--base", base, "--engagement", "e1", f'"{SAMPLE}"'])
    assert rc == 0
    assert "accounted for" in capsys.readouterr().out


def test_import_reports_bad_file_without_traceback(tmp_path: Path, capsys) -> None:
    base = str(tmp_path / "engagements")
    main(["engagement", "create", "--base", base, "--id", "e1"])
    bad = tmp_path / "bad.nessus"
    bad.write_text("<!DOCTYPE html><html>nope</html>", encoding="utf-8")
    capsys.readouterr()
    rc = main(["import", "--base", base, "--engagement", "e1", str(bad)])
    out = capsys.readouterr().out
    assert rc == 2
    assert "error:" in out
    assert "Traceback" not in out


# --- doctor ----------------------------------------------------------------

def test_doctor_reports_recipe_library_health(capsys) -> None:
    rc = main(["doctor"])
    out = capsys.readouterr().out
    assert "recipe library:" in out
    assert "recipe(s) loaded" in out
    assert "platform:" in out and "console encoding:" in out
    # Exit code reflects health; recipes must load in a healthy checkout.
    assert rc in {0, 1}
