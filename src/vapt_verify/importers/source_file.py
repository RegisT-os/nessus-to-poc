"""Source-file preflight checks.

Scanner exports reach us from many places: a Windows share, an email
attachment, a Tenable download re-saved by a text editor. They can carry a
UTF-8 BOM, be re-encoded as UTF-16, or not be the file the operator thought
(an HTML error page saved as ``.nessus`` is common).

Rather than letting the XML parser fail with an opaque
``ParseError: not well-formed (invalid token)``, we sniff the file first and
raise :class:`SourceFileError` with an actionable message. Losslessness is
unaffected: a file that cannot be read produces zero findings and an explicit,
visible error — never a silent partial import.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Byte-order marks we recognise, longest first so UTF-32 wins over UTF-16.
_BOMS: list[tuple[bytes, str]] = [
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
]


class SourceFileError(Exception):
    """A source file cannot be used, with an operator-facing explanation."""


@dataclass
class SourceFileInfo:
    path: Path
    size: int
    detected_encoding: str
    has_bom: bool
    looks_like_xml: bool
    root_hint: str = ""


def inspect_source_file(path: str | Path) -> SourceFileInfo:
    """Sniff a scanner export, raising :class:`SourceFileError` if unusable."""
    p = Path(path)
    if not p.exists():
        raise SourceFileError(f"File not found: {p}")
    if p.is_dir():
        raise SourceFileError(f"Expected a file but got a directory: {p}")

    size = p.stat().st_size
    if size == 0:
        raise SourceFileError(f"File is empty (0 bytes): {p}")

    try:
        with open(p, "rb") as handle:
            head = handle.read(4096)
    except OSError as exc:
        raise SourceFileError(f"Could not read {p}: {exc}") from exc

    encoding = "utf-8"
    has_bom = False
    for bom, name in _BOMS:
        if head.startswith(bom):
            encoding, has_bom = name, True
            head = head[len(bom) :]
            break

    # Decode a sample for content sniffing; UTF-16/32 need the real codec.
    sample_encoding = encoding if encoding != "utf-8" else "utf-8"
    try:
        sample = head.decode(sample_encoding, errors="replace")
    except LookupError:  # pragma: no cover - defensive
        sample = head.decode("utf-8", errors="replace")

    stripped = sample.lstrip("﻿ \t\r\n")
    looks_like_xml = stripped.startswith("<")

    root_hint = ""
    lowered = stripped.lower()
    if "nessusclientdata" in lowered:
        root_hint = "nessus"
    elif "<nmaprun" in lowered:
        root_hint = "nmap"
    elif stripped.startswith("<!doctype html") or "<html" in lowered[:200]:
        raise SourceFileError(
            f"{p.name} looks like an HTML page, not a scanner export. This usually means a "
            "download returned a login or error page. Re-export the scan from the scanner "
            "and check the file opens in a text editor as XML."
        )

    if not looks_like_xml and p.suffix.lower() in {".nessus", ".xml"}:
        raise SourceFileError(
            f"{p.name} does not start with an XML tag, so it cannot be parsed as "
            f"{p.suffix} data. Detected encoding: {encoding}. If this is a Nessus "
            "database or archive (.db/.zip), export it as '.nessus' (Nessus XML) first."
        )

    return SourceFileInfo(
        path=p,
        size=size,
        detected_encoding=encoding,
        has_bom=has_bom,
        looks_like_xml=looks_like_xml,
        root_hint=root_hint,
    )


def normalize_user_path(raw: str) -> Path:
    """Normalize a path as typed by a user, especially on Windows.

    Handles surrounding quotes (common when pasting from Explorer's "Copy as
    path", which wraps in double quotes), ``~`` expansion, and stray whitespace.
    """
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1]
    return Path(text.strip()).expanduser()
