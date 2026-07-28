"""Console safety for cross-platform (notably Windows) terminals.

Windows consoles frequently run a legacy code page (cp1252 / cp437) rather than
UTF-8. Printing a character the code page cannot represent — an em dash, an
arrow, a box-drawing glyph — raises ``UnicodeEncodeError`` and aborts the
command with a traceback. That failure mode is indistinguishable, to a user,
from "the tool doesn't work on Windows".

:func:`configure_stdio` makes output encoding-proof:

* prefer UTF-8 on the stream where the platform allows it;
* always fall back to ``errors="replace"`` so an unrepresentable character
  degrades to ``?`` instead of crashing the process.

Source strings should still stay ASCII (see :func:`ascii_safe`); this is the
belt-and-braces layer for anything dynamic, such as scanner output echoed back
to the terminal.
"""

from __future__ import annotations

import sys
from typing import IO, Any

# Characters that commonly appear in scanner output/prose but are missing from
# legacy Windows code pages. Mapped to ASCII equivalents for display.
# ruff: noqa: RUF001 - the ambiguous characters are the point of this table.
_ASCII_FALLBACKS = {
    "—": "--",  # em dash
    "–": "-",  # en dash
    "→": "->",  # rightwards arrow
    "←": "<-",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "…": "...",
    "·": "-",  # middle dot
    "✓": "OK",
    "✗": "X",
    "✅": "OK",
    " ": " ",  # non-breaking space
}


def ascii_safe(text: str) -> str:
    """Return ``text`` with common typographic characters folded to ASCII."""
    for source, replacement in _ASCII_FALLBACKS.items():
        if source in text:
            text = text.replace(source, replacement)
    return text


def _reconfigure(stream: IO[Any] | None) -> None:
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    # Try UTF-8 first; if the platform/stream refuses, at least stop it raising.
    for kwargs in ({"encoding": "utf-8", "errors": "replace"}, {"errors": "replace"}):
        try:
            reconfigure(**kwargs)
            return
        except (ValueError, OSError):  # pragma: no cover - platform dependent
            continue


def configure_stdio() -> None:
    """Make stdout/stderr resilient to characters the console cannot encode.

    Safe and idempotent on every platform; a no-op where streams are already
    UTF-8 or have been replaced (e.g. by pytest's capture).
    """
    _reconfigure(sys.stdout)
    _reconfigure(sys.stderr)


def console_encoding() -> str:
    """Best-effort name of the current stdout encoding (for diagnostics)."""
    return getattr(sys.stdout, "encoding", None) or "unknown"
