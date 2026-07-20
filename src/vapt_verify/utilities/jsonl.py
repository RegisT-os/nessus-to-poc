"""JSON Lines helpers for normalized exports.

Normalized assets, services and findings are written as JSONL (one JSON object
per line) so that large engagements stream cleanly and appends preserve the
provenance of repeated scans (task 2.4 / 22.7).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

JSONValue = Any  # JSON-compatible value; kept permissive for serialized models.


def write_jsonl(path: str | Path, rows: Iterable[dict[str, JSONValue]]) -> int:
    """Write ``rows`` as JSONL, overwriting the file. Returns the row count."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(p, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            count += 1
    return count


def append_jsonl(path: str | Path, rows: Iterable[dict[str, JSONValue]]) -> int:
    """Append ``rows`` to a JSONL file (creating it if needed).

    Appending — rather than overwriting — is what lets multiple scans of the
    same finding retain separate provenance instead of clobbering each other.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(p, "a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            count += 1
    return count


def read_jsonl(path: str | Path) -> Iterator[dict[str, JSONValue]]:
    """Yield objects from a JSONL file. Blank lines are skipped."""
    p = Path(path)
    if not p.exists():
        return
    with open(p, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)
