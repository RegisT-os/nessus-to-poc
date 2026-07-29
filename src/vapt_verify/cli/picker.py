"""Interactive finding picker for ``vapt-verify select --interactive``.

A plain stdin/stdout loop -- no curses, no third-party TUI, no ANSI escapes.
That is deliberate: this runs in a Windows console, over SSH, and inside a
Kali VM, and the project already had to fix a crash caused by non-ASCII output
on cp1252. A numbered list plus typed ranges works everywhere.

The command grammar is small enough to be listed in the prompt itself:

    1-5,9      toggle those rows
    a / n / v  select all / none / invert (within the current filter)
    s HIGH     select every row of that severity
    /ssl       filter the view to rows matching text ("/" alone clears)
    p / <      next / previous page
    d          done, save
    q          quit without saving
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from vapt_verify.selection import finding_host, sort_key

PAGE_SIZE = 20


def _row_line(index: int, row: dict[str, Any], selected: bool) -> str:
    mark = "x" if selected else " "
    port = row.get("port", 0) or 0
    location = f"{port}/{row.get('transport', '')}" if port else "host"
    name = str(row.get("plugin_name", ""))
    if len(name) > 46:
        name = name[:43] + "..."
    return (
        f"  [{mark}] {index:>4}  {row.get('severity_label', '')!s:<13} "
        f"{finding_host(row):<16} {location:<10} {name}"
    )


def _parse_numbers(token: str, limit: int) -> list[int]:
    """``1-3,7`` -> ``[1, 2, 3, 7]``. Out-of-range entries are dropped."""
    picked: list[int] = []
    for chunk in token.replace(" ", ",").split(","):
        if not chunk:
            continue
        if "-" in chunk[1:]:
            start_text, _, end_text = chunk.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            picked.extend(range(start, end + 1))
        else:
            try:
                picked.append(int(chunk))
            except ValueError:
                continue
    return [n for n in picked if 1 <= n <= limit]


def run_picker(
    rows: Sequence[dict[str, Any]],
    *,
    preselected: set[str] | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> set[str] | None:
    """Pick findings interactively.

    Returns the chosen finding ids, or ``None`` if the operator quit without
    saving -- a distinction the caller must respect, because "I changed my mind"
    and "I chose nothing" are different answers.
    """
    ordered = sorted(rows, key=sort_key)
    if not ordered:
        output_fn("No findings to select from.")
        return None
    selected: set[str] = set(preselected or set())
    numbering = dict(enumerate(ordered, start=1))
    filter_text = ""
    page = 0

    def visible() -> list[tuple[int, dict[str, Any]]]:
        items = list(numbering.items())
        if not filter_text:
            return items
        needle = filter_text.lower()
        return [
            (i, r) for i, r in items
            if needle in f"{r.get('plugin_name', '')} {r.get('service', '')} "
                         f"{finding_host(r)} {r.get('severity_label', '')}".lower()
        ]

    while True:
        shown = visible()
        pages = max(1, (len(shown) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = max(0, min(page, pages - 1))
        window = shown[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]

        output_fn("")
        output_fn(f"  {'':3} {'#':>4}  {'SEVERITY':<13} {'HOST':<16} {'PORT':<10} FINDING")
        output_fn("  " + "-" * 76)
        for index, row in window:
            output_fn(_row_line(index, row, row["finding_id"] in selected))
        if not window:
            output_fn("  (no rows match the current filter)")
        output_fn("  " + "-" * 76)

        status = f"  selected {len(selected)} of {len(ordered)}"
        if filter_text:
            status += f"   filter '{filter_text}' -> {len(shown)} row(s)"
        if pages > 1:
            status += f"   page {page + 1}/{pages}"
        output_fn(status)
        output_fn("  1-5,9 toggle | a all | n none | v invert | s HIGH | /text filter"
                  " | p,< page | d done | q quit")

        try:
            answer = input_fn("  > ").strip()
        except EOFError:
            output_fn("  (end of input) - saving current selection.")
            return selected

        if not answer:
            continue
        command = answer[0].lower()

        if command == "q":
            output_fn("  Cancelled. Nothing was saved.")
            return None
        if command == "d":
            return selected
        if command == "a":
            selected |= {r["finding_id"] for _i, r in shown}
            continue
        if command == "n":
            selected -= {r["finding_id"] for _i, r in shown}
            continue
        if command == "v":
            for _index, row in shown:
                fid = row["finding_id"]
                selected.symmetric_difference_update({fid})
            continue
        if command == "p":
            page += 1
            continue
        if command == "<":
            page -= 1
            continue
        if command == "/":
            filter_text = answer[1:].strip()
            page = 0
            continue
        if command == "s":
            wanted = answer[1:].strip().upper()
            if not wanted:
                output_fn("  Usage: s <SEVERITY>, e.g. 's HIGH'")
                continue
            matched = {
                r["finding_id"] for _i, r in shown
                if str(r.get("severity_label", "")).upper() == wanted
            }
            if not matched:
                output_fn(f"  No {wanted} findings in the current view.")
            selected |= matched
            continue

        numbers = _parse_numbers(answer, len(ordered))
        if not numbers:
            output_fn(f"  Did not understand {answer!r}. Type 'd' when done, 'q' to cancel.")
            continue
        for number in numbers:
            fid = numbering[number]["finding_id"]
            selected.symmetric_difference_update({fid})
