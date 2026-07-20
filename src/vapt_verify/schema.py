"""Schema versioning and migration (task section 23, v1.0).

Normalized exports and engagement workspaces are stamped with a schema version
so that future format changes can be migrated forward safely. v1.0 ships schema
``1.0``; the migration registry is the extension point for later versions.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

SCHEMA_VERSION = "1.0"

Payload = dict[str, Any]

# Ordered migrations: {from_version: (to_version, migrate_fn)}. Empty at 1.0.
_MIGRATIONS: dict[str, tuple[str, Callable[[Payload], Payload]]] = {}


def is_current(version: str) -> bool:
    return version == SCHEMA_VERSION


def needs_migration(version: str) -> bool:
    return version != SCHEMA_VERSION and version in _MIGRATIONS


def migrate(version: str, payload: Payload) -> tuple[str, Payload]:
    """Apply migrations from ``version`` toward the current schema.

    Returns the resulting (version, payload). Unknown/older versions with no
    registered migration are returned unchanged so nothing is silently altered.
    """
    current = version
    data = payload
    while current in _MIGRATIONS:
        target, fn = _MIGRATIONS[current]
        data = fn(data)
        current = target
    return current, data
