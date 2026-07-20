"""Engagement backup & restore with integrity manifest (task section 23, v1.0).

A backup is a zip of the engagement workspace plus a ``backup_manifest.json``
listing a SHA-256 for every file, so a restore can be verified against
tampering or corruption. Originals and evidence keep their hashes, so
chain-of-custody survives a backup/restore round trip.
"""

from __future__ import annotations

import datetime as _dt
import json
import zipfile
from pathlib import Path
from typing import Any

from vapt_verify import __version__
from vapt_verify.schema import SCHEMA_VERSION
from vapt_verify.utilities.hashing import sha256_file

_MANIFEST_NAME = "backup_manifest.json"


def create_backup(engagement_root: str | Path, destination: str | Path | None = None) -> Path:
    root = Path(engagement_root)
    if not (root / "engagement.yaml").exists():
        raise FileNotFoundError(f"not an engagement workspace: {root}")

    files = [p for p in root.rglob("*") if p.is_file()]
    manifest: dict[str, Any] = {
        "created": _dt.datetime.now(_dt.UTC).isoformat(),
        "tool_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "engagement": root.name,
        "files": {str(p.relative_to(root)): sha256_file(p) for p in files},
    }

    if destination is None:
        stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = root.parent / f"{root.name}_backup_{stamp}.zip"
    dest = Path(destination)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True))
        for p in files:
            zf.write(p, arcname=str(Path(root.name) / p.relative_to(root)))
    return dest


def restore_backup(archive: str | Path, base_dir: str | Path) -> tuple[Path, list[str]]:
    """Restore an engagement zip under ``base_dir``.

    Returns (restored_root, integrity_errors). An empty error list means every
    restored file matched the manifest hash.
    """
    archive = Path(archive)
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        manifest = json.loads(zf.read(_MANIFEST_NAME).decode("utf-8"))
        engagement = manifest["engagement"]
        for name in zf.namelist():
            if name == _MANIFEST_NAME:
                continue
            # Prevent path traversal from a hostile archive.
            target = (base / name).resolve()
            if not str(target).startswith(str(base.resolve())):
                raise ValueError(f"unsafe path in archive: {name}")
            zf.extract(name, base)

    restored_root = base / engagement
    errors: list[str] = []
    for rel, expected in manifest["files"].items():
        path = restored_root / rel
        if not path.exists():
            errors.append(f"missing after restore: {rel}")
        elif sha256_file(path) != expected:
            errors.append(f"hash mismatch: {rel}")
    return restored_root, errors
