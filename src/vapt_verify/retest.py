"""Retest comparison (task section 13, v0.5).

Compares two imports of the same engagement by finding fingerprint. A finding
present in the baseline but absent in the latest scan is **not deleted** — it is
reported as "no longer reported", a state that requires reviewer assessment
(candidate ``SERVICE_NOT_CURRENTLY_OBSERVED`` / possibly remediated), never an
automatic false positive or a silent removal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RetestResult:
    baseline_import: str
    latest_import: str
    still_reported: list[dict[str, str]] = field(default_factory=list)
    no_longer_reported: list[dict[str, str]] = field(default_factory=list)
    newly_reported: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_import": self.baseline_import,
            "latest_import": self.latest_import,
            "counts": {
                "still_reported": len(self.still_reported),
                "no_longer_reported": len(self.no_longer_reported),
                "newly_reported": len(self.newly_reported),
            },
            "still_reported": self.still_reported,
            "no_longer_reported": self.no_longer_reported,
            "newly_reported": self.newly_reported,
        }


def _by_fingerprint(findings: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for f in findings:
        fp = f.get("fingerprint", "")
        out[fp] = {
            "fingerprint": fp,
            "finding_id": f.get("finding_id", ""),
            "plugin_id": f.get("plugin_id", ""),
            "plugin_name": f.get("plugin_name", ""),
            "severity": f.get("severity_label", ""),
        }
    return out


def compare(
    *,
    baseline: list[dict[str, Any]],
    latest: list[dict[str, Any]],
    baseline_import: str = "baseline",
    latest_import: str = "latest",
) -> RetestResult:
    base = _by_fingerprint(baseline)
    new = _by_fingerprint(latest)
    base_fps = set(base)
    new_fps = set(new)
    return RetestResult(
        baseline_import=baseline_import,
        latest_import=latest_import,
        still_reported=[base[fp] for fp in sorted(base_fps & new_fps)],
        no_longer_reported=[base[fp] for fp in sorted(base_fps - new_fps)],
        newly_reported=[new[fp] for fp in sorted(new_fps - base_fps)],
    )
