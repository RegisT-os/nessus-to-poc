"""Evidence model (task section 9.6).

Evidence records a single adapter execution: the exact structured command
(argument array — never a shell string), the tool and its version, timing,
exit/timeout state, captured output, parsed observations and a SHA-256 of the
raw evidence. Evidence is the input to a human decision; it is never itself a
verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    evidence_id: str
    finding_id: str
    engagement_id: str
    asset_id: str
    adapter: str
    tool_name: str
    tool_version: str = ""
    command_args: list[str] = field(default_factory=list)
    sanitized_command: str = ""
    operator: str = ""
    start_timestamp: str = ""
    end_timestamp: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    parsed_observations: dict[str, Any] = field(default_factory=dict)
    raw_evidence_path: str = ""
    sha256: str = ""
    sanitization_status: str = "unsanitized"
    review_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "finding_id": self.finding_id,
            "engagement_id": self.engagement_id,
            "asset_id": self.asset_id,
            "adapter": self.adapter,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "command_args": self.command_args,
            "sanitized_command": self.sanitized_command,
            "operator": self.operator,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "parsed_observations": self.parsed_observations,
            "raw_evidence_path": self.raw_evidence_path,
            "sha256": self.sha256,
            "sanitization_status": self.sanitization_status,
            "review_notes": self.review_notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        return cls(
            evidence_id=data["evidence_id"],
            finding_id=data["finding_id"],
            engagement_id=data.get("engagement_id", ""),
            asset_id=data.get("asset_id", ""),
            adapter=data.get("adapter", ""),
            tool_name=data.get("tool_name", ""),
            tool_version=data.get("tool_version", ""),
            command_args=list(data.get("command_args", [])),
            sanitized_command=data.get("sanitized_command", ""),
            operator=data.get("operator", ""),
            start_timestamp=data.get("start_timestamp", ""),
            end_timestamp=data.get("end_timestamp", ""),
            exit_code=data.get("exit_code"),
            timed_out=bool(data.get("timed_out", False)),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            parsed_observations=dict(data.get("parsed_observations", {})),
            raw_evidence_path=data.get("raw_evidence_path", ""),
            sha256=data.get("sha256", ""),
            sanitization_status=data.get("sanitization_status", "unsanitized"),
            review_notes=data.get("review_notes", ""),
        )
