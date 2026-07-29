"""Manual-capture runbook generation (roadmap v4.0).

The orchestrator's other half. ``run`` executes a verification itself; the
runbook is for the far more common case where the operator runs the commands
*themselves* -- from Kali, from a jump host, from wherever the target is
actually reachable -- and brings the output back.

``runbook`` turns every imported finding into concrete, copy-pasteable commands
built from the same adapters ``run`` uses, so a runbook command and an executed
command can never drift apart. ``evidence import`` takes the captured output
files back in.
"""

from vapt_verify.runbook.builder import RunbookBuilder
from vapt_verify.runbook.models import (
    CommandStatus,
    Runbook,
    RunbookCommand,
    RunbookEntry,
    RunbookManualTask,
)

__all__ = [
    "CommandStatus",
    "Runbook",
    "RunbookBuilder",
    "RunbookCommand",
    "RunbookEntry",
    "RunbookManualTask",
]
