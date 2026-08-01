"""Declarative, ordered verification pipelines (roadmap v3.1).

A recipe describes what evidence settles a class of finding; a playbook orders
that evidence gathering and says when a later step is worth running at all.
Playbooks contain no executable content: conditions are structured records
evaluated against earlier steps' observations, never expression strings.
"""

from vapt_verify.playbooks.library import (
    PlaybookLibrary,
    describe_playbook,
    validate_library,
    validate_playbook,
)
from vapt_verify.playbooks.models import (
    Condition,
    Operator,
    Playbook,
    PlaybookError,
    PlaybookStep,
)

__all__ = [
    "Condition",
    "Operator",
    "Playbook",
    "PlaybookError",
    "PlaybookLibrary",
    "PlaybookStep",
    "describe_playbook",
    "validate_library",
    "validate_playbook",
]
