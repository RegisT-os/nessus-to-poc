"""Playbook loading and validation (roadmap v3.1).

Playbooks ship as package data (``vapt_verify/playbooks/data/*.yaml``) and load
through :mod:`importlib.resources`, for the reason recorded as roadmap
invariant 8: a repo-relative data path once shipped nothing on a real install
and every classification crashed. ``VAPT_VERIFY_PLAYBOOKS_DIR`` layers operator
playbooks on top by id.

Validation is deliberately strict and happens at load time. The failure mode a
playbook invites is a condition that can never be true -- a typo'd observation
name, or a step depending on an observation only a *later* step produces --
which is indistinguishable from a step that simply never applies. Catching that
when the file is read turns a silent coverage hole into an error message.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

import yaml

from vapt_verify.adapters import get_adapter
from vapt_verify.playbooks.models import Playbook, PlaybookError

_PACKAGE_DATA = "vapt_verify.playbooks.data"
_ENV_OVERRIDE = "VAPT_VERIFY_PLAYBOOKS_DIR"

#: Observations every adapter's parser is expected to be able to produce, in
#: addition to whatever it declares. ``timed_out`` is set by the shared timeout
#: path; the execution layer supplies the rest.
UNIVERSAL_OBSERVATIONS = {"timed_out", "exit_code", "port_open"}


class PlaybookLibrary:
    """Ordered collection of playbooks, addressable by id, family or recipe."""

    def __init__(self, playbooks: list[Playbook]) -> None:
        self._playbooks = sorted(playbooks, key=lambda p: p.playbook_id)

    def __len__(self) -> int:
        return len(self._playbooks)

    @property
    def playbooks(self) -> list[Playbook]:
        return list(self._playbooks)

    def by_id(self, playbook_id: str) -> Playbook | None:
        for playbook in self._playbooks:
            if playbook.playbook_id == playbook_id:
                return playbook
        return None

    def for_recipe(self, recipe_id: str, family: str = "") -> Playbook | None:
        """Most specific match wins: an explicit recipe id beats a family."""
        for playbook in self._playbooks:
            if recipe_id and recipe_id in playbook.recipe_ids:
                return playbook
        for playbook in self._playbooks:
            if family and family in playbook.families:
                return playbook
        return None

    # -- loading ------------------------------------------------------------

    @classmethod
    def load_builtin(cls) -> PlaybookLibrary:
        playbooks: dict[str, Playbook] = {}
        for playbook in cls._load_package_data():
            playbooks[playbook.playbook_id] = playbook

        override = os.environ.get(_ENV_OVERRIDE, "").strip()
        if override:
            for playbook in cls._load_dir(Path(override)):
                playbooks[playbook.playbook_id] = playbook
        return cls(list(playbooks.values()))

    @classmethod
    def load_dirs(cls, dirs: list[Path]) -> PlaybookLibrary:
        playbooks: dict[str, Playbook] = {}
        for directory in dirs:
            for playbook in cls._load_dir(directory):
                playbooks[playbook.playbook_id] = playbook
        return cls(list(playbooks.values()))

    @staticmethod
    def _load_package_data() -> list[Playbook]:
        playbooks: list[Playbook] = []
        try:
            anchor = resources.files(_PACKAGE_DATA)
        except (ModuleNotFoundError, TypeError):  # pragma: no cover - defensive
            return playbooks
        for entry in sorted(anchor.iterdir(), key=lambda p: p.name):
            if not entry.name.endswith((".yaml", ".yml")):
                continue
            try:
                text = entry.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):  # pragma: no cover - defensive
                continue
            playbooks.extend(PlaybookLibrary._parse(text, source=entry.name))
        return playbooks

    @staticmethod
    def _load_dir(directory: Path) -> list[Playbook]:
        playbooks: list[Playbook] = []
        if not directory.exists():
            return playbooks
        for path in sorted(directory.glob("*.y*ml")):
            playbooks.extend(
                PlaybookLibrary._parse(path.read_text(encoding="utf-8"), source=str(path))
            )
        return playbooks

    @staticmethod
    def _parse(text: str, *, source: str) -> list[Playbook]:
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise PlaybookError(f"invalid playbook YAML in {source}: {exc}") from exc
        raw = data.get("playbooks", []) if isinstance(data, dict) else []
        if not isinstance(raw, list):
            raise PlaybookError(f"'playbooks' in {source} must be a list")
        try:
            return [Playbook.from_dict(item) for item in raw]
        except PlaybookError as exc:
            raise PlaybookError(f"{source}: {exc}") from exc

    @staticmethod
    def builtin_location() -> str:
        try:
            return str(resources.files(_PACKAGE_DATA))
        except (ModuleNotFoundError, TypeError):  # pragma: no cover - defensive
            return "(not found)"


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def declared_observations(adapter_name: str) -> set[str]:
    """Observations an adapter's parser can produce, as it declares them.

    An adapter may publish ``produces_observations``; those that do not are
    treated as unknown rather than empty, so validation warns instead of
    rejecting a condition it cannot check.
    """
    adapter = get_adapter(adapter_name)
    if adapter is None:
        return set()
    declared = getattr(adapter, "produces_observations", None)
    return set(declared) if declared else set()


def validate_playbook(playbook: Playbook) -> list[str]:
    """Return human-readable problems. Empty means valid.

    Checks, in order of how badly each one bites:

    1. an adapter that is not registered -- the step can never run;
    2. a condition reading a *later* step's output -- it can never be true;
    3. a condition naming an observation no earlier step declares -- almost
       always a typo, and it fails silently rather than loudly;
    4. a first step that is conditional -- nothing has run, so nothing can
       satisfy it.
    """
    problems: list[str] = []
    if not playbook.steps:
        problems.append(f"{playbook.playbook_id}: has no steps")
        return problems

    step_order = {step.step_id: index for index, step in enumerate(playbook.steps)}
    available: set[str] = set(UNIVERSAL_OBSERVATIONS)
    unknown_producers: set[str] = set()

    for index, step in enumerate(playbook.steps):
        where = f"{playbook.playbook_id}.{step.step_id}"
        adapter = get_adapter(step.adapter)
        if adapter is None:
            problems.append(
                f"{where}: adapter {step.adapter!r} is not registered, so this step "
                "can never run"
            )

        if index == 0 and step.is_conditional:
            problems.append(
                f"{where}: the first step is conditional, but no step has produced "
                "observations yet, so the condition can never be satisfied"
            )

        for condition in step.when:
            if condition.from_step:
                if condition.from_step not in step_order:
                    problems.append(
                        f"{where}: condition references unknown step "
                        f"{condition.from_step!r}"
                    )
                elif step_order[condition.from_step] >= index:
                    problems.append(
                        f"{where}: condition reads {condition.from_step!r}, which runs "
                        "at or after this step; it can never be true"
                    )
            elif (
                condition.observation not in available
                and not unknown_producers
                and condition.observation not in UNIVERSAL_OBSERVATIONS
            ):
                problems.append(
                    f"{where}: condition reads observation "
                    f"{condition.observation!r}, which no earlier step declares it "
                    "produces (likely a typo; the step would silently never run)"
                )

        declared = declared_observations(step.adapter)
        if declared:
            available |= declared
        elif adapter is not None:
            # The adapter does not declare its observations, so we cannot know
            # what later conditions may legitimately read. Stop reporting
            # unknown-observation problems rather than emit false alarms.
            unknown_producers.add(step.adapter)

    return problems


def validate_library(library: PlaybookLibrary) -> dict[str, list[str]]:
    """``{playbook_id: problems}``, only for playbooks that have problems."""
    report: dict[str, list[str]] = {}
    for playbook in library.playbooks:
        problems = validate_playbook(playbook)
        if problems:
            report[playbook.playbook_id] = problems
    return report


def describe_playbook(playbook: Playbook) -> list[str]:
    """Human-readable rendering for ``playbook show``."""
    lines = [
        f"playbook:   {playbook.playbook_id}  (v{playbook.version})",
        f"title:      {playbook.title or '(none)'}",
    ]
    if playbook.description:
        lines.append(f"purpose:    {playbook.description}")
    if playbook.families:
        lines.append("families:   " + ", ".join(playbook.families))
    if playbook.recipe_ids:
        lines.append("recipes:    " + ", ".join(playbook.recipe_ids))
    lines.append(f"adapters:   {', '.join(playbook.required_adapters())}")
    lines.append("")
    lines.append("steps:")
    for index, step in enumerate(playbook.steps, start=1):
        flags = []
        if step.optional:
            flags.append("optional")
        if not step.continue_on_failure:
            flags.append("stops the chain on failure")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        lines.append(f"  {index}. {step.step_id}  ({step.adapter}){suffix}")
        if step.description:
            lines.append(f"       {step.description}")
        if step.when:
            for condition in step.when:
                lines.append(f"       run only if: {condition.describe()}")
        else:
            lines.append("       runs unconditionally")
        if step.params:
            rendered = ", ".join(f"{k}={v!r}" for k, v in sorted(step.params.items()))
            lines.append(f"       params: {rendered}")
    for note in playbook.notes:
        lines.append(f"note: {note}")
    return lines
