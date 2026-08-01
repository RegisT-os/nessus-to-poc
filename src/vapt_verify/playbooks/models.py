"""Playbook model (roadmap v3.1).

A recipe says *what evidence would settle a class of finding*. A playbook says
*in what order to gather it, and when a step is worth running at all* -- *"only
probe TLS ciphers if a TLS handshake actually succeeded"*, *"only enumerate SMB
shares if 445 answered"*.

Same rule as recipes: **declarative only, no executable content.** A condition
is a small structured record -- observation name, operator, value -- evaluated
by :class:`Condition.evaluate` against the observations previous steps
produced. There is no expression string, no ``eval``, and no way for a YAML
file to name a Python callable. A malformed condition is a load-time error, not
a runtime surprise.

Two invariants carry over from the rest of the platform and are enforced here:

* **A skipped step is a recorded decision, not an omission.** When a condition
  is false the step yields a ``SKIPPED`` outcome carrying the reason, so a
  playbook run can always account for every step it declared.
* **No step may assign a verdict.** Playbooks order evidence gathering; they
  have no opinion on what the evidence means.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PlaybookError(ValueError):
    """A playbook is structurally invalid. Raised at load time, never at run time."""


class Operator(Enum):
    """The complete set of comparisons a condition may express.

    Deliberately small. Every operator here is total -- it returns True or False
    for any pair of values, including missing ones -- so a condition can never
    raise mid-run and abandon a half-written evidence file.
    """

    IS_TRUE = "is_true"
    IS_FALSE = "is_false"
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    EXISTS = "exists"
    MISSING = "missing"
    IN = "in"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"

    @property
    def needs_value(self) -> bool:
        return self not in {
            Operator.IS_TRUE, Operator.IS_FALSE, Operator.EXISTS, Operator.MISSING,
        }


@dataclass(frozen=True)
class Condition:
    """``observation <operator> value``, as data.

    ``observation`` names a key produced by an earlier step's parser. A
    condition referring to an observation no step can produce is a load-time
    error (see :func:`validate_playbook`), because silently never firing is
    indistinguishable from working.
    """

    observation: str
    operator: Operator
    value: Any = None
    #: Which step produced the observation. Empty means "any earlier step".
    from_step: str = ""

    def describe(self) -> str:
        where = f"{self.from_step}." if self.from_step else ""
        if not self.operator.needs_value:
            return f"{where}{self.observation} {self.operator.value.replace('_', ' ')}"
        return f"{where}{self.observation} {self.operator.value.replace('_', ' ')} {self.value!r}"

    def evaluate(self, observations: dict[str, Any]) -> bool:
        """Total: never raises, whatever the observations contain."""
        present = self.observation in observations
        actual = observations.get(self.observation)

        if self.operator is Operator.EXISTS:
            return present
        if self.operator is Operator.MISSING:
            return not present
        if self.operator is Operator.IS_TRUE:
            return actual is True
        if self.operator is Operator.IS_FALSE:
            return actual is False
        if not present:
            # An absent observation satisfies no value comparison. "Not equals"
            # included: absence is unknown, not inequality, and treating it as a
            # match would run steps on evidence nobody gathered.
            return False
        if self.operator is Operator.EQUALS:
            return bool(actual == self.value)
        if self.operator is Operator.NOT_EQUALS:
            return bool(actual != self.value)
        if self.operator is Operator.CONTAINS:
            return _contains(actual, self.value)
        if self.operator is Operator.NOT_CONTAINS:
            return not _contains(actual, self.value)
        if self.operator is Operator.IN:
            return _is_in(actual, self.value)
        if self.operator is Operator.GREATER_THAN:
            return _compare(actual, self.value, greater=True)
        if self.operator is Operator.LESS_THAN:
            return _compare(actual, self.value, greater=False)
        return False  # pragma: no cover - Operator is exhaustive above

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "observation": self.observation,
            "operator": self.operator.value,
        }
        if self.operator.needs_value:
            data["value"] = self.value
        if self.from_step:
            data["from_step"] = self.from_step
        return data

    @classmethod
    def from_dict(cls, data: Any) -> Condition:
        if not isinstance(data, dict):
            raise PlaybookError(
                f"a condition must be a mapping with 'observation' and 'operator', got {data!r}"
            )
        observation = str(data.get("observation", "")).strip()
        if not observation:
            raise PlaybookError(f"condition is missing 'observation': {data!r}")
        raw_operator = str(data.get("operator", "")).strip()
        try:
            operator = Operator(raw_operator)
        except ValueError as exc:
            allowed = ", ".join(sorted(o.value for o in Operator))
            raise PlaybookError(
                f"unknown condition operator {raw_operator!r} for observation "
                f"{observation!r}; allowed operators are: {allowed}"
            ) from exc
        if operator.needs_value and "value" not in data:
            raise PlaybookError(
                f"operator {operator.value!r} on {observation!r} requires a 'value'"
            )
        return cls(
            observation=observation,
            operator=operator,
            value=data.get("value"),
            from_step=str(data.get("from_step", "")).strip(),
        )


def _contains(actual: Any, needle: Any) -> bool:
    if isinstance(actual, str):
        return str(needle).lower() in actual.lower()
    if isinstance(actual, (list, tuple, set)):
        return any(str(needle).lower() == str(item).lower() for item in actual)
    if isinstance(actual, dict):
        return str(needle) in actual
    return False


def _is_in(actual: Any, allowed: Any) -> bool:
    if isinstance(allowed, (list, tuple, set)):
        return any(str(actual).lower() == str(item).lower() for item in allowed)
    return _contains(allowed, actual)


def _compare(actual: Any, expected: Any, *, greater: bool) -> bool:
    try:
        left, right = float(actual), float(expected)
    except (TypeError, ValueError):
        return False
    return left > right if greater else left < right


@dataclass
class PlaybookStep:
    """One ordered step: an adapter, its parameters, and when to run it."""

    step_id: str
    adapter: str
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    #: All conditions must hold (AND). An empty list means "always run".
    when: list[Condition] = field(default_factory=list)
    optional: bool = False
    #: Continue the playbook when this step fails. False stops the chain, which
    #: is right when later steps would only produce uninterpretable output.
    continue_on_failure: bool = True

    @property
    def is_conditional(self) -> bool:
        return bool(self.when)

    def should_run(self, observations: dict[str, Any]) -> tuple[bool, str]:
        """``(run, reason)``. The reason is recorded either way."""
        if not self.when:
            return True, "unconditional step"
        for condition in self.when:
            if not condition.evaluate(observations):
                return False, f"condition not met: {condition.describe()}"
        return True, "; ".join(c.describe() for c in self.when)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "adapter": self.adapter,
            "description": self.description,
            "params": dict(self.params),
            "when": [c.to_dict() for c in self.when],
            "optional": self.optional,
            "continue_on_failure": self.continue_on_failure,
        }

    @classmethod
    def from_dict(cls, data: Any) -> PlaybookStep:
        if not isinstance(data, dict):
            raise PlaybookError(f"a playbook step must be a mapping, got {data!r}")
        step_id = str(data.get("step_id", "")).strip()
        if not step_id:
            raise PlaybookError(f"playbook step is missing 'step_id': {data!r}")
        adapter = str(data.get("adapter", "")).strip()
        if not adapter:
            raise PlaybookError(f"playbook step {step_id!r} is missing 'adapter'")
        raw_when = data.get("when", []) or []
        if isinstance(raw_when, dict):  # a single condition, unwrapped
            raw_when = [raw_when]
        if not isinstance(raw_when, list):
            raise PlaybookError(
                f"'when' on step {step_id!r} must be a condition or a list of conditions"
            )
        params = data.get("params", {}) or {}
        if not isinstance(params, dict):
            raise PlaybookError(f"'params' on step {step_id!r} must be a mapping")
        return cls(
            step_id=step_id,
            adapter=adapter,
            description=str(data.get("description", "")),
            params=dict(params),
            when=[Condition.from_dict(c) for c in raw_when],
            optional=bool(data.get("optional", False)),
            continue_on_failure=bool(data.get("continue_on_failure", True)),
        )


@dataclass
class Playbook:
    """An ordered, conditional pipeline for one verification family."""

    playbook_id: str
    version: str = "1"
    title: str = ""
    description: str = ""
    #: Verification families this playbook applies to (matches Recipe.family).
    families: list[str] = field(default_factory=list)
    #: Recipe ids this playbook applies to; more specific than ``families``.
    recipe_ids: list[str] = field(default_factory=list)
    steps: list[PlaybookStep] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def step(self, step_id: str) -> PlaybookStep | None:
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None

    def applies_to(self, *, family: str = "", recipe_id: str = "") -> bool:
        if recipe_id and recipe_id in self.recipe_ids:
            return True
        return bool(family) and family in self.families

    def required_adapters(self) -> list[str]:
        return sorted({s.adapter for s in self.steps})

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "families": list(self.families),
            "recipe_ids": list(self.recipe_ids),
            "steps": [s.to_dict() for s in self.steps],
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: Any) -> Playbook:
        if not isinstance(data, dict):
            raise PlaybookError(f"a playbook must be a mapping, got {data!r}")
        playbook_id = str(data.get("playbook_id", "")).strip()
        if not playbook_id:
            raise PlaybookError(f"playbook is missing 'playbook_id': {data!r}")
        raw_steps = data.get("steps", []) or []
        if not isinstance(raw_steps, list):
            raise PlaybookError(f"'steps' on playbook {playbook_id!r} must be a list")
        steps = [PlaybookStep.from_dict(s) for s in raw_steps]
        seen: set[str] = set()
        for step in steps:
            if step.step_id in seen:
                raise PlaybookError(
                    f"playbook {playbook_id!r} has duplicate step id {step.step_id!r}; "
                    "step ids address conditions and evidence, so they must be unique"
                )
            seen.add(step.step_id)
        return cls(
            playbook_id=playbook_id,
            version=str(data.get("version", "1")),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            families=[str(f) for f in data.get("families", []) or []],
            recipe_ids=[str(r) for r in data.get("recipe_ids", []) or []],
            steps=steps,
            notes=[str(n) for n in data.get("notes", []) or []],
        )
