"""Declarative verification playbooks (roadmap v3.1).

Two things these tests defend.

**No executable content.** A playbook is data. Conditions are structured
records, so a YAML file cannot name a Python callable, smuggle an expression
string past ``yaml.safe_load``, or reach anything at evaluation time beyond the
observations previous steps produced.

**A condition that can never fire is an error, not a no-op.** A typo'd
observation name, or a step reading output only a *later* step produces, yields
a step that silently never runs -- indistinguishable from one that legitimately
does not apply. Validation turns that into a load-time message.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from vapt_verify.adapters import all_adapters, get_adapter
from vapt_verify.cli.main import main
from vapt_verify.playbooks import (
    Condition,
    Operator,
    Playbook,
    PlaybookError,
    PlaybookLibrary,
    PlaybookStep,
    describe_playbook,
    validate_library,
    validate_playbook,
)

# --- conditions -------------------------------------------------------------


def _c(observation: str, operator: str, value: object = None, **kw: object) -> Condition:
    return Condition.from_dict(
        {"observation": observation, "operator": operator, "value": value, **kw}
    )


@pytest.mark.parametrize(
    "operator,value,observations,expected",
    [
        ("is_true", None, {"connected": True}, True),
        ("is_true", None, {"connected": False}, False),
        ("is_true", None, {"connected": "yes"}, False),  # truthy is not True
        ("is_false", None, {"connected": False}, True),
        ("equals", "open", {"connected": "open"}, True),
        ("not_equals", "open", {"connected": "closed"}, True),
        ("contains", "TLSv1.", {"connected": "Protocol: TLSv1.2"}, True),
        ("contains", "tlsv1.", {"connected": "Protocol: TLSv1.2"}, True),  # case-insensitive
        ("not_contains", "TLSv1.3", {"connected": "TLSv1.2"}, True),
        ("in", ["open", "filtered"], {"connected": "open"}, True),
        ("in", ["open"], {"connected": "closed"}, False),
        ("greater_than", 1, {"connected": 2}, True),
        ("less_than", 1, {"connected": 0}, True),
    ],
)
def test_operators_evaluate_as_documented(
    operator: str, value: object, observations: dict[str, object], expected: bool
) -> None:
    assert _c("connected", operator, value).evaluate(observations) is expected


def test_exists_and_missing_distinguish_absence_from_falseness() -> None:
    assert _c("connected", "exists").evaluate({"connected": False}) is True
    assert _c("connected", "exists").evaluate({}) is False
    assert _c("connected", "missing").evaluate({}) is True
    assert _c("connected", "missing").evaluate({"connected": None}) is False


def test_an_absent_observation_satisfies_no_value_comparison() -> None:
    """Absence is unknown, not inequality.

    If `not_equals` matched a missing observation, a step gated on "the protocol
    is not TLS 1.3" would run against a host nobody successfully probed.
    """
    for operator, value in [
        ("equals", "x"), ("not_equals", "x"), ("contains", "x"),
        ("not_contains", "x"), ("in", ["x"]), ("greater_than", 1), ("less_than", 1),
    ]:
        assert _c("connected", operator, value).evaluate({}) is False, operator


@pytest.mark.parametrize(
    "observations",
    [{}, {"connected": None}, {"connected": object()}, {"connected": [1, 2]},
     {"connected": {"a": 1}}, {"connected": "text"}],
)
def test_evaluation_never_raises(observations: dict[str, object]) -> None:
    """A condition must not abort a run part-way and orphan an evidence file."""
    for operator in Operator:
        condition = Condition(observation="connected", operator=operator, value=1)
        assert isinstance(condition.evaluate(observations), bool)


# --- no executable content --------------------------------------------------


def test_a_condition_must_be_structured_not_an_expression_string() -> None:
    """There is no expression syntax to smuggle code through."""
    with pytest.raises(PlaybookError, match="must be a mapping"):
        Condition.from_dict("connected == True")
    with pytest.raises(PlaybookError, match="must be a mapping"):
        Condition.from_dict("__import__('os').system('id')")


def test_an_unknown_operator_is_rejected_with_the_allowed_set() -> None:
    with pytest.raises(PlaybookError, match="unknown condition operator"):
        Condition.from_dict({"observation": "x", "operator": "eval"})


def test_an_operator_needing_a_value_must_be_given_one() -> None:
    with pytest.raises(PlaybookError, match="requires a 'value'"):
        Condition.from_dict({"observation": "x", "operator": "equals"})


def test_builtin_playbooks_contain_no_executable_keys() -> None:
    """The YAML must not carry anything that looks like code or a callable."""
    from importlib import resources

    forbidden = ("!!python", "eval", "exec(", "lambda", "__import__", "subprocess", "os.system")
    anchor = resources.files("vapt_verify.playbooks.data")
    files = [e for e in anchor.iterdir() if e.name.endswith((".yaml", ".yml"))]
    assert files, "no packaged playbooks found"
    for entry in files:
        text = entry.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{entry.name} contains {token!r}"
        # Parses under safe_load, which refuses arbitrary python tags outright.
        assert yaml.safe_load(text)


# --- steps ------------------------------------------------------------------


def test_an_unconditional_step_always_runs() -> None:
    step = PlaybookStep(step_id="s", adapter="tcp")
    run, reason = step.should_run({})
    assert run is True
    assert reason == "unconditional step"


def test_conditions_are_anded() -> None:
    step = PlaybookStep(
        step_id="s", adapter="openssl",
        when=[_c("port_open", "is_true"), _c("protocol", "contains", "TLS")],
    )
    assert step.should_run({"port_open": True, "protocol": "TLSv1.2"})[0] is True
    assert step.should_run({"port_open": True, "protocol": "SSLv3"})[0] is False
    assert step.should_run({"port_open": False, "protocol": "TLSv1.2"})[0] is False


def test_a_skipped_step_reports_which_condition_failed() -> None:
    """A skip is a recorded decision; a run must account for every declared step."""
    step = PlaybookStep(step_id="s", adapter="openssl", when=[_c("port_open", "is_true")])
    run, reason = step.should_run({"port_open": False})
    assert run is False
    assert "port_open is true" in reason


# --- structural validation --------------------------------------------------


def _playbook(steps: list[dict[str, object]], **kw: object) -> Playbook:
    return Playbook.from_dict({"playbook_id": "test-pb", "steps": steps, **kw})


def test_duplicate_step_ids_are_rejected() -> None:
    """Step ids address conditions and evidence, so they must be unique."""
    with pytest.raises(PlaybookError, match="duplicate step id"):
        _playbook([
            {"step_id": "a", "adapter": "tcp"},
            {"step_id": "a", "adapter": "nmap"},
        ])


def test_a_step_without_an_adapter_is_rejected() -> None:
    with pytest.raises(PlaybookError, match="missing 'adapter'"):
        _playbook([{"step_id": "a"}])


def test_an_unregistered_adapter_is_reported() -> None:
    problems = validate_playbook(_playbook([{"step_id": "a", "adapter": "nosuchtool"}]))
    assert any("is not registered" in p for p in problems)


def test_a_conditional_first_step_can_never_fire() -> None:
    problems = validate_playbook(_playbook([
        {"step_id": "a", "adapter": "openssl",
         "when": [{"observation": "port_open", "operator": "is_true"}]},
    ]))
    assert any("first step is conditional" in p for p in problems)


def test_a_condition_reading_a_later_step_can_never_fire() -> None:
    """The subtle one: forward references look plausible and never run."""
    problems = validate_playbook(_playbook([
        {"step_id": "first", "adapter": "tcp"},
        {"step_id": "second", "adapter": "openssl",
         "when": [{"observation": "port_state", "operator": "is_true",
                   "from_step": "third"}]},
        {"step_id": "third", "adapter": "nmap"},
    ]))
    assert any("can never be true" in p for p in problems)


def test_a_condition_reading_its_own_step_can_never_fire() -> None:
    problems = validate_playbook(_playbook([
        {"step_id": "first", "adapter": "tcp"},
        {"step_id": "second", "adapter": "openssl",
         "when": [{"observation": "connected", "operator": "is_true",
                   "from_step": "second"}]},
    ]))
    assert any("can never be true" in p for p in problems)


def test_a_condition_on_an_unknown_step_is_reported() -> None:
    problems = validate_playbook(_playbook([
        {"step_id": "first", "adapter": "tcp"},
        {"step_id": "second", "adapter": "openssl",
         "when": [{"observation": "connected", "operator": "is_true",
                   "from_step": "typo"}]},
    ]))
    assert any("unknown step" in p for p in problems)


def test_a_typoed_observation_is_reported() -> None:
    """`conected` would produce a step that silently never runs."""
    problems = validate_playbook(_playbook([
        {"step_id": "first", "adapter": "openssl"},
        {"step_id": "second", "adapter": "nmap",
         "when": [{"observation": "conected", "operator": "is_true"}]},
    ]))
    assert any("conected" in p and "no earlier step declares" in p for p in problems)


def test_an_observation_an_earlier_step_declares_is_accepted() -> None:
    assert validate_playbook(_playbook([
        {"step_id": "first", "adapter": "openssl"},
        {"step_id": "second", "adapter": "nmap",
         "when": [{"observation": "connected", "operator": "is_true"}]},
    ])) == []


def test_universal_observations_are_always_available() -> None:
    assert validate_playbook(_playbook([
        {"step_id": "first", "adapter": "nmap"},
        {"step_id": "second", "adapter": "openssl",
         "when": [{"observation": "timed_out", "operator": "is_false"}]},
    ])) == []


def test_an_undeclared_adapter_suppresses_typo_warnings_rather_than_lying() -> None:
    """Validation must not invent problems for adapters it cannot introspect."""
    assert not get_adapter("database").produces_observations
    assert validate_playbook(_playbook([
        {"step_id": "first", "adapter": "database"},
        {"step_id": "second", "adapter": "nmap",
         "when": [{"observation": "anything_at_all", "operator": "is_true"}]},
    ])) == []


def test_an_empty_playbook_is_reported() -> None:
    assert any("has no steps" in p for p in validate_playbook(_playbook([])))


# --- the shipped library ----------------------------------------------------


def test_builtin_library_loads_and_validates() -> None:
    library = PlaybookLibrary.load_builtin()
    assert len(library) >= 4
    assert validate_library(library) == {}


def test_builtin_playbooks_reference_only_registered_adapters() -> None:
    registered = {a.name for a in all_adapters()}
    for playbook in PlaybookLibrary.load_builtin().playbooks:
        for adapter in playbook.required_adapters():
            assert adapter in registered, f"{playbook.playbook_id} uses unknown {adapter!r}"


def test_expensive_steps_are_gated_on_a_successful_handshake() -> None:
    """The reason playbooks exist: don't run testssl against a dead port."""
    playbook = PlaybookLibrary.load_builtin().by_id("tls-certificate-chain")
    assert playbook is not None
    survey = playbook.step("protocol-survey")
    assert survey is not None
    assert survey.is_conditional
    assert not survey.should_run({"port_open": True})[0]  # handshake never ran
    assert survey.should_run({"connected": True})[0]


def test_playbooks_resolve_by_recipe_then_by_family() -> None:
    library = PlaybookLibrary.load_builtin()
    by_recipe = library.for_recipe("tls-certificate")
    assert by_recipe is not None and by_recipe.playbook_id == "tls-certificate-chain"
    by_family = library.for_recipe("some-unmapped-recipe", family="ssh")
    assert by_family is not None and by_family.playbook_id == "ssh-algorithms"
    assert library.for_recipe("nope", family="nope") is None


def test_playbook_round_trips_through_its_dict_form() -> None:
    original = PlaybookLibrary.load_builtin().by_id("tls-certificate-chain")
    assert original is not None
    restored = Playbook.from_dict(original.to_dict())
    assert restored.to_dict() == original.to_dict()


def test_describe_renders_conditions_readably() -> None:
    playbook = PlaybookLibrary.load_builtin().by_id("tls-certificate-chain")
    assert playbook is not None
    text = "\n".join(describe_playbook(playbook))
    assert "run only if: handshake.connected is true" in text
    assert "runs unconditionally" in text


def test_operator_overrides_are_layered_on_top(tmp_path: Path, monkeypatch) -> None:
    override = tmp_path / "playbooks"
    override.mkdir()
    (override / "custom.yaml").write_text(
        "playbooks:\n"
        "  - playbook_id: tls-certificate-chain\n"
        "    title: Locally overridden\n"
        "    steps:\n"
        "      - {step_id: only, adapter: tcp}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VAPT_VERIFY_PLAYBOOKS_DIR", str(override))
    playbook = PlaybookLibrary.load_builtin().by_id("tls-certificate-chain")
    assert playbook is not None
    assert playbook.title == "Locally overridden"


def test_malformed_yaml_names_the_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("playbooks:\n  - step_id: no-playbook-id\n", encoding="utf-8")
    with pytest.raises(PlaybookError, match=r"bad\.yaml"):
        PlaybookLibrary.load_dirs([tmp_path])


# --- CLI --------------------------------------------------------------------


def test_cli_list(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["playbook", "list"]) == 0
    out = capsys.readouterr().out
    assert "tls-certificate-chain" in out
    assert "applies to:" in out


def test_cli_show(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["playbook", "show", "tls-certificate-chain"]) == 0
    out = capsys.readouterr().out
    assert "run only if: handshake.connected is true" in out


def test_cli_show_unknown_lists_what_is_available(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["playbook", "show", "nope"]) == 2
    assert "Available:" in capsys.readouterr().out


def test_cli_validate_passes_for_the_shipped_library(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["playbook", "validate"]) == 0
    assert "every condition can fire" in capsys.readouterr().out


def test_cli_validate_fails_closed_on_a_broken_playbook(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "broken.yaml").write_text(
        "playbooks:\n"
        "  - playbook_id: broken\n"
        "    steps:\n"
        "      - {step_id: a, adapter: tcp}\n"
        "      - step_id: b\n"
        "        adapter: nmap\n"
        "        when: [{observation: nonexistent_thing, operator: is_true}]\n",
        encoding="utf-8",
    )
    assert main(["playbook", "validate", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "nonexistent_thing" in out
    assert "FAILED" in out
