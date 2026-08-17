"""The CLI's help screen is tiered; nothing is actually removed.

`--help` lists the core workflow. Every other command still parses, still has
its own `--help`, and is listed by `vapt-verify commands`. These tests exist
because "hidden" and "gone" are one careless edit apart, and a hidden command
that stopped working would show no symptom until an operator needed it.
"""

from __future__ import annotations

import argparse

import pytest

from vapt_verify.cli.main import COMMAND_GROUPS, CORE_COMMANDS, build_parser, main


def _registered_commands() -> dict[str, argparse.ArgumentParser]:
    parser = build_parser()
    action = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    return dict(action.choices)


def _listed_in_help() -> set[str]:
    parser = build_parser()
    action = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    return {choice.dest for choice in action._choices_actions}


def test_help_lists_only_the_core_workflow() -> None:
    assert _listed_in_help() == set(CORE_COMMANDS)


def test_help_never_prints_the_suppress_sentinel(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """argparse renders a literal "==SUPPRESS==" row for a subparser choice
    whose help is SUPPRESS -- the row has to be absent, not suppressed."""
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "SUPPRESS" not in out


def test_every_hidden_command_still_parses_and_has_its_own_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Hiding is presentation. A hidden command that stopped working would
    show no symptom until an operator went looking for it."""
    registered = _registered_commands()
    hidden = sorted(set(registered) - set(CORE_COMMANDS))
    assert hidden, "nothing is hidden; this test is no longer measuring anything"
    for name in hidden:
        with pytest.raises(SystemExit) as exc:
            main([name, "--help"])
        assert exc.value.code == 0, f"`vapt-verify {name} --help` failed"
        out = capsys.readouterr().out
        assert f"vapt-verify {name}" in out


def test_commands_listing_covers_every_registered_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A command absent from the listing is invisible: not in --help either."""
    listed_roots = {
        name.split()[0] for _t, _b, entries in COMMAND_GROUPS for name, _h in entries
    }
    registered = set(_registered_commands())
    # `commands` itself is the listing, so it is not a row in its own output.
    missing = registered - listed_roots - {"commands"}
    assert not missing, f"registered but undiscoverable: {sorted(missing)}"
    stale = listed_roots - registered
    assert not stale, f"listed but not registered: {sorted(stale)}"


def test_commands_listing_names_real_subcommands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`kit build` in the listing has to actually be `kit build`."""
    registered = _registered_commands()
    for _title, _blurb, entries in COMMAND_GROUPS:
        for name, _help in entries:
            parts = name.split()
            if len(parts) == 1:
                continue
            parent = registered[parts[0]]
            child_action = next(
                a for a in parent._actions if isinstance(a, argparse._SubParsersAction)
            )
            assert parts[1] in child_action.choices, f"`{name}` does not exist"


def test_commands_prints_the_groups(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["commands"]) == 0
    out = capsys.readouterr().out
    for title, _blurb, _entries in COMMAND_GROUPS:
        assert title in out
    assert "kit build" in out
    assert "correlate" in out


def test_help_epilog_states_the_workflow_order(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An operator's first question is 'which of these do I run, and when?'."""
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "A normal engagement, in order:" in out
    for step in ("prepare", "select", "kit build", "kit import", "review", "poc export"):
        assert step in out
    assert "vapt-verify commands" in out
