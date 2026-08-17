"""Resolve a real POSIX shell for tests that syntax-check generated scripts.

Originally written for the runbook tests (`fix/windows-bash-resolution-in-tests`);
kept and moved here when the runbook generator was removed, because the kit
tests shell out for exactly the same reasons and would hit exactly the same
Windows failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def posix_shell(name: str) -> str:
    r"""Absolute path to a working POSIX shell, or skip the test.

    Passing a bare ``"bash"`` to ``subprocess`` is not portable to Windows:
    ``CreateProcess`` searches System32 *before* PATH, so the name resolves to
    the WSL launcher (``C:\Windows\System32\bash.exe``) even when Git Bash is
    first on PATH -- ``shutil.which`` and the child process disagree. On a
    machine with no WSL distro installed that launcher fails with an
    ``execvpe`` error, which reads as a shell *syntax* failure here and hides
    whether the generated script is actually valid.

    So resolve an explicit interpreter, reject the two Windows shims, and
    prove the candidate runs before handing it to a test.
    """
    candidates: list[str] = []
    if os.name == "nt":
        for var, default in (
            ("ProgramFiles", r"C:\Program Files"),
            ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ):
            git = Path(os.environ.get(var, default)) / "Git"
            candidates += [
                str(git / "bin" / f"{name}.exe"),
                str(git / "usr" / "bin" / f"{name}.exe"),
            ]

    found = shutil.which(name)
    # System32 is the WSL launcher; WindowsApps is the Store app-execution alias.
    if found and not any(shim in found.lower() for shim in ("system32", "windowsapps")):
        candidates.append(found)

    for candidate in candidates:
        if not Path(candidate).exists():
            continue
        try:
            probe = subprocess.run([candidate, "-c", "exit 0"], capture_output=True, timeout=30)
        except OSError:
            continue
        if probe.returncode == 0:
            return candidate

    pytest.skip(f"no working POSIX {name!r} on this machine")
