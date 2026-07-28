# Running on Windows

The platform is fully supported on Windows. This page covers install, the exact
commands (they differ from Linux/macOS), and the problems people actually hit.

## Install

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install .
```

For development (editable + dev tools):

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Running the CLI

On Windows the executables live in `.venv\Scripts\`, **not** `.venv/bin/`:

```powershell
.\.venv\Scripts\vapt-verify.exe doctor
```

If `vapt-verify` is "not recognized", the `Scripts` directory is not on `PATH`.
The module form always works and needs no `PATH` changes:

```powershell
.\.venv\Scripts\python.exe -m vapt_verify doctor
```

## Start with `doctor`

`doctor` is the first thing to run when anything misbehaves. It reports the
Python and platform in use, the console encoding, **where the recipe library
resolved to and how many recipes loaded**, which optional tools are present, and
whether the CLI is on `PATH`. It exits non-zero if the environment is unhealthy.

```powershell
.\.venv\Scripts\python.exe -m vapt_verify doctor
```

## Importing a `.nessus` file

```powershell
.\.venv\Scripts\vapt-verify.exe engagement create --id demo
.\.venv\Scripts\vapt-verify.exe import --engagement demo "C:\scans\report.nessus"
```

Paths copied from Explorer with **Copy as path** arrive wrapped in double
quotes; that is handled — the quotes are stripped automatically. `~` is expanded
too.

## Known issues and how they present

| Symptom | Cause | Status |
|---|---|---|
| `RuntimeError: manual-review-fallback recipe is missing from the library` on `classify`/`plan`/`run` | Recipes were not shipped as package data, so a normal `pip install` had no recipe library | **Fixed** — recipes ship inside the package and load via `importlib.resources`. Verify with `doctor`. |
| `UnicodeEncodeError` on almost any command, including `--help` | Legacy console code page (cp1252/cp437) could not encode typographic characters in output | **Fixed** — CLI output is ASCII and stdout/stderr are reconfigured defensively at startup |
| `ParseError: not well-formed (invalid token)` when importing | File re-saved with a UTF-8 BOM or as UTF-16 (Notepad/Excel), or it is not really XML | **Fixed** — encodings are detected and handled; non-XML files produce a clear message |
| Import fails and the file "looks fine" | The download returned an HTML login/error page saved as `.nessus` | **Fixed** — detected explicitly with an actionable message |
| `'vapt-verify' is not recognized` | `.venv\Scripts` not on `PATH` | Use `python -m vapt_verify`, as `doctor` advises |

If you hit something not listed here, re-run the failing command with
`--traceback` and share the output:

```powershell
.\.venv\Scripts\python.exe -m vapt_verify import --engagement demo "C:\scans\report.nessus" --traceback
```

## Notes

- **Verification tools** (`nmap`, `openssl`, `testssl.sh`, …) are optional. If
  they are missing on Windows, findings are **never** dropped — they receive a
  `tool_capability_unavailable` disposition and stay fully visible in coverage.
- **Long paths**: if engagement paths exceed 260 characters, enable
  `LongPathsEnabled` in Windows, or use a shorter `--base` directory.
- Reports are written as UTF-8; open `dashboard.html` in any browser.
