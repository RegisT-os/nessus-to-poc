"""Allow ``python -m vapt_verify`` as an alternative to the console script.

On Windows the ``Scripts\\`` directory is frequently not on ``PATH``, so
``vapt-verify`` may appear "not installed" even when it is. Running the module
form always works:

    python -m vapt_verify doctor
"""

from vapt_verify.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
