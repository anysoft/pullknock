#!/usr/bin/env python3
"""Run dependency vulnerability scanning for PullKnock."""

from __future__ import annotations

import importlib.util
import subprocess
import sys


def main() -> int:
    if importlib.util.find_spec("pip_audit") is None:
        print("pip-audit is not installed. Install with: python -m pip install -e '.[security]'", file=sys.stderr)
        return 1
    args = [
        sys.executable,
        "-m",
        "pip_audit",
        "--strict",
        "--progress-spinner",
        "off",
        "--desc",
    ]
    try:
        subprocess.run(args, check=True)
    except subprocess.CalledProcessError as exc:
        return exc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
