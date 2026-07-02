#!/usr/bin/env python3
"""Run dependency vulnerability scanning for PullKnock."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

from _toml_compat import tomllib


def main() -> int:
    if importlib.util.find_spec("pip_audit") is None:
        print("pip-audit is not installed. Install with: python -m pip install -e '.[security]'", file=sys.stderr)
        return 1
    root = Path(__file__).resolve().parents[1]
    dependencies = load_runtime_dependencies(root / "pyproject.toml")
    if not dependencies:
        print("No runtime dependencies found in pyproject.toml [project].dependencies")
        return 0
    print("Auditing runtime dependencies from pyproject.toml", flush=True)
    for dependency in dependencies:
        print(f"- {dependency}", flush=True)
    with tempfile.TemporaryDirectory(prefix="pullknock-audit-") as temp_dir:
        requirements_path = Path(temp_dir) / "requirements.txt"
        requirements_path.write_text("\n".join(dependencies) + "\n", encoding="utf-8")
        return run_pip_audit(str(requirements_path))


def load_runtime_dependencies(pyproject_path: Path) -> list[str]:
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    dependencies = data.get("project", {}).get("dependencies", [])
    return [str(dependency) for dependency in dependencies]


def run_pip_audit(requirements_path: str) -> int:
    args = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        requirements_path,
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
