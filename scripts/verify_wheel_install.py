#!/usr/bin/env python3
"""Install the built wheel in a clean venv and run CLI smoke checks."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from _toml_compat import tomllib


CONSOLE_SCRIPTS = (
    "pullknock",
    "pullknock-agent",
    "pullknock-publisher",
    "pullknock-configgen",
    "pullknock-admin",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", default="dist", help="Directory containing built wheel artifacts.")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    version = load_version(root)
    wheel = find_wheel(root / args.dist_dir, version)
    with tempfile.TemporaryDirectory(prefix="pullknock-wheel-smoke-") as temp_dir:
        venv_dir = Path(temp_dir) / "venv"
        run([sys.executable, "-m", "venv", str(venv_dir)])
        python = venv_python(venv_dir)
        run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
        run([str(python), "-m", "pip", "install", str(wheel)])
        run([str(python), "-c", f"import pullknock; assert pullknock.__version__ == '{version}'"])
        bin_dir = python.parent
        for script in CONSOLE_SCRIPTS:
            run([str(bin_dir / script), "--help"])
    print(f"wheel install smoke OK: {wheel.name}")
    return 0


def load_version(root: Path) -> str:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["project"]["version"]


def find_wheel(dist_dir: Path, version: str) -> Path:
    wheels = sorted(dist_dir.glob(f"pullknock-{version}-*.whl"))
    if not wheels:
        raise SystemExit(f"missing built wheel for version {version}; run python -m build first")
    if len(wheels) > 1:
        raise SystemExit(f"multiple wheels found for version {version}: {', '.join(path.name for path in wheels)}")
    return wheels[0]


def venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def run(args: list[str]) -> None:
    subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


if __name__ == "__main__":
    raise SystemExit(main())
