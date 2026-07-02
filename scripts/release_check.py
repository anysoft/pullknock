#!/usr/bin/env python3
"""Run local checks that should pass before publishing to PyPI."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from _toml_compat import tomllib


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    init_text = (root / "pullknock" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if not match:
        print("missing pullknock.__version__", file=sys.stderr)
        return 1
    if match.group(1) != version:
        print(f"version mismatch: pyproject={version} __init__={match.group(1)}", file=sys.stderr)
        return 1

    run([sys.executable, "scripts/check_release_tag.py"], cwd=root)
    run([sys.executable, "scripts/check_release_notes.py"], cwd=root)
    run([sys.executable, "scripts/extract_release_notes.py"], cwd=root)
    run([sys.executable, "scripts/check_pr_title.py", "feat(agent): add config reload"], cwd=root)
    run([sys.executable, "scripts/verify_systemd_hardening.py"], cwd=root)
    run([sys.executable, "scripts/generate_config_schema_docs.py"], cwd=root)
    run([sys.executable, "-m", "compileall", "pullknock", "tests", "scripts"], cwd=root)
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=root)
    run([sys.executable, "scripts/e2e_file_mode.py"], cwd=root)
    run([sys.executable, "-m", "build"], cwd=root)
    dist_files = sorted(
        str(path.relative_to(root))
        for pattern in ("*.whl", "*.tar.gz")
        for path in (root / "dist").glob(pattern)
    )
    run([sys.executable, "-m", "twine", "check", *dist_files], cwd=root)
    run([sys.executable, "scripts/verify_wheel_install.py"], cwd=root)
    run([sys.executable, "scripts/generate_sbom.py"], cwd=root)
    print(f"release checks OK for version {version}")
    return 0


def run(args: list[str], *, cwd: Path) -> None:
    subprocess.run(args, cwd=str(cwd), check=True)


if __name__ == "__main__":
    raise SystemExit(main())
