#!/usr/bin/env python3
"""Validate CHANGELOG release notes for the current package version."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from _toml_compat import tomllib

REQUIRED_SECTIONS = ("Added", "Changed", "Fixed", "Security", "Migration")
TEMPLATE = """Expected CHANGELOG.md format:

## v{version}

### Added

### Changed

### Fixed

### Security

### Migration
"""


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    version = load_version(root)
    changelog = root / "CHANGELOG.md"
    if not changelog.exists():
        print("CHANGELOG.md is required", file=sys.stderr)
        print(TEMPLATE.format(version=version), file=sys.stderr)
        return 1

    text = changelog.read_text(encoding="utf-8")
    section = extract_version_section(text, version)
    if section is None:
        print(f"CHANGELOG.md must contain section: ## v{version}", file=sys.stderr)
        print(TEMPLATE.format(version=version), file=sys.stderr)
        return 1
    missing = [name for name in REQUIRED_SECTIONS if f"### {name}" not in section]
    if missing:
        print(f"CHANGELOG.md v{version} missing sections: {', '.join(missing)}", file=sys.stderr)
        print(TEMPLATE.format(version=version), file=sys.stderr)
        return 1

    ref_name = os.environ.get("GITHUB_REF_NAME")
    if ref_name and ref_name.startswith("v") and ref_name != f"v{version}":
        print(f"tag/version mismatch: tag={ref_name} package=v{version}", file=sys.stderr)
        return 1

    print(f"release notes OK for v{version}")
    return 0


def load_version(root: Path) -> str:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["project"]["version"]


def extract_version_section(text: str, version: str) -> str | None:
    pattern = re.compile(rf"^## v{re.escape(version)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return None
    next_match = re.search(r"^## v[0-9]", text[match.end() :], re.MULTILINE)
    if next_match:
        return text[match.end() : match.end() + next_match.start()]
    return text[match.end() :]


if __name__ == "__main__":
    raise SystemExit(main())
