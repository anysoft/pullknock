#!/usr/bin/env python3
"""Extract release notes for a version from CHANGELOG.md."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from _toml_compat import tomllib


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=None, help="Version without leading v. Defaults to pyproject version.")
    parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to changelog file.")
    parser.add_argument("--output", default=None, help="Write notes to this file instead of stdout.")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    version = args.version or load_version(root)
    changelog = Path(args.changelog)
    if not changelog.is_absolute():
        changelog = root / changelog
    text = changelog.read_text(encoding="utf-8")
    notes = extract_version_section(text, version)
    if notes is None:
        print(f"missing CHANGELOG section: ## v{version}", file=sys.stderr)
        return 1
    notes = notes.strip() + "\n"
    if args.output:
        output = Path(args.output)
        output.write_text(notes, encoding="utf-8")
    else:
        print(notes, end="")
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
