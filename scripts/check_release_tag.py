#!/usr/bin/env python3
"""Validate release tag, package version, and CHANGELOG alignment."""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        default=None,
        help="Release tag, for example v0.1.0. Defaults to GITHUB_REF_NAME only when GITHUB_REF_TYPE=tag.",
    )
    parser.add_argument("--require-tag", action="store_true", help="Fail when no tag is available.")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    version = load_pyproject_version(root)
    init_version = load_init_version(root)
    if init_version != version:
        print(f"version mismatch: pyproject={version} __init__={init_version}", file=sys.stderr)
        return 1

    changelog = root / "CHANGELOG.md"
    if not changelog.exists():
        print("CHANGELOG.md is required", file=sys.stderr)
        return 1
    if not has_changelog_version(changelog.read_text(encoding="utf-8"), version):
        print(f"CHANGELOG.md must contain section: ## v{version}", file=sys.stderr)
        return 1

    tag = resolve_release_tag(args.tag)
    if tag:
        if not tag.startswith("v"):
            print(f"release tag must start with v, got {tag}", file=sys.stderr)
            return 1
        if tag != f"v{version}":
            print(f"tag/version mismatch: tag={tag} package=v{version}", file=sys.stderr)
            return 1
    elif args.require_tag:
        print("release tag is required", file=sys.stderr)
        return 1

    tag_label = tag or f"v{version} (tag check skipped)"
    print(f"release tag OK: {tag_label}")
    return 0


def resolve_release_tag(explicit_tag: str | None) -> str:
    if explicit_tag:
        return explicit_tag
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        return os.environ.get("GITHUB_REF_NAME") or ""
    return ""


def load_pyproject_version(root: Path) -> str:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["project"]["version"]


def load_init_version(root: Path) -> str:
    init_text = (root / "pullknock" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if not match:
        raise SystemExit("missing pullknock.__version__")
    return match.group(1)


def has_changelog_version(text: str, version: str) -> bool:
    return re.search(rf"^## v{re.escape(version)}\s*$", text, re.MULTILINE) is not None


if __name__ == "__main__":
    raise SystemExit(main())
