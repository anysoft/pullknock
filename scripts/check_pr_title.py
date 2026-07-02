#!/usr/bin/env python3
"""Validate a pull request title with a small Conventional Commits subset."""

from __future__ import annotations

import argparse
import re
import sys


ALLOWED_TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "release",
    "revert",
    "security",
    "test",
)

TITLE_RE = re.compile(
    r"^(?P<type>[a-z]+)(?:\([a-z0-9][a-z0-9._/-]*\))?(?P<breaking>!)?: (?P<subject>.+)$"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("title", help="Pull request title to validate")
    args = parser.parse_args()

    return check_title(args.title)


def check_title(title: str) -> int:
    if len(title) > 120:
        print("PR title is too long; keep it at 120 characters or less.", file=sys.stderr)
        return 1

    match = TITLE_RE.match(title)
    if not match:
        print_invalid(title)
        return 1

    title_type = match.group("type")
    subject = match.group("subject")
    if title_type not in ALLOWED_TYPES:
        print(f"Unsupported PR title type: {title_type}", file=sys.stderr)
        print(f"Allowed types: {', '.join(ALLOWED_TYPES)}", file=sys.stderr)
        return 1

    if subject.strip() != subject or len(subject.strip()) < 3:
        print("PR title subject must be meaningful and must not have surrounding spaces.", file=sys.stderr)
        return 1

    if subject.endswith("."):
        print("PR title subject should not end with a period.", file=sys.stderr)
        return 1

    print("PR title OK")
    return 0


def print_invalid(title: str) -> None:
    print(f"Invalid PR title: {title}", file=sys.stderr)
    print("Use Conventional Commits style, for example:", file=sys.stderr)
    print("  feat(agent): add nftables backend", file=sys.stderr)
    print("  fix(protocol): reject malformed source IP", file=sys.stderr)
    print("  docs: update deployment guide", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
