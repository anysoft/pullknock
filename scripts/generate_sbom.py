#!/usr/bin/env python3
"""Generate a minimal CycloneDX SBOM for the PullKnock package."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=None, help="Output path. Defaults to dist/pullknock-<version>-sbom.cdx.json.")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    version = project["version"]
    output = Path(args.output) if args.output else root / "dist" / f"pullknock-{version}-sbom.cdx.json"
    if not output.is_absolute():
        output = root / output
    output.parent.mkdir(parents=True, exist_ok=True)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "tools": [{"vendor": "PullKnock", "name": "scripts/generate_sbom.py"}],
            "component": component(project["name"], version, "application"),
        },
        "components": [dependency_component(requirement) for requirement in project.get("dependencies", [])],
    }
    output.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"generated {display_path(output, root)}")
    return 0


def component(name: str, version: str | None, component_type: str) -> dict[str, str]:
    item = {
        "type": component_type,
        "name": name,
        "bom-ref": f"pkg:pypi/{normalize_name(name)}" + (f"@{version}" if version else ""),
        "purl": f"pkg:pypi/{normalize_name(name)}" + (f"@{version}" if version else ""),
    }
    if version:
        item["version"] = version
    return item


def dependency_component(requirement: str) -> dict[str, str]:
    name, version_spec = split_requirement(requirement)
    item = component(name, None, "library")
    if version_spec:
        item["version"] = version_spec
    return item


def split_requirement(requirement: str) -> tuple[str, str]:
    requirement = requirement.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", requirement)
    if not match:
        return requirement, ""
    return match.group(1), match.group(2).strip()


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
