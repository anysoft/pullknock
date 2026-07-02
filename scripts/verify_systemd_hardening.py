#!/usr/bin/env python3
"""Verify expected hardening directives in systemd unit files."""

from __future__ import annotations

import configparser
import sys
from pathlib import Path


COMMON_REQUIRED = {
    "NoNewPrivileges": "true",
    "PrivateTmp": "true",
    "ProtectHome": "true",
    "ProtectSystem": "full",
}

SERVICE_EXPECTATIONS = {
    "systemd/pullknock-agent.service": {
        **COMMON_REQUIRED,
        "User": "root",
        "Group": "root",
        "CapabilityBoundingSet": "CAP_NET_ADMIN CAP_NET_RAW",
        "AmbientCapabilities": "CAP_NET_ADMIN CAP_NET_RAW",
        "ReadWritePaths": "/var/lib/pullknock /var/log/pullknock",
        "ExecReload": "/bin/kill -HUP $MAINPID",
    },
    "systemd/pullknock-publisher.service": {
        **COMMON_REQUIRED,
        "User": "pullknock",
        "Group": "pullknock",
        "ReadWritePaths": "/var/lib/pullknock-publisher",
    },
}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    for relative_path, expectations in SERVICE_EXPECTATIONS.items():
        service_path = root / relative_path
        service = read_service(service_path)
        for key, expected in expectations.items():
            actual = service.get(key)
            if actual != expected:
                errors.append(f"{relative_path}: expected {key}={expected!r}, got {actual!r}")
        if relative_path.endswith("publisher.service") and (
            "CapabilityBoundingSet" in service or "AmbientCapabilities" in service
        ):
            errors.append(f"{relative_path}: publisher must not request Linux capabilities")
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("systemd hardening OK")
    return 0


def read_service(path: Path) -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(path, encoding="utf-8")
    if not parser.has_section("Service"):
        raise SystemExit(f"{path}: missing [Service] section")
    return dict(parser.items("Service"))


if __name__ == "__main__":
    raise SystemExit(main())
