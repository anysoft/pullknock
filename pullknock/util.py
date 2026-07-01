"""Small shared helpers."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

from .errors import ProtocolError


def expand_path(path: str) -> str:
    return os.path.abspath(os.path.expandvars(os.path.expanduser(path)))


def expand_env_value(value: Any) -> Any:
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {key: expand_env_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [expand_env_value(item) for item in value]
    return value


def utc_timestamp() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def utc_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def parse_ip(value: str):
    try:
        return ip_address(value)
    except ValueError as exc:
        raise ProtocolError(f"invalid_ip: {value}") from exc


def parse_cidr(value: str):
    try:
        return ip_network(value, strict=False)
    except ValueError as exc:
        raise ProtocolError(f"invalid_cidr: {value}") from exc
