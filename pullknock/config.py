"""YAML configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError
from .util import expand_path, parse_cidr


@dataclass(frozen=True)
class ServerConfig:
    id: str
    control_url: str
    poll_interval_seconds: int = 5
    poll_jitter_seconds: int = 2
    http_timeout_seconds: int = 5
    control_headers: dict[str, str] | None = None


@dataclass(frozen=True)
class SecurityConfig:
    allowed_signers_file: str
    nonce_db: str
    signature_namespace: str = "pullknock-v1"
    max_clock_skew_seconds: int = 30
    max_command_ttl_seconds: int = 120
    nonce_retention_seconds: int = 604800


@dataclass(frozen=True)
class FirewallConfig:
    backend: str = "firewalld"
    firewall_cmd: str = "/usr/bin/firewall-cmd"
    default_zone: str = "public"


@dataclass(frozen=True)
class PortConfig:
    protocol: str
    port: int


@dataclass(frozen=True)
class UserPolicy:
    principal: str
    enabled: bool = True
    display_name: str | None = None
    allowed_grants: tuple[str, ...] | None = None
    max_timeout_seconds: int | None = None
    not_before: int | None = None
    expires_at: int | None = None
    allow_source_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class GrantConfig:
    id: str
    description: str
    allowed_principals: tuple[str, ...]
    ports: tuple[PortConfig, ...]
    max_timeout_seconds: int
    zone: str | None
    allow_source_cidrs: tuple[str, ...]


@dataclass(frozen=True)
class AgentConfig:
    server: ServerConfig
    security: SecurityConfig
    firewall: FirewallConfig
    users: dict[str, UserPolicy]
    grants: dict[str, GrantConfig]


@dataclass(frozen=True)
class DefaultsConfig:
    principal: str
    private_key: str
    signature_namespace: str = "pullknock-v1"
    command_ttl_seconds: int = 60
    requested_timeout_seconds: int = 60
    ssh_keygen: str = "ssh-keygen"


@dataclass(frozen=True)
class PublisherConfig:
    name: str
    type: str
    options: dict[str, Any]


@dataclass(frozen=True)
class TargetConfig:
    name: str
    target: str
    grant_id: str
    publisher: str


@dataclass(frozen=True)
class CliConfig:
    defaults: DefaultsConfig
    publishers: dict[str, PublisherConfig]
    targets: dict[str, TargetConfig]


def load_agent_config(path: str) -> AgentConfig:
    data = _load_yaml(path)
    server_data = _mapping(data.get("server"), "server")
    security_data = _mapping(data.get("security"), "security")
    firewall_data = _mapping(data.get("firewall", {}), "firewall")

    server = ServerConfig(
        id=_required_str(server_data, "id", "server"),
        control_url=_required_str(server_data, "control_url", "server"),
        poll_interval_seconds=_positive_int(server_data.get("poll_interval_seconds", 5), "server.poll_interval_seconds"),
        poll_jitter_seconds=_nonnegative_int(server_data.get("poll_jitter_seconds", 2), "server.poll_jitter_seconds"),
        http_timeout_seconds=_positive_int(server_data.get("http_timeout_seconds", 5), "server.http_timeout_seconds"),
        control_headers=_optional_str_map(server_data.get("control_headers"), "server.control_headers"),
    )
    security = SecurityConfig(
        allowed_signers_file=expand_path(_required_str(security_data, "allowed_signers_file", "security")),
        nonce_db=expand_path(_required_str(security_data, "nonce_db", "security")),
        signature_namespace=str(security_data.get("signature_namespace", "pullknock-v1")),
        max_clock_skew_seconds=_nonnegative_int(
            security_data.get("max_clock_skew_seconds", 30), "security.max_clock_skew_seconds"
        ),
        max_command_ttl_seconds=_positive_int(
            security_data.get("max_command_ttl_seconds", 120), "security.max_command_ttl_seconds"
        ),
        nonce_retention_seconds=_positive_int(
            security_data.get("nonce_retention_seconds", 604800), "security.nonce_retention_seconds"
        ),
    )
    firewall = FirewallConfig(
        backend=str(firewall_data.get("backend", "firewalld")),
        firewall_cmd=str(firewall_data.get("firewall_cmd", "/usr/bin/firewall-cmd")),
        default_zone=str(firewall_data.get("default_zone", "public")),
    )
    users = _load_users(data.get("users", {}))
    grants = _load_grants(data.get("grants"))
    return AgentConfig(server=server, security=security, firewall=firewall, users=users, grants=grants)


def load_cli_config(path: str) -> CliConfig:
    data = _load_yaml(path)
    defaults_data = _mapping(data.get("defaults"), "defaults")
    defaults = DefaultsConfig(
        principal=_required_str(defaults_data, "principal", "defaults"),
        private_key=expand_path(_required_str(defaults_data, "private_key", "defaults")),
        signature_namespace=str(defaults_data.get("signature_namespace", "pullknock-v1")),
        command_ttl_seconds=_positive_int(defaults_data.get("command_ttl_seconds", 60), "defaults.command_ttl_seconds"),
        requested_timeout_seconds=_positive_int(
            defaults_data.get("requested_timeout_seconds", 60), "defaults.requested_timeout_seconds"
        ),
        ssh_keygen=str(defaults_data.get("ssh_keygen", "ssh-keygen")),
    )
    publishers = _load_publishers(data.get("publishers"))
    targets = _load_targets(data.get("targets"), publishers)
    return CliConfig(defaults=defaults, publishers=publishers, targets=targets)


def _load_yaml(path: str) -> dict[str, Any]:
    expanded = expand_path(path)
    try:
        raw = Path(expanded).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot_read_config: {expanded}: {exc}") from exc
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid_yaml: {expanded}: {exc}") from exc
    return _mapping(data, "root")


def _load_users(value: Any) -> dict[str, UserPolicy]:
    data = _mapping(value or {}, "users")
    users: dict[str, UserPolicy] = {}
    for principal, raw_policy in data.items():
        if not isinstance(principal, str) or not principal:
            raise ConfigError("users keys must be non-empty principal strings")
        policy = _mapping(raw_policy or {}, f"users.{principal}")
        allowed_grants = _optional_str_tuple(policy.get("allowed_grants"), f"users.{principal}.allowed_grants")
        max_timeout = policy.get("max_timeout_seconds")
        cidrs = _optional_str_tuple(policy.get("allow_source_cidrs"), f"users.{principal}.allow_source_cidrs") or ()
        for cidr in cidrs:
            parse_cidr(cidr)
        users[principal] = UserPolicy(
            principal=principal,
            enabled=bool(policy.get("enabled", True)),
            display_name=policy.get("display_name"),
            allowed_grants=allowed_grants,
            max_timeout_seconds=None
            if max_timeout is None
            else _positive_int(max_timeout, f"users.{principal}.max_timeout_seconds"),
            not_before=_optional_timestamp(policy.get("not_before"), f"users.{principal}.not_before"),
            expires_at=_optional_timestamp(policy.get("expires_at"), f"users.{principal}.expires_at"),
            allow_source_cidrs=cidrs,
        )
    return users


def _load_grants(value: Any) -> dict[str, GrantConfig]:
    data = _mapping(value, "grants")
    grants: dict[str, GrantConfig] = {}
    for grant_id, raw_grant in data.items():
        if not isinstance(grant_id, str) or not grant_id:
            raise ConfigError("grant ids must be non-empty strings")
        grant = _mapping(raw_grant, f"grants.{grant_id}")
        ports = []
        for index, raw_port in enumerate(_list(grant.get("ports"), f"grants.{grant_id}.ports")):
            port_data = _mapping(raw_port, f"grants.{grant_id}.ports[{index}]")
            protocol = _required_str(port_data, "protocol", f"grants.{grant_id}.ports[{index}]").lower()
            if protocol not in {"tcp", "udp"}:
                raise ConfigError(f"unsupported_protocol: grants.{grant_id}.ports[{index}].protocol")
            port = _positive_int(port_data.get("port"), f"grants.{grant_id}.ports[{index}].port")
            if port > 65535:
                raise ConfigError(f"invalid_port: grants.{grant_id}.ports[{index}].port")
            ports.append(PortConfig(protocol=protocol, port=port))
        allowed_principals = _str_tuple(grant.get("allowed_principals"), f"grants.{grant_id}.allowed_principals")
        cidrs = _str_tuple(grant.get("allow_source_cidrs"), f"grants.{grant_id}.allow_source_cidrs")
        for cidr in cidrs:
            parse_cidr(cidr)
        grants[grant_id] = GrantConfig(
            id=grant_id,
            description=str(grant.get("description", "")),
            allowed_principals=allowed_principals,
            ports=tuple(ports),
            max_timeout_seconds=_positive_int(
                grant.get("max_timeout_seconds"), f"grants.{grant_id}.max_timeout_seconds"
            ),
            zone=grant.get("zone"),
            allow_source_cidrs=cidrs,
        )
    return grants


def _load_publishers(value: Any) -> dict[str, PublisherConfig]:
    data = _mapping(value, "publishers")
    publishers: dict[str, PublisherConfig] = {}
    for name, raw_pub in data.items():
        if not isinstance(name, str) or not name:
            raise ConfigError("publisher names must be non-empty strings")
        pub = _mapping(raw_pub, f"publishers.{name}")
        pub_type = _required_str(pub, "type", f"publishers.{name}").lower()
        options = {key: item for key, item in pub.items() if key != "type"}
        publishers[name] = PublisherConfig(name=name, type=pub_type, options=options)
    return publishers


def _load_targets(value: Any, publishers: dict[str, PublisherConfig]) -> dict[str, TargetConfig]:
    data = _mapping(value, "targets")
    targets: dict[str, TargetConfig] = {}
    for name, raw_target in data.items():
        if not isinstance(name, str) or not name:
            raise ConfigError("target names must be non-empty strings")
        target = _mapping(raw_target, f"targets.{name}")
        publisher = _required_str(target, "publisher", f"targets.{name}")
        if publisher not in publishers:
            raise ConfigError(f"unknown_publisher: targets.{name}.publisher={publisher}")
        targets[name] = TargetConfig(
            name=name,
            target=_required_str(target, "target", f"targets.{name}"),
            grant_id=_required_str(target, "grant_id", f"targets.{name}"),
            publisher=publisher,
        )
    return targets


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{name} must be a non-empty list")
    return value


def _required_str(data: dict[str, Any], key: str, scope: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{scope}.{key} must be a non-empty string")
    return value


def _str_tuple(value: Any, name: str) -> tuple[str, ...]:
    items = _list(value, name)
    result = tuple(item for item in items if isinstance(item, str) and item)
    if len(result) != len(items):
        raise ConfigError(f"{name} must contain only non-empty strings")
    return result


def _optional_str_tuple(value: Any, name: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    return _str_tuple(value, name)


def _optional_str_map(value: Any, name: str) -> dict[str, str] | None:
    if value is None:
        return None
    data = _mapping(value, name)
    result = {}
    for key, item in data.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ConfigError(f"{name} must map strings to strings")
        result[key] = item
    return result


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{name} must be a non-negative integer")
    return value


def _optional_timestamp(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ConfigError(f"{name} must be a unix timestamp or ISO datetime")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
        try:
            return int(datetime.fromisoformat(stripped.replace("Z", "+00:00")).timestamp())
        except ValueError as exc:
            raise ConfigError(f"{name} must be a unix timestamp or ISO datetime") from exc
    raise ConfigError(f"{name} must be a unix timestamp or ISO datetime")
