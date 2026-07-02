"""YAML configuration loading and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError
from .util import expand_env_value, expand_path, parse_cidr

SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
SAFE_ZONE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SUPPORTED_PUBLISHER_TYPES = {
    "file",
    "http_put",
    "webdav_put",
    "ftp_upload",
    "ftps_upload",
    "ipfs_http",
    "s3_put",
}
SUPPORTED_FIREWALL_BACKENDS = {"firewalld", "nftables"}


@dataclass(frozen=True)
class ServerConfig:
    id: str
    control_url: str
    control_urls: tuple[str, ...] = ()
    poll_interval_seconds: int = 5
    poll_jitter_seconds: int = 2
    http_timeout_seconds: int = 5
    control_headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if not self.control_urls:
            object.__setattr__(self, "control_urls", (self.control_url,))


@dataclass(frozen=True)
class SecurityConfig:
    nonce_db: str
    signature_namespace: str = "pullknock-v1"
    max_clock_skew_seconds: int = 30
    max_command_ttl_seconds: int = 120
    nonce_retention_seconds: int = 604800
    age: "AgeConfig | None" = None


@dataclass(frozen=True)
class AgeConfig:
    age_cmd: str = "age"
    envelope_version: int = 2
    key_id: str | None = None
    recipients: tuple[str, ...] = ()
    recipient_files: tuple[str, ...] = ()
    identity_files: tuple[str, ...] = ()


@dataclass(frozen=True)
class FirewallConfig:
    backend: str = "firewalld"
    firewall_cmd: str = "/usr/bin/firewall-cmd"
    default_zone: str = "public"
    nft_cmd: str = "/usr/sbin/nft"
    nft_family: str = "inet"
    nft_table: str = "pullknock"
    nft_set_prefix: str = "pullknock"
    nft_setup_sets: bool = True


@dataclass(frozen=True)
class AuditConfig:
    log_file: str | None = None


@dataclass(frozen=True)
class PortConfig:
    protocol: str
    port: int


@dataclass(frozen=True)
class UserPolicy:
    principal: str
    enabled: bool = True
    display_name: str | None = None
    groups: tuple[str, ...] = ()
    keys: tuple["UserKeyPolicy", ...] = ()
    allowed_grants: tuple[str, ...] | None = None
    max_timeout_seconds: int | None = None
    not_before: int | None = None
    expires_at: int | None = None
    allow_source_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class UserKeyPolicy:
    id: str
    public_key: str
    enabled: bool = True
    not_before: int | None = None
    expires_at: int | None = None
    comment: str | None = None


@dataclass(frozen=True)
class GrantConfig:
    id: str
    description: str
    allowed_principals: tuple[str, ...]
    ports: tuple[PortConfig, ...]
    max_timeout_seconds: int
    zone: str | None
    allow_source_cidrs: tuple[str, ...]
    allowed_groups: tuple[str, ...] = ()
    inherits: tuple[str, ...] = ()


@dataclass(frozen=True)
class GroupPolicy:
    name: str
    enabled: bool = True
    display_name: str | None = None
    allowed_grants: tuple[str, ...] | None = None
    max_timeout_seconds: int | None = None
    not_before: int | None = None
    expires_at: int | None = None
    allow_source_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentConfig:
    server: ServerConfig
    security: SecurityConfig
    firewall: FirewallConfig
    users: dict[str, UserPolicy]
    grants: dict[str, GrantConfig]
    groups: dict[str, GroupPolicy] | None = None
    audit: AuditConfig = AuditConfig()


@dataclass(frozen=True)
class DefaultsConfig:
    principal: str
    private_key: str
    signature_namespace: str = "pullknock-v1"
    command_ttl_seconds: int = 60
    requested_timeout_seconds: int = 60
    ssh_keygen: str = "ssh-keygen"
    age: AgeConfig | None = None


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


@dataclass(frozen=True)
class PublisherServiceHttpConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    path: str = "/pullknock-command.json"
    health_path: str = "/healthz"
    max_body_bytes: int = 65536


@dataclass(frozen=True)
class PublisherServiceStorageConfig:
    envelope_file: str
    mode: str = "latest"
    queue_dir: str | None = None


@dataclass(frozen=True)
class PublisherServiceAuthConfig:
    write_bearer_tokens: tuple[str, ...]
    read_bearer_tokens: tuple[str, ...] = ()
    require_auth_for_read: bool = False


@dataclass(frozen=True)
class PublisherServiceConfig:
    http: PublisherServiceHttpConfig
    storage: PublisherServiceStorageConfig
    auth: PublisherServiceAuthConfig


def load_agent_config(path: str) -> AgentConfig:
    data = _load_yaml(path)
    server_data = _mapping(data.get("server"), "server")
    security_data = _mapping(data.get("security"), "security")
    firewall_data = _mapping(data.get("firewall", {}), "firewall")
    audit_data = _mapping(data.get("audit", {}), "audit")
    control_urls = _load_control_urls(server_data)

    server = ServerConfig(
        id=_required_str(server_data, "id", "server"),
        control_url=control_urls[0],
        control_urls=control_urls,
        poll_interval_seconds=_positive_int(server_data.get("poll_interval_seconds", 5), "server.poll_interval_seconds"),
        poll_jitter_seconds=_nonnegative_int(server_data.get("poll_jitter_seconds", 2), "server.poll_jitter_seconds"),
        http_timeout_seconds=_positive_int(server_data.get("http_timeout_seconds", 5), "server.http_timeout_seconds"),
        control_headers=_optional_str_map(server_data.get("control_headers"), "server.control_headers"),
    )
    security = SecurityConfig(
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
        age=_load_age_config(security_data.get("age"), "security.age", for_agent=True),
    )
    _validate_safe_id(server.id, "server.id")
    _validate_signature_namespace(security.signature_namespace)
    firewall = FirewallConfig(
        backend=str(firewall_data.get("backend", "firewalld")),
        firewall_cmd=str(firewall_data.get("firewall_cmd", "/usr/bin/firewall-cmd")),
        default_zone=str(firewall_data.get("default_zone", "public")),
        nft_cmd=str(firewall_data.get("nft_cmd", "/usr/sbin/nft")),
        nft_family=str(firewall_data.get("nft_family", "inet")),
        nft_table=str(firewall_data.get("nft_table", "pullknock")),
        nft_set_prefix=str(firewall_data.get("nft_set_prefix", "pullknock")),
        nft_setup_sets=bool(firewall_data.get("nft_setup_sets", True)),
    )
    _validate_firewall_config(firewall)
    audit_log_file = audit_data.get("log_file")
    audit = AuditConfig(
        log_file=None if audit_log_file is None else expand_path(_required_str(audit_data, "log_file", "audit")),
    )
    groups = _load_groups(data.get("groups", {}))
    users = _load_users(data.get("users", {}), groups)
    grants = _load_grants(data.get("grants"), groups)
    if not users:
        raise ConfigError("users must contain at least one principal with keys")
    missing_keys = [principal for principal, user in users.items() if not user.keys]
    if missing_keys:
        raise ConfigError("users missing keys: " + ", ".join(sorted(missing_keys)))
    return AgentConfig(
        server=server,
        security=security,
        firewall=firewall,
        audit=audit,
        users=users,
        groups=groups,
        grants=grants,
    )


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
        age=_load_age_config(defaults_data.get("age"), "defaults.age", for_agent=False),
    )
    _validate_safe_id(defaults.principal, "defaults.principal")
    _validate_signature_namespace(defaults.signature_namespace)
    publishers = _load_publishers(data.get("publishers"))
    targets = _load_targets(data.get("targets"), publishers)
    return CliConfig(defaults=defaults, publishers=publishers, targets=targets)


def load_publisher_service_config(path: str) -> PublisherServiceConfig:
    data = expand_env_value(_load_yaml(path))
    server_data = _mapping(data.get("server", {}), "server")
    storage_data = _mapping(data.get("storage"), "storage")
    auth_data = _mapping(data.get("auth"), "auth")

    publish_path = str(server_data.get("path", "/pullknock-command.json"))
    health_path = str(server_data.get("health_path", "/healthz"))
    _validate_http_path(publish_path, "server.path")
    _validate_http_path(health_path, "server.health_path")
    if publish_path == health_path:
        raise ConfigError("server.path and server.health_path must be different")

    write_tokens = _str_tuple(auth_data.get("write_bearer_tokens"), "auth.write_bearer_tokens")
    read_tokens = _optional_str_tuple_allow_empty(auth_data.get("read_bearer_tokens"), "auth.read_bearer_tokens")
    if any("${" in token or "$" in token for token in write_tokens + read_tokens):
        raise ConfigError("publisher bearer tokens contain unresolved environment variables")
    if any(not token.strip() for token in write_tokens + read_tokens):
        raise ConfigError("publisher bearer tokens must not be empty")

    require_auth_for_read = bool(auth_data.get("require_auth_for_read", False))
    if require_auth_for_read and not read_tokens:
        read_tokens = write_tokens

    storage_mode = str(storage_data.get("mode", "latest")).lower()
    if storage_mode not in {"latest", "queue"}:
        raise ConfigError("storage.mode must be latest or queue")
    queue_dir = storage_data.get("queue_dir")
    if queue_dir is not None and (not isinstance(queue_dir, str) or not queue_dir):
        raise ConfigError("storage.queue_dir must be a non-empty string")

    return PublisherServiceConfig(
        http=PublisherServiceHttpConfig(
            host=str(server_data.get("host", "127.0.0.1")),
            port=_nonnegative_int(server_data.get("port", 8080), "server.port"),
            path=publish_path,
            health_path=health_path,
            max_body_bytes=_positive_int(server_data.get("max_body_bytes", 65536), "server.max_body_bytes"),
        ),
        storage=PublisherServiceStorageConfig(
            envelope_file=expand_path(_required_str(storage_data, "envelope_file", "storage")),
            mode=storage_mode,
            queue_dir=expand_path(queue_dir) if queue_dir else None,
        ),
        auth=PublisherServiceAuthConfig(
            write_bearer_tokens=write_tokens,
            read_bearer_tokens=read_tokens,
            require_auth_for_read=require_auth_for_read,
        ),
    )


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


def _load_groups(value: Any) -> dict[str, GroupPolicy]:
    data = _mapping(value or {}, "groups")
    groups: dict[str, GroupPolicy] = {}
    for name, raw_group in data.items():
        if not isinstance(name, str) or not name:
            raise ConfigError("groups keys must be non-empty strings")
        _validate_safe_id(name, f"groups.{name}")
        group = _mapping(raw_group or {}, f"groups.{name}")
        allowed_grants = _optional_str_tuple(group.get("allowed_grants"), f"groups.{name}.allowed_grants")
        if allowed_grants:
            for grant_id in allowed_grants:
                _validate_safe_id(grant_id, f"groups.{name}.allowed_grants")
        cidrs = _optional_str_tuple(group.get("allow_source_cidrs"), f"groups.{name}.allow_source_cidrs") or ()
        for cidr in cidrs:
            parse_cidr(cidr)
        max_timeout = group.get("max_timeout_seconds")
        groups[name] = GroupPolicy(
            name=name,
            enabled=bool(group.get("enabled", True)),
            display_name=group.get("display_name"),
            allowed_grants=allowed_grants,
            max_timeout_seconds=None if max_timeout is None else _positive_int(max_timeout, f"groups.{name}.max_timeout_seconds"),
            not_before=_optional_timestamp(group.get("not_before"), f"groups.{name}.not_before"),
            expires_at=_optional_timestamp(group.get("expires_at"), f"groups.{name}.expires_at"),
            allow_source_cidrs=cidrs,
        )
    return groups


def _load_users(value: Any, groups: dict[str, GroupPolicy]) -> dict[str, UserPolicy]:
    data = _mapping(value or {}, "users")
    users: dict[str, UserPolicy] = {}
    for principal, raw_policy in data.items():
        if not isinstance(principal, str) or not principal:
            raise ConfigError("users keys must be non-empty principal strings")
        _validate_safe_id(principal, f"users.{principal}")
        policy = _mapping(raw_policy or {}, f"users.{principal}")
        if "public_keys" in policy:
            raise ConfigError(f"users.{principal}.public_keys is unsupported; use users.{principal}.keys")
        allowed_grants = _optional_str_tuple(policy.get("allowed_grants"), f"users.{principal}.allowed_grants")
        if allowed_grants:
            for grant_id in allowed_grants:
                _validate_safe_id(grant_id, f"users.{principal}.allowed_grants")
        user_groups = _optional_str_tuple_allow_empty(policy.get("groups"), f"users.{principal}.groups")
        for group_name in user_groups:
            _validate_safe_id(group_name, f"users.{principal}.groups")
            if group_name not in groups:
                raise ConfigError(f"unknown_group: users.{principal}.groups={group_name}")
        max_timeout = policy.get("max_timeout_seconds")
        cidrs = _optional_str_tuple(policy.get("allow_source_cidrs"), f"users.{principal}.allow_source_cidrs") or ()
        user_keys = _load_user_keys(principal, policy.get("keys"))
        for cidr in cidrs:
            parse_cidr(cidr)
        users[principal] = UserPolicy(
            principal=principal,
            enabled=bool(policy.get("enabled", True)),
            display_name=policy.get("display_name"),
            groups=user_groups,
            keys=user_keys,
            allowed_grants=allowed_grants,
            max_timeout_seconds=None
            if max_timeout is None
            else _positive_int(max_timeout, f"users.{principal}.max_timeout_seconds"),
            not_before=_optional_timestamp(policy.get("not_before"), f"users.{principal}.not_before"),
            expires_at=_optional_timestamp(policy.get("expires_at"), f"users.{principal}.expires_at"),
            allow_source_cidrs=cidrs,
        )
    return users


def _load_user_keys(principal: str, value: Any) -> tuple[UserKeyPolicy, ...]:
    if value is None:
        return ()
    raw_items = _list(value, f"users.{principal}.keys")
    result: list[UserKeyPolicy] = []
    seen: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        item = _mapping(raw_item, f"users.{principal}.keys[{index}]")
        key_id = _required_str(item, "id", f"users.{principal}.keys[{index}]")
        _validate_safe_id(key_id, f"users.{principal}.keys[{index}].id")
        if key_id in seen:
            raise ConfigError(f"duplicate_key_id: users.{principal}.keys={key_id}")
        seen.add(key_id)
        public_key = _required_str(item, "public_key", f"users.{principal}.keys[{index}]")
        _validate_public_key(public_key, f"users.{principal}.keys[{index}].public_key")
        result.append(
            UserKeyPolicy(
                id=key_id,
                public_key=public_key,
                enabled=bool(item.get("enabled", True)),
                not_before=_optional_timestamp(item.get("not_before"), f"users.{principal}.keys[{index}].not_before"),
                expires_at=_optional_timestamp(item.get("expires_at"), f"users.{principal}.keys[{index}].expires_at"),
                comment=item.get("comment"),
            )
        )
    return tuple(result)


def _load_control_urls(server_data: dict[str, Any]) -> tuple[str, ...]:
    has_single = "control_url" in server_data
    has_many = "control_urls" in server_data
    if not has_single and not has_many:
        raise ConfigError("server.control_url or server.control_urls is required")

    urls: list[str] = []
    if has_many:
        urls.extend(_str_tuple(server_data.get("control_urls"), "server.control_urls"))
    if has_single:
        single = _required_str(server_data, "control_url", "server")
        if single not in urls:
            urls.insert(0, single)

    if not urls:
        raise ConfigError("server.control_urls must contain at least one URL or path")
    for index, url in enumerate(urls):
        if _has_control_chars(url):
            raise ConfigError(f"server.control_urls[{index}] contains invalid control characters")
    return tuple(urls)


def _load_grants(value: Any, groups: dict[str, GroupPolicy]) -> dict[str, GrantConfig]:
    data = _mapping(value, "grants")
    raw_grants: dict[str, dict[str, Any]] = {}
    for grant_id, raw_grant in data.items():
        if not isinstance(grant_id, str) or not grant_id:
            raise ConfigError("grant ids must be non-empty strings")
        _validate_safe_id(grant_id, f"grants.{grant_id}")
        raw_grants[grant_id] = _mapping(raw_grant, f"grants.{grant_id}")

    grants: dict[str, GrantConfig] = {}
    resolving: set[str] = set()
    for grant_id in raw_grants:
        _resolve_grant(grant_id, raw_grants, grants, resolving, groups)
    return grants


def _resolve_grant(
    grant_id: str,
    raw_grants: dict[str, dict[str, Any]],
    resolved: dict[str, GrantConfig],
    resolving: set[str],
    groups: dict[str, GroupPolicy],
) -> GrantConfig:
    if grant_id in resolved:
        return resolved[grant_id]
    if grant_id in resolving:
        raise ConfigError(f"grant_inheritance_cycle: {grant_id}")
    resolving.add(grant_id)
    grant = raw_grants[grant_id]
    inherits = _optional_str_tuple_allow_empty(grant.get("inherits"), f"grants.{grant_id}.inherits")
    parents = []
    for parent_id in inherits:
        _validate_safe_id(parent_id, f"grants.{grant_id}.inherits")
        if parent_id not in raw_grants:
            raise ConfigError(f"unknown_grant_parent: grants.{grant_id}.inherits={parent_id}")
        parents.append(_resolve_grant(parent_id, raw_grants, resolved, resolving, groups))

    inherited_ports: list[PortConfig] = []
    inherited_principals: list[str] = []
    inherited_groups: list[str] = []
    inherited_cidrs: list[str] = []
    inherited_timeout: int | None = None
    inherited_zone: str | None = None
    inherited_description = ""
    for parent in parents:
        inherited_ports.extend(parent.ports)
        inherited_principals.extend(parent.allowed_principals)
        inherited_groups.extend(parent.allowed_groups)
        inherited_cidrs.extend(parent.allow_source_cidrs)
        inherited_timeout = parent.max_timeout_seconds if inherited_timeout is None else min(inherited_timeout, parent.max_timeout_seconds)
        inherited_zone = parent.zone if inherited_zone is None else inherited_zone
        if parent.description and not inherited_description:
            inherited_description = parent.description

    ports = []
    raw_ports = grant.get("ports")
    if raw_ports is None:
        ports.extend(inherited_ports)
    else:
        for index, raw_port in enumerate(_list(raw_ports, f"grants.{grant_id}.ports")):
            port_data = _mapping(raw_port, f"grants.{grant_id}.ports[{index}]")
            protocol = _required_str(port_data, "protocol", f"grants.{grant_id}.ports[{index}]").lower()
            if protocol not in {"tcp", "udp"}:
                raise ConfigError(f"unsupported_protocol: grants.{grant_id}.ports[{index}].protocol")
            port = _positive_int(port_data.get("port"), f"grants.{grant_id}.ports[{index}].port")
            if port > 65535:
                raise ConfigError(f"invalid_port: grants.{grant_id}.ports[{index}].port")
            ports.append(PortConfig(protocol=protocol, port=port))
        if inherited_ports and bool(grant.get("merge_inherited_ports", False)):
            ports = _dedupe_ports([*inherited_ports, *ports])
    if not ports:
        raise ConfigError(f"grants.{grant_id}.ports must be configured or inherited")

    allowed_principals = _optional_str_tuple_allow_empty(
        grant.get("allowed_principals"), f"grants.{grant_id}.allowed_principals"
    )
    for principal in allowed_principals:
        _validate_safe_id(principal, f"grants.{grant_id}.allowed_principals")
    allowed_groups = _optional_str_tuple_allow_empty(grant.get("allowed_groups"), f"grants.{grant_id}.allowed_groups")
    for group_name in allowed_groups:
        _validate_safe_id(group_name, f"grants.{grant_id}.allowed_groups")
        if group_name not in groups:
            raise ConfigError(f"unknown_group: grants.{grant_id}.allowed_groups={group_name}")
    final_principals = _dedupe_strs([*inherited_principals, *allowed_principals])
    final_groups = _dedupe_strs([*inherited_groups, *allowed_groups])
    if not final_principals and not final_groups:
        raise ConfigError(f"grants.{grant_id}.allowed_principals or allowed_groups is required")

    cidrs = _optional_str_tuple_allow_empty(grant.get("allow_source_cidrs"), f"grants.{grant_id}.allow_source_cidrs")
    final_cidrs = _dedupe_strs([*inherited_cidrs, *cidrs])
    if not final_cidrs:
        raise ConfigError(f"grants.{grant_id}.allow_source_cidrs must be configured or inherited")
    for cidr in final_cidrs:
        parse_cidr(cidr)

    raw_timeout = grant.get("max_timeout_seconds")
    if raw_timeout is None:
        if inherited_timeout is None:
            raise ConfigError(f"grants.{grant_id}.max_timeout_seconds must be configured or inherited")
        max_timeout = inherited_timeout
    else:
        max_timeout = _positive_int(raw_timeout, f"grants.{grant_id}.max_timeout_seconds")
        if inherited_timeout is not None:
            max_timeout = min(max_timeout, inherited_timeout)

    final_grant = GrantConfig(
        id=grant_id,
        description=str(grant.get("description", inherited_description)),
        allowed_principals=final_principals,
        ports=tuple(ports),
        max_timeout_seconds=max_timeout,
        zone=_optional_zone(grant.get("zone"), f"grants.{grant_id}.zone") if "zone" in grant else inherited_zone,
        allow_source_cidrs=final_cidrs,
        allowed_groups=final_groups,
        inherits=inherits,
    )
    resolved[grant_id] = final_grant
    resolving.remove(grant_id)
    return final_grant


def _legacy_load_grants(value: Any) -> dict[str, GrantConfig]:
    data = _mapping(value, "grants")
    grants: dict[str, GrantConfig] = {}
    for grant_id, raw_grant in data.items():
        if not isinstance(grant_id, str) or not grant_id:
            raise ConfigError("grant ids must be non-empty strings")
        _validate_safe_id(grant_id, f"grants.{grant_id}")
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
        for principal in allowed_principals:
            _validate_safe_id(principal, f"grants.{grant_id}.allowed_principals")
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
            zone=_optional_zone(grant.get("zone"), f"grants.{grant_id}.zone"),
            allow_source_cidrs=cidrs,
        )
    return grants


def _load_publishers(value: Any) -> dict[str, PublisherConfig]:
    data = _mapping(value, "publishers")
    publishers: dict[str, PublisherConfig] = {}
    for name, raw_pub in data.items():
        if not isinstance(name, str) or not name:
            raise ConfigError("publisher names must be non-empty strings")
        _validate_safe_id(name, f"publishers.{name}")
        pub = _mapping(raw_pub, f"publishers.{name}")
        pub_type = _required_str(pub, "type", f"publishers.{name}").lower()
        if pub_type not in SUPPORTED_PUBLISHER_TYPES:
            raise ConfigError(f"unsupported_publisher_type: publishers.{name}.type")
        options = {key: item for key, item in pub.items() if key != "type"}
        publishers[name] = PublisherConfig(name=name, type=pub_type, options=options)
    return publishers


def _load_age_config(value: Any, name: str, *, for_agent: bool) -> AgeConfig | None:
    if value is None:
        return None
    data = _mapping(value, name)
    enabled = bool(data.get("enabled", True))
    if not enabled:
        return None
    age_cmd = str(data.get("age_cmd", data.get("age", "age")))
    if _has_control_chars(age_cmd):
        raise ConfigError(f"{name}.age_cmd contains invalid control characters")
    recipients = _optional_str_tuple_allow_empty(data.get("recipients"), f"{name}.recipients")
    recipient_files = tuple(
        expand_path(item) for item in _optional_str_tuple_allow_empty(data.get("recipient_files"), f"{name}.recipient_files")
    )
    identity_files = tuple(
        expand_path(item) for item in _optional_str_tuple_allow_empty(data.get("identity_files"), f"{name}.identity_files")
    )
    for recipient in recipients:
        if _has_control_chars(recipient) or not recipient.startswith("age1"):
            raise ConfigError(f"{name}.recipients entries must be age recipient strings")
    for path in recipient_files + identity_files:
        if _has_control_chars(path):
            raise ConfigError(f"{name} file paths contain invalid control characters")
    if for_agent and not identity_files:
        raise ConfigError(f"{name}.identity_files must contain at least one age identity file")
    if not for_agent and not recipients and not recipient_files:
        raise ConfigError(f"{name}.recipients or {name}.recipient_files is required")
    envelope_version = _positive_int(data.get("envelope_version", 2), f"{name}.envelope_version")
    if envelope_version not in {1, 2}:
        raise ConfigError(f"{name}.envelope_version must be 1 or 2")
    key_id_value = data.get("key_id")
    key_id = None
    if key_id_value is not None:
        if not isinstance(key_id_value, str) or not key_id_value:
            raise ConfigError(f"{name}.key_id must be a non-empty string")
        _validate_safe_id(key_id_value, f"{name}.key_id")
        key_id = key_id_value
    if not for_agent and envelope_version == 2 and key_id is None:
        raise ConfigError(f"{name}.key_id is required when envelope_version is 2")
    return AgeConfig(
        age_cmd=age_cmd,
        envelope_version=envelope_version,
        key_id=key_id,
        recipients=recipients,
        recipient_files=recipient_files,
        identity_files=identity_files,
    )


def _load_targets(value: Any, publishers: dict[str, PublisherConfig]) -> dict[str, TargetConfig]:
    data = _mapping(value, "targets")
    targets: dict[str, TargetConfig] = {}
    for name, raw_target in data.items():
        if not isinstance(name, str) or not name:
            raise ConfigError("target names must be non-empty strings")
        _validate_safe_id(name, f"targets.{name}")
        target = _mapping(raw_target, f"targets.{name}")
        publisher = _required_str(target, "publisher", f"targets.{name}")
        if publisher not in publishers:
            raise ConfigError(f"unknown_publisher: targets.{name}.publisher={publisher}")
        targets[name] = TargetConfig(
            name=name,
            target=_safe_id_from_mapping(target, "target", f"targets.{name}"),
            grant_id=_safe_id_from_mapping(target, "grant_id", f"targets.{name}"),
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
    if _has_control_chars(value):
        raise ConfigError(f"{scope}.{key} contains invalid control characters")
    return value


def _safe_id_from_mapping(data: dict[str, Any], key: str, scope: str) -> str:
    value = _required_str(data, key, scope)
    _validate_safe_id(value, f"{scope}.{key}")
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


def _optional_str_tuple_allow_empty(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list")
    result = tuple(item for item in value if isinstance(item, str) and item)
    if len(result) != len(value):
        raise ConfigError(f"{name} must contain only non-empty strings")
    return result


def _optional_str_map(value: Any, name: str) -> dict[str, str] | None:
    if value is None:
        return None
    data = _mapping(value, name)
    result = {}
    for key, item in data.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ConfigError(f"{name} must map strings to strings")
        if _has_control_chars(key) or _has_control_chars(item):
            raise ConfigError(f"{name} contains invalid control characters")
        result[key] = item
    return result


def _dedupe_strs(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _dedupe_ports(values: list[PortConfig] | tuple[PortConfig, ...]) -> list[PortConfig]:
    seen: set[tuple[str, int]] = set()
    result: list[PortConfig] = []
    for value in values:
        key = (value.protocol, value.port)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{name} must be a non-negative integer")
    return value


def _validate_http_path(value: str, name: str) -> None:
    if not value.startswith("/") or "?" in value or "#" in value:
        raise ConfigError(f"{name} must be an absolute URL path without query or fragment")


def _validate_public_key(value: str, name: str) -> None:
    if "\n" in value or "\r" in value:
        raise ConfigError(f"{name} entries must be single-line OpenSSH public keys")
    parts = value.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "sk-", "ecdsa-")):
        raise ConfigError(f"{name} entries must be OpenSSH public key lines")


def _validate_safe_id(value: str, name: str) -> None:
    if not SAFE_ID_RE.fullmatch(value):
        raise ConfigError(f"{name} must use only letters, numbers, underscore, dot, at, colon or hyphen")


def _validate_signature_namespace(value: str) -> None:
    _validate_safe_id(value, "signature_namespace")


def _optional_zone(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{name} must be a non-empty string")
    if _has_control_chars(value) or not SAFE_ZONE_RE.fullmatch(value):
        raise ConfigError(f"{name} contains invalid characters")
    return value


def _validate_firewall_config(firewall: FirewallConfig) -> None:
    if firewall.backend not in SUPPORTED_FIREWALL_BACKENDS:
        raise ConfigError("firewall.backend must be firewalld or nftables")
    if firewall.backend == "firewalld":
        if _has_control_chars(firewall.firewall_cmd) or not firewall.firewall_cmd.startswith("/"):
            raise ConfigError("firewall.firewall_cmd must be an absolute path without control characters")
        if _has_control_chars(firewall.default_zone) or not SAFE_ZONE_RE.fullmatch(firewall.default_zone):
            raise ConfigError("firewall.default_zone contains invalid characters")
    if firewall.backend == "nftables":
        if _has_control_chars(firewall.nft_cmd) or not firewall.nft_cmd.startswith("/"):
            raise ConfigError("firewall.nft_cmd must be an absolute path without control characters")
        for value, name in (
            (firewall.nft_family, "firewall.nft_family"),
            (firewall.nft_table, "firewall.nft_table"),
            (firewall.nft_set_prefix, "firewall.nft_set_prefix"),
        ):
            if _has_control_chars(value) or not SAFE_ZONE_RE.fullmatch(value):
                raise ConfigError(f"{name} contains invalid characters")


def _has_control_chars(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


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
