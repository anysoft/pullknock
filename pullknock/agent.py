"""Server-side polling agent."""

from __future__ import annotations

import logging
import json
import base64
import binascii
import hashlib
import random
import signal
import shlex
import time
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import click

from .audit import configure_logging, log_event
from .config import AgentConfig, GrantConfig, UserKeyPolicy, load_agent_config
from .crypto import age_decrypt
from .errors import (
    DuplicateCommand,
    ExpiredCommand,
    NotYetValidCommand,
    PermissionDenied,
    PullKnockError,
    ProtocolError,
    SignatureVerificationError,
)
from .fetcher import fetch_control_url, fetch_control_urls_with_source
from .firewall import FirewallCommandResult, create_firewall_backend
from .nonce_store import NonceStore
from .protocol import is_encrypted_envelope, parse_encrypted_envelope, parse_envelope, parse_payload
from .signing import sshsig_verify


@dataclass(frozen=True)
class PermissionDecision:
    grant: GrantConfig
    timeout_seconds: int


@dataclass(frozen=True)
class ProcessResult:
    status: str
    message: str
    payload: dict[str, Any] | None = None
    commands: list[FirewallCommandResult] = field(default_factory=list)
    key_id: str | None = None
    key_fingerprint: str | None = None


def process_once(config: AgentConfig, *, dry_run: bool = False, now: int | None = None) -> ProcessResult:
    fetched = fetch_control_urls_with_source(
        config.server.control_urls,
        timeout_seconds=config.server.http_timeout_seconds,
        headers=config.server.control_headers,
    )
    if fetched is None:
        return ProcessResult(status="idle", message="no_command")
    envelope_text, source_url = fetched
    queue_items = parse_queue_index(envelope_text, source_url=source_url)
    if queue_items is not None:
        return process_queue_items(queue_items, config, dry_run=dry_run, now=now)
    return _process_with_audit(envelope_text, config, dry_run=dry_run, now=now)


def parse_queue_index(queue_text: str, *, source_url: str) -> list[str] | None:
    try:
        data = json.loads(queue_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("queue_version") != 1:
        return None
    commands = data.get("commands")
    if not isinstance(commands, list):
        raise ProtocolError("queue_commands_must_be_list")
    urls: list[str] = []
    for item in commands:
        if not isinstance(item, dict):
            raise ProtocolError("queue_command_must_be_mapping")
        url = item.get("url")
        if not isinstance(url, str) or not url:
            raise ProtocolError("queue_command_url_required")
        urls.append(resolve_queue_url(url, source_url=source_url))
    return urls


def resolve_queue_url(url: str, *, source_url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme:
        return url
    source = urlparse(source_url)
    if source.scheme in {"http", "https", "ftp", "ftps"}:
        return urljoin(source_url, url)
    if source.scheme == "file":
        base = Path(source.path).parent
        return str(base / url.lstrip("/"))
    return str(Path(source_url).parent / url.lstrip("/"))


def process_queue_items(
    urls: list[str],
    config: AgentConfig,
    *,
    dry_run: bool,
    now: int | None,
) -> ProcessResult:
    if not urls:
        return ProcessResult(status="idle", message="empty_queue")
    aggregate_commands: list[FirewallCommandResult] = []
    payload: dict[str, Any] | None = None
    success_count = 0
    ignored_count = 0
    failure_count = 0
    for url in urls:
        data = fetch_control_url(
            url,
            timeout_seconds=config.server.http_timeout_seconds,
            headers=config.server.control_headers,
        )
        if data is None:
            ignored_count += 1
            continue
        result = _process_with_audit(data, config, dry_run=dry_run, now=now)
        payload = result.payload or payload
        aggregate_commands.extend(result.commands)
        if result.status == "success":
            success_count += 1
        elif result.status == "ignored":
            ignored_count += 1
        else:
            failure_count += 1
    if success_count:
        return ProcessResult(
            status="success",
            message=f"queue_processed: success={success_count} ignored={ignored_count} failure={failure_count}",
            payload=payload,
            commands=aggregate_commands,
        )
    if failure_count:
        return ProcessResult(
            status="failure",
            message=f"queue_processed: success=0 ignored={ignored_count} failure={failure_count}",
            payload=payload,
            commands=aggregate_commands,
        )
    return ProcessResult(status="ignored", message=f"queue_processed: ignored={ignored_count}", payload=payload)


def process_envelope(
    envelope_data: str | bytes | dict[str, Any],
    config: AgentConfig,
    *,
    dry_run: bool = False,
    now: int | None = None,
) -> ProcessResult:
    now = int(time.time()) if now is None else now
    envelope_data = decrypt_envelope_if_needed(envelope_data, config)
    payload_bytes, signature_bytes, envelope = parse_envelope(envelope_data)
    payload = parse_payload(payload_bytes)
    validate_envelope_kid(envelope, payload)
    validate_target(payload, config)
    validate_time_window(payload, config, now=now)
    signing_key = verify_payload_signature(payload_bytes, signature_bytes, payload, config, now=now)
    nonce_store = NonceStore(config.security.nonce_db)
    nonce_store.assert_unused(payload["command_id"])
    decision = evaluate_permission(payload, config, now=now)
    firewall = create_firewall_backend(config.firewall, dry_run=dry_run)
    commands = firewall.open_grant(
        decision.grant,
        source_ip=payload["source_ip"],
        timeout_seconds=decision.timeout_seconds,
    )
    if not dry_run:
        nonce_store.mark_used(
            command_id=payload["command_id"],
            principal=payload["principal"],
            grant_id=payload["grant_id"],
            source_ip=payload["source_ip"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            processed_at=now,
        )
        nonce_store.cleanup(retention_seconds=config.security.nonce_retention_seconds, now=now)
    return ProcessResult(
        status="success",
        message="grant_opened",
        payload=payload,
        commands=commands,
        key_id=signing_key.id,
        key_fingerprint=public_key_fingerprint(signing_key.public_key),
    )


def validate_target(payload: dict[str, Any], config: AgentConfig) -> None:
    if payload["target"] != config.server.id:
        raise PermissionDenied("target_mismatch")


def validate_envelope_kid(envelope: dict[str, Any], payload: dict[str, Any]) -> None:
    kid = envelope.get("kid")
    if isinstance(kid, str) and kid != payload["principal"]:
        raise PermissionDenied("kid_principal_mismatch")


def validate_time_window(payload: dict[str, Any], config: AgentConfig, *, now: int) -> None:
    skew = config.security.max_clock_skew_seconds
    if payload["issued_at"] - skew > now:
        raise NotYetValidCommand("issued_at_in_future")
    if payload["not_before"] - skew > now:
        raise NotYetValidCommand("not_before_in_future")
    if payload["expires_at"] + skew < now:
        raise ExpiredCommand("expired_command")
    if payload["expires_at"] - payload["issued_at"] > config.security.max_command_ttl_seconds:
        raise PermissionDenied("command_ttl_too_long")


def verify_payload_signature(
    payload_bytes: bytes,
    signature_bytes: bytes,
    payload: dict[str, Any],
    config: AgentConfig,
    *,
    now: int,
) -> UserKeyPolicy:
    principal = payload["principal"]
    last_error: SignatureVerificationError | None = None
    for key in active_signing_keys_for_principal(config, principal, now=now):
        try:
            sshsig_verify(
                payload_bytes,
                signature_bytes,
                principal=principal,
                signer_file_content=f"{principal} {key.public_key}\n",
                namespace=config.security.signature_namespace,
            )
        except SignatureVerificationError as exc:
            last_error = exc
            continue
        return key
    if last_error is not None:
        raise last_error
    raise PermissionDenied("user_keys_missing")


def signer_file_content_for_principal(config: AgentConfig, principal: str) -> str:
    return "".join(f"{principal} {key.public_key}\n" for key in active_signing_keys_for_principal(config, principal, now=int(time.time())))


def active_signing_keys_for_principal(config: AgentConfig, principal: str, *, now: int) -> tuple[UserKeyPolicy, ...]:
    user = config.users.get(principal)
    if not user:
        return ()
    active = []
    for key in user.keys:
        if not key.enabled:
            continue
        if key.not_before is not None and now < key.not_before:
            continue
        if key.expires_at is not None and now > key.expires_at:
            continue
        active.append(key)
    return tuple(active)


def public_key_fingerprint(public_key: str) -> str:
    parts = public_key.split()
    if len(parts) < 2:
        return ""
    try:
        blob = base64.b64decode(parts[1].encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        return ""
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def evaluate_permission(payload: dict[str, Any], config: AgentConfig, *, now: int) -> PermissionDecision:
    principal = payload["principal"]
    grant_id = payload["grant_id"]
    grant = config.grants.get(grant_id)
    if grant is None:
        raise PermissionDenied("unknown_grant")

    user_timeout: int | None = None
    user_cidrs: tuple[str, ...] = ()
    user_groups: tuple[str, ...] = ()
    allowed_grants: set[str] | None = None
    if config.users:
        user = config.users.get(principal)
        if user is None:
            raise PermissionDenied("unknown_user")
        if not user.enabled:
            raise PermissionDenied("user_disabled")
        if user.not_before is not None and now < user.not_before:
            raise PermissionDenied("user_not_yet_valid")
        if user.expires_at is not None and now > user.expires_at:
            raise PermissionDenied("user_expired")
        active_groups = _active_user_groups(user.groups, config, now=now)
        user_groups = tuple(group.name for group in active_groups)
        if user.allowed_grants is not None:
            allowed_grants = set(user.allowed_grants)
        for group in active_groups:
            if group.allowed_grants is not None:
                if allowed_grants is None:
                    allowed_grants = set()
                allowed_grants.update(group.allowed_grants)
        if allowed_grants is not None and grant_id not in allowed_grants:
            raise PermissionDenied("grant_not_allowed_for_user")
        user_timeout = user.max_timeout_seconds
        for group in active_groups:
            if group.max_timeout_seconds is not None:
                user_timeout = group.max_timeout_seconds if user_timeout is None else min(user_timeout, group.max_timeout_seconds)
        user_cidrs = _dedupe_tuple((*user.allow_source_cidrs, *(cidr for group in active_groups for cidr in group.allow_source_cidrs)))

    if principal not in grant.allowed_principals and not set(user_groups).intersection(grant.allowed_groups):
        raise PermissionDenied("principal_not_allowed_for_grant")

    source_ip = ip_address(payload["source_ip"])
    if not _ip_allowed(source_ip, grant.allow_source_cidrs):
        raise PermissionDenied("source_ip_not_allowed_for_grant")
    if user_cidrs and not _ip_allowed(source_ip, user_cidrs):
        raise PermissionDenied("source_ip_not_allowed_for_user")

    max_timeout = grant.max_timeout_seconds
    if user_timeout is not None:
        max_timeout = min(max_timeout, user_timeout)
    timeout = min(payload["requested_timeout"], max_timeout)
    return PermissionDecision(grant=grant, timeout_seconds=timeout)


def _ip_allowed(source_ip, cidrs: tuple[str, ...]) -> bool:
    return any(source_ip in ip_network(cidr, strict=False) for cidr in cidrs)


def _active_user_groups(group_names: tuple[str, ...], config: AgentConfig, *, now: int):
    groups = config.groups or {}
    active = []
    for group_name in group_names:
        group = groups.get(group_name)
        if group is None:
            continue
        if not group.enabled:
            continue
        if group.not_before is not None and now < group.not_before:
            continue
        if group.expires_at is not None and now > group.expires_at:
            continue
        active.append(group)
    return active


def _dedupe_tuple(values) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _process_with_audit(
    envelope_data: str | bytes | dict[str, Any],
    config: AgentConfig,
    *,
    dry_run: bool,
    now: int | None,
) -> ProcessResult:
    payload: dict[str, Any] | None = None
    try:
        envelope_data = decrypt_envelope_if_needed(envelope_data, config)
        payload_bytes, _, _ = parse_envelope(envelope_data)
        payload = parse_payload(payload_bytes)
        result = process_envelope(envelope_data, config, dry_run=dry_run, now=now)
        assert result.payload is not None
        decision = evaluate_permission(result.payload, config, now=int(time.time()) if now is None else now)
        log_event(
            "grant_opened",
            result="success",
            principal=result.payload["principal"],
            target=result.payload["target"],
            grant_id=result.payload["grant_id"],
            source_ip=result.payload["source_ip"],
            timeout=decision.timeout_seconds,
            requested_timeout=result.payload["requested_timeout"],
            command_id=result.payload["command_id"],
            key_id=result.key_id,
            key_fingerprint=result.key_fingerprint,
            dry_run=dry_run,
        )
        return result
    except (DuplicateCommand, ExpiredCommand, NotYetValidCommand) as exc:
        log_event(
            "grant_ignored",
            result="ignored",
            reason=str(exc),
            level=logging.DEBUG,
            **_payload_audit_fields(payload),
        )
        return ProcessResult(status="ignored", message=str(exc), payload=payload)
    except SignatureVerificationError as exc:
        log_event(
            "grant_rejected",
            result="failure",
            reason="signature_verify_failed",
            error_message=str(exc),
            **_payload_audit_fields(payload),
        )
        return ProcessResult(status="failure", message="signature_verify_failed", payload=payload)
    except PullKnockError as exc:
        log_event(
            "grant_rejected",
            result="failure",
            reason=str(exc),
            error_message=str(exc),
            **_payload_audit_fields(payload),
        )
        return ProcessResult(status="failure", message=str(exc), payload=payload)


def decrypt_envelope_if_needed(envelope_data: str | bytes | dict[str, Any], config: AgentConfig) -> str | bytes | dict[str, Any]:
    try:
        encrypted = is_encrypted_envelope(envelope_data)
    except ProtocolError:
        return envelope_data
    if not encrypted:
        return envelope_data
    if config.security.age is None:
        raise PermissionDenied("encrypted_envelope_requires_age_identity")
    ciphertext, _ = parse_encrypted_envelope(envelope_data)
    return age_decrypt(ciphertext, config.security.age)


def _payload_audit_fields(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not payload:
        return {}
    return {
        "principal": payload.get("principal"),
        "target": payload.get("target"),
        "grant_id": payload.get("grant_id"),
        "source_ip": payload.get("source_ip"),
        "timeout": payload.get("requested_timeout"),
        "command_id": payload.get("command_id"),
    }


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "config_path", default="/etc/pullknock/agent.yaml", show_default=True, help="Agent YAML config.")
@click.option("--dry-run", is_flag=True, help="Verify commands and print firewall-cmd calls without changing firewalld.")
@click.option("--once", is_flag=True, help="Fetch and process once, then exit.")
@click.option("--check-config", is_flag=True, help="Validate config and exit.")
@click.option("--log-file", default=None, help="Write JSON audit logs to this file instead of stderr.")
@click.option("--log-level", default="INFO", show_default=True, help="Python logging level.")
def main(
    config_path: str,
    dry_run: bool,
    once: bool,
    check_config: bool,
    log_file: str | None,
    log_level: str,
) -> None:
    """Poll an untrusted control location and open local firewall grants."""
    config = load_agent_config(config_path)
    if check_config:
        click.echo("Agent config OK.")
        return
    configure_logging(log_file=_effective_log_file(config, log_file), level=log_level)
    if once:
        result = process_once(config, dry_run=dry_run)
        _echo_result(result, dry_run=dry_run)
        return

    reload_state = _ReloadState()
    _install_reload_handler(reload_state)

    while True:
        if reload_state.requested:
            reload_state.requested = False
            config = _reload_config(config_path, current_config=config, log_file=log_file, log_level=log_level)
        try:
            result = process_once(config, dry_run=dry_run)
            if dry_run and result.commands:
                _echo_result(result, dry_run=True)
        except PullKnockError as exc:
            log_event("agent_error", result="failure", error_message=str(exc))
        delay = config.server.poll_interval_seconds
        if config.server.poll_jitter_seconds:
            delay += random.uniform(0, config.server.poll_jitter_seconds)
        time.sleep(delay)


def _echo_result(result: ProcessResult, *, dry_run: bool) -> None:
    if result.status == "idle":
        click.echo("No command found.")
        return
    click.echo(f"{result.status}: {result.message}")
    if dry_run:
        for command in result.commands:
            click.echo(shlex.join(command.args))


@dataclass
class _ReloadState:
    requested: bool = False


def _install_reload_handler(reload_state: _ReloadState) -> None:
    if not hasattr(signal, "SIGHUP"):
        return

    def _request_reload(signum, frame) -> None:
        reload_state.requested = True

    signal.signal(signal.SIGHUP, _request_reload)


def _reload_config(
    config_path: str,
    *,
    current_config: AgentConfig,
    log_file: str | None,
    log_level: str,
) -> AgentConfig:
    try:
        new_config = load_agent_config(config_path)
        configure_logging(log_file=_effective_log_file(new_config, log_file), level=log_level)
    except PullKnockError as exc:
        log_event("agent_config_reload_failed", result="failure", error_message=str(exc))
        return current_config
    log_event("agent_config_reloaded", result="success", config_path=config_path)
    return new_config


def _effective_log_file(config: AgentConfig, cli_log_file: str | None) -> str | None:
    return cli_log_file if cli_log_file is not None else config.audit.log_file


if __name__ == "__main__":
    main()
