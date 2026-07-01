"""Server-side polling agent."""

from __future__ import annotations

import logging
import random
import shlex
import time
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any

import click

from .audit import configure_logging, log_event
from .config import AgentConfig, GrantConfig, load_agent_config
from .errors import (
    DuplicateCommand,
    ExpiredCommand,
    NotYetValidCommand,
    PermissionDenied,
    PullKnockError,
    SignatureVerificationError,
)
from .fetcher import fetch_control_url
from .firewall import FirewalldBackend, FirewallCommandResult
from .nonce_store import NonceStore
from .protocol import parse_envelope, parse_payload
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


def process_once(config: AgentConfig, *, dry_run: bool = False, now: int | None = None) -> ProcessResult:
    envelope_text = fetch_control_url(
        config.server.control_url,
        timeout_seconds=config.server.http_timeout_seconds,
        headers=config.server.control_headers,
    )
    if envelope_text is None:
        return ProcessResult(status="idle", message="no_command")
    return _process_with_audit(envelope_text, config, dry_run=dry_run, now=now)


def process_envelope(
    envelope_data: str | bytes | dict[str, Any],
    config: AgentConfig,
    *,
    dry_run: bool = False,
    now: int | None = None,
) -> ProcessResult:
    now = int(time.time()) if now is None else now
    payload_bytes, signature_bytes, _ = parse_envelope(envelope_data)
    payload = parse_payload(payload_bytes)
    validate_target(payload, config)
    validate_time_window(payload, config, now=now)
    sshsig_verify(
        payload_bytes,
        signature_bytes,
        allowed_signers_file=config.security.allowed_signers_file,
        principal=payload["principal"],
        namespace=config.security.signature_namespace,
    )
    nonce_store = NonceStore(config.security.nonce_db)
    nonce_store.assert_unused(payload["command_id"])
    decision = evaluate_permission(payload, config, now=now)
    firewall = FirewalldBackend(config.firewall, dry_run=dry_run)
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
    return ProcessResult(status="success", message="grant_opened", payload=payload, commands=commands)


def validate_target(payload: dict[str, Any], config: AgentConfig) -> None:
    if payload["target"] != config.server.id:
        raise PermissionDenied("target_mismatch")


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


def evaluate_permission(payload: dict[str, Any], config: AgentConfig, *, now: int) -> PermissionDecision:
    principal = payload["principal"]
    grant_id = payload["grant_id"]
    grant = config.grants.get(grant_id)
    if grant is None:
        raise PermissionDenied("unknown_grant")
    if principal not in grant.allowed_principals:
        raise PermissionDenied("principal_not_allowed_for_grant")

    user_timeout: int | None = None
    user_cidrs: tuple[str, ...] = ()
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
        if user.allowed_grants is not None and grant_id not in user.allowed_grants:
            raise PermissionDenied("grant_not_allowed_for_user")
        user_timeout = user.max_timeout_seconds
        user_cidrs = user.allow_source_cidrs

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


def _process_with_audit(
    envelope_data: str | bytes | dict[str, Any],
    config: AgentConfig,
    *,
    dry_run: bool,
    now: int | None,
) -> ProcessResult:
    payload: dict[str, Any] | None = None
    try:
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
@click.option("--log-file", default=None, help="Write JSON audit logs to this file instead of stderr.")
@click.option("--log-level", default="INFO", show_default=True, help="Python logging level.")
def main(config_path: str, dry_run: bool, once: bool, log_file: str | None, log_level: str) -> None:
    """Poll an untrusted control location and open local firewall grants."""
    configure_logging(log_file=log_file, level=log_level)
    config = load_agent_config(config_path)
    if once:
        result = process_once(config, dry_run=dry_run)
        _echo_result(result, dry_run=dry_run)
        return

    while True:
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


if __name__ == "__main__":
    main()
