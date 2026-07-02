"""Client-side command line interface."""

from __future__ import annotations

import json
import time
from ipaddress import ip_address
from typing import Iterable

import click
import requests

from .config import load_cli_config
from .crypto import age_encrypt
from .errors import PullKnockError
from .protocol import build_encrypted_envelope, build_envelope, build_envelope_v2, build_payload, canonical_json
from .publisher import envelope_json_bytes, publish_envelope
from .signing import sshsig_sign

DEFAULT_PUBLIC_IP_PROVIDERS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://checkip.amazonaws.com",
)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main() -> None:
    """Publish signed PullKnock authorization commands."""


@main.command("open")
@click.argument("target_name")
@click.option(
    "--config",
    "config_path",
    default="~/.config/pullknock/config.yaml",
    show_default=True,
    help="CLI YAML config.",
)
@click.option("--source-ip", default=None, help="Client public IP to allow. Auto-detected when omitted.")
@click.option("--timeout", "requested_timeout", type=int, default=None, help="Requested access duration in seconds.")
@click.option("--reason", default="", help="Audit reason stored in the signed payload.")
@click.option("--dry-run", is_flag=True, help="Sign and print the envelope instead of publishing it.")
def open_command(
    target_name: str,
    config_path: str,
    source_ip: str | None,
    requested_timeout: int | None,
    reason: str,
    dry_run: bool,
) -> None:
    """Open a configured target grant."""
    try:
        config = load_cli_config(config_path)
        if target_name not in config.targets:
            raise click.ClickException(f"unknown target: {target_name}")
        target = config.targets[target_name]
        publisher = config.publishers[target.publisher]
        resolved_source_ip = source_ip or detect_public_ip()
        ip_address(resolved_source_ip)
        timeout_seconds = requested_timeout or config.defaults.requested_timeout_seconds
        if timeout_seconds <= 0:
            raise click.ClickException("--timeout must be positive")
        now = int(time.time())
        payload = build_payload(
            principal=config.defaults.principal,
            target=target.target,
            grant_id=target.grant_id,
            source_ip=resolved_source_ip,
            requested_timeout=timeout_seconds,
            issued_at=now,
            not_before=now,
            expires_at=now + config.defaults.command_ttl_seconds,
            reason=reason,
        )
        payload_bytes = canonical_json(payload)
        signature_bytes = sshsig_sign(
            payload_bytes,
            private_key=config.defaults.private_key,
            namespace=config.defaults.signature_namespace,
            ssh_keygen=config.defaults.ssh_keygen,
        )
        envelope = build_envelope(payload_bytes, signature_bytes, kid=config.defaults.principal, created_at=now)
        if config.defaults.age is not None:
            ciphertext = age_encrypt(envelope_json_bytes(envelope), config.defaults.age)
            if config.defaults.age.envelope_version == 1:
                envelope = build_encrypted_envelope(ciphertext, kid=config.defaults.principal, created_at=now)
            else:
                assert config.defaults.age.key_id is not None
                envelope = build_envelope_v2(
                    ciphertext,
                    kid=config.defaults.principal,
                    encryption_key_id=config.defaults.age.key_id,
                    created_at=now,
                )
        if dry_run:
            click.echo(envelope_json_bytes(envelope).decode("utf-8"), nl=False)
            return
        location = publish_envelope(
            envelope,
            publisher,
            context={
                "target": target.target,
                "grant_id": target.grant_id,
                "command_id": payload["command_id"],
                "principal": config.defaults.principal,
            },
        )
        click.echo(json.dumps({"published": location, "target": target_name, "source_ip": resolved_source_ip}))
    except PullKnockError as exc:
        raise click.ClickException(str(exc)) from exc
    except ValueError as exc:
        raise click.ClickException(f"invalid source IP: {source_ip}") from exc


def detect_public_ip(providers: Iterable[str] = DEFAULT_PUBLIC_IP_PROVIDERS, *, timeout_seconds: int = 5) -> str:
    results: set[str] = set()
    errors: list[str] = []
    for provider in providers:
        try:
            response = requests.get(provider, timeout=timeout_seconds)
            response.raise_for_status()
            candidate = response.text.strip()
            ip_address(candidate)
            results.add(candidate)
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"{provider}: {exc}")
    if not results:
        raise PullKnockError("public_ip_detection_failed: " + "; ".join(errors))
    if len(results) > 1:
        raise PullKnockError("public_ip_detection_inconsistent: " + ", ".join(sorted(results)))
    return next(iter(results))


if __name__ == "__main__":
    main()
