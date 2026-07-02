"""Firewall backend implementations."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address

from .config import FirewallConfig, GrantConfig, PortConfig
from .errors import FirewallError

SAFE_ZONE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


@dataclass(frozen=True)
class FirewallCommandResult:
    args: list[str]
    dry_run: bool
    stdout: str = ""
    stderr: str = ""


class FirewalldBackend:
    def __init__(self, config: FirewallConfig, *, dry_run: bool = False):
        if config.backend != "firewalld":
            raise FirewallError(f"unsupported_firewall_backend: {config.backend}")
        self.config = config
        self.dry_run = dry_run

    def open_grant(self, grant: GrantConfig, *, source_ip: str, timeout_seconds: int) -> list[FirewallCommandResult]:
        results = []
        zone = grant.zone or self.config.default_zone
        for port in grant.ports:
            rich_rule = self._rich_rule(source_ip=source_ip, port=port)
            commands = [
                (self._remove_args(zone=zone, rich_rule=rich_rule), True),
                (self._add_args(zone=zone, rich_rule=rich_rule, timeout_seconds=timeout_seconds), False),
            ]
            for args, tolerate_missing in commands:
                if self.dry_run:
                    results.append(FirewallCommandResult(args=args, dry_run=True))
                    continue
                completed = subprocess.run(args, check=False, capture_output=True, text=True)
                if completed.returncode != 0 and not (tolerate_missing and _is_firewalld_missing_rule(completed.stderr or completed.stdout)):
                    message = (completed.stderr or completed.stdout or "").strip()
                    raise FirewallError(f"firewall_cmd_failed: {message or completed.returncode}")
                results.append(
                    FirewallCommandResult(
                        args=args,
                        dry_run=False,
                        stdout=completed.stdout,
                        stderr=completed.stderr,
                    )
                )
        return results

    def _rich_rule(self, *, source_ip: str, port: PortConfig) -> str:
        parsed_ip = ip_address(source_ip)
        normalized_source = str(parsed_ip)
        family = "ipv6" if parsed_ip.version == 6 else "ipv4"
        return (
            f'rule family="{family}" source address="{normalized_source}" '
            f'port protocol="{port.protocol}" port="{port.port}" accept'
        )

    def _remove_args(self, *, zone: str, rich_rule: str) -> list[str]:
        if not SAFE_ZONE_RE.fullmatch(zone):
            raise FirewallError("invalid_firewall_zone")
        return [
            self.config.firewall_cmd,
            "--zone",
            zone,
            "--remove-rich-rule",
            rich_rule,
        ]

    def _add_args(self, *, zone: str, rich_rule: str, timeout_seconds: int) -> list[str]:
        if not SAFE_ZONE_RE.fullmatch(zone):
            raise FirewallError("invalid_firewall_zone")
        return [
            self.config.firewall_cmd,
            "--zone",
            zone,
            "--add-rich-rule",
            rich_rule,
            "--timeout",
            str(timeout_seconds),
        ]


class NftablesBackend:
    def __init__(self, config: FirewallConfig, *, dry_run: bool = False):
        if config.backend != "nftables":
            raise FirewallError(f"unsupported_firewall_backend: {config.backend}")
        self.config = config
        self.dry_run = dry_run

    def open_grant(self, grant: GrantConfig, *, source_ip: str, timeout_seconds: int) -> list[FirewallCommandResult]:
        results = []
        parsed_ip = ip_address(source_ip)
        normalized_source = str(parsed_ip)
        family_suffix = "ipv6" if parsed_ip.version == 6 else "ipv4"
        set_type = "ipv6_addr" if parsed_ip.version == 6 else "ipv4_addr"
        for port in grant.ports:
            set_name = self._set_name(port=port, family_suffix=family_suffix)
            commands: list[tuple[list[str], bool]] = []
            if self.config.nft_setup_sets:
                commands.append((self._add_table_args(), True))
                commands.append((self._add_set_args(set_name=set_name, set_type=set_type), True))
            commands.append(
                (
                    self._add_element_args(
                        set_name=set_name,
                        source_ip=normalized_source,
                        timeout_seconds=timeout_seconds,
                    ),
                    False,
                )
            )
            for args, tolerate_exists in commands:
                if self.dry_run:
                    results.append(FirewallCommandResult(args=args, dry_run=True))
                    continue
                completed = subprocess.run(args, check=False, capture_output=True, text=True)
                if completed.returncode != 0 and not (tolerate_exists and _is_nft_exists_error(completed.stderr)):
                    message = (completed.stderr or completed.stdout or "").strip()
                    raise FirewallError(f"nft_failed: {message or completed.returncode}")
                results.append(
                    FirewallCommandResult(
                        args=args,
                        dry_run=False,
                        stdout=completed.stdout,
                        stderr=completed.stderr,
                    )
                )
        return results

    def _set_name(self, *, port: PortConfig, family_suffix: str) -> str:
        return f"{self.config.nft_set_prefix}_{port.protocol}_{port.port}_{family_suffix}"

    def _add_table_args(self) -> list[str]:
        return [self.config.nft_cmd, "add", "table", self.config.nft_family, self.config.nft_table]

    def _add_set_args(self, *, set_name: str, set_type: str) -> list[str]:
        return [
            self.config.nft_cmd,
            "add",
            "set",
            self.config.nft_family,
            self.config.nft_table,
            set_name,
            "{",
            "type",
            f"{set_type};",
            "flags",
            "timeout;",
            "}",
        ]

    def _add_element_args(self, *, set_name: str, source_ip: str, timeout_seconds: int) -> list[str]:
        return [
            self.config.nft_cmd,
            "add",
            "element",
            self.config.nft_family,
            self.config.nft_table,
            set_name,
            "{",
            source_ip,
            "timeout",
            f"{timeout_seconds}s",
            "}",
        ]


def create_firewall_backend(config: FirewallConfig, *, dry_run: bool = False) -> FirewalldBackend | NftablesBackend:
    if config.backend == "firewalld":
        return FirewalldBackend(config, dry_run=dry_run)
    if config.backend == "nftables":
        return NftablesBackend(config, dry_run=dry_run)
    raise FirewallError(f"unsupported_firewall_backend: {config.backend}")


def _is_nft_exists_error(stderr: str) -> bool:
    normalized = stderr.lower()
    return "file exists" in normalized or "already exists" in normalized


def _is_firewalld_missing_rule(output: str) -> bool:
    normalized = output.lower()
    return "not enabled" in normalized or "not found" in normalized or "no such" in normalized
