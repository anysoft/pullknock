"""firewalld backend implementation."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from ipaddress import ip_address

from .config import FirewallConfig, GrantConfig, PortConfig
from .errors import FirewallError


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
            args = self._build_args(zone=zone, source_ip=source_ip, port=port, timeout_seconds=timeout_seconds)
            if self.dry_run:
                results.append(FirewallCommandResult(args=args, dry_run=True))
                continue
            completed = subprocess.run(args, check=False, capture_output=True, text=True)
            if completed.returncode != 0:
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

    def _build_args(self, *, zone: str, source_ip: str, port: PortConfig, timeout_seconds: int) -> list[str]:
        family = "ipv6" if ip_address(source_ip).version == 6 else "ipv4"
        rich_rule = (
            f'rule family="{family}" source address="{source_ip}" '
            f'port protocol="{port.protocol}" port="{port.port}" accept'
        )
        return [
            self.config.firewall_cmd,
            "--zone",
            zone,
            "--add-rich-rule",
            rich_rule,
            "--timeout",
            str(timeout_seconds),
        ]
