import tempfile
import unittest
from pathlib import Path

from pullknock.agent import evaluate_permission, validate_time_window
from pullknock.config import (
    AgentConfig,
    FirewallConfig,
    GrantConfig,
    PortConfig,
    SecurityConfig,
    ServerConfig,
    UserPolicy,
)
from pullknock.errors import ExpiredCommand, PermissionDenied
from pullknock.protocol import build_payload


def make_config(tmp_path, *, users=None):
    temp_path = Path(tmp_path)
    return AgentConfig(
        server=ServerConfig(id="x162", control_url=str(temp_path / "command.json")),
        security=SecurityConfig(
            allowed_signers_file=f"{tmp_path}/allowed_signers",
            nonce_db=f"{tmp_path}/nonces.sqlite3",
            max_command_ttl_seconds=120,
        ),
        firewall=FirewallConfig(firewall_cmd="/usr/bin/firewall-cmd"),
        users=users
        if users is not None
        else {
            "jonhy": UserPolicy(
                principal="jonhy",
                enabled=True,
                allowed_grants=("ssh",),
                max_timeout_seconds=45,
                expires_at=1_000,
                allow_source_cidrs=("203.0.113.0/24",),
            )
        },
        grants={
            "ssh": GrantConfig(
                id="ssh",
                description="ssh",
                allowed_principals=("jonhy",),
                ports=(PortConfig(protocol="tcp", port=22),),
                max_timeout_seconds=60,
                zone="public",
                allow_source_cidrs=("0.0.0.0/0",),
            )
        },
    )


def make_payload(**overrides):
    data = {
        "principal": "jonhy",
        "target": "x162",
        "grant_id": "ssh",
        "source_ip": "203.0.113.10",
        "requested_timeout": 90,
        "issued_at": 100,
        "not_before": 100,
        "expires_at": 160,
    }
    data.update(overrides)
    return build_payload(**data)


class AgentPolicyTest(unittest.TestCase):
    def test_permission_caps_timeout_by_user_and_grant(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(temp_dir)
            payload = make_payload()

            decision = evaluate_permission(payload, config, now=200)

        self.assertEqual(decision.timeout_seconds, 45)
        self.assertEqual(decision.grant.id, "ssh")

    def test_permission_rejects_expired_user(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(
                temp_dir,
                users={
                    "jonhy": UserPolicy(
                        principal="jonhy",
                        enabled=True,
                        allowed_grants=("ssh",),
                        expires_at=150,
                    )
                },
            )
            payload = make_payload()

            with self.assertRaisesRegex(PermissionDenied, "user_expired"):
                evaluate_permission(payload, config, now=200)

    def test_permission_rejects_user_source_outside_cidr(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(temp_dir)
            payload = make_payload(source_ip="198.51.100.10")

            with self.assertRaisesRegex(PermissionDenied, "source_ip_not_allowed_for_user"):
                evaluate_permission(payload, config, now=200)

    def test_time_window_rejects_expired_command(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(temp_dir)
            payload = make_payload(expires_at=120)

            with self.assertRaises(ExpiredCommand):
                validate_time_window(payload, config, now=200)

    def test_time_window_rejects_ttl_too_long(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(temp_dir)
            payload = make_payload(issued_at=100, expires_at=500)

            with self.assertRaisesRegex(PermissionDenied, "command_ttl_too_long"):
                validate_time_window(payload, config, now=120)


if __name__ == "__main__":
    unittest.main()
