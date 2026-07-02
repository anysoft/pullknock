import tempfile
import unittest
from pathlib import Path

from pullknock.agent import (
    active_signing_keys_for_principal,
    decrypt_envelope_if_needed,
    evaluate_permission,
    parse_queue_index,
    signer_file_content_for_principal,
    validate_envelope_kid,
    validate_time_window,
)
from pullknock.config import (
    AgeConfig,
    AgentConfig,
    FirewallConfig,
    GrantConfig,
    GroupPolicy,
    PortConfig,
    SecurityConfig,
    ServerConfig,
    UserPolicy,
    UserKeyPolicy,
)
from pullknock.errors import ExpiredCommand, PermissionDenied
from pullknock.protocol import build_envelope, build_envelope_v2, build_payload, canonical_json
from unittest.mock import patch


def make_config(tmp_path, *, users=None):
    temp_path = Path(tmp_path)
    return AgentConfig(
        server=ServerConfig(id="x162", control_url=str(temp_path / "command.json")),
        security=SecurityConfig(
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
                keys=(UserKeyPolicy(id="jonhy-yubikey", public_key="sk-ssh-ed25519@openssh.com AAAAExample jonhy-key"),),
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

    def test_permission_allows_active_group_and_caps_timeout(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = AgentConfig(
                server=ServerConfig(id="x162", control_url=f"{temp_dir}/command.json"),
                security=SecurityConfig(nonce_db=f"{temp_dir}/nonces.sqlite3"),
                firewall=FirewallConfig(firewall_cmd="/usr/bin/firewall-cmd"),
                users={
                    "jonhy": UserPolicy(
                        principal="jonhy",
                        enabled=True,
                        groups=("ops",),
                        keys=(UserKeyPolicy(id="jonhy-laptop", public_key="ssh-ed25519 AAAAExample jonhy-key"),),
                    )
                },
                groups={
                    "ops": GroupPolicy(
                        name="ops",
                        allowed_grants=("ssh",),
                        max_timeout_seconds=35,
                        allow_source_cidrs=("203.0.113.0/24",),
                    )
                },
                grants={
                    "ssh": GrantConfig(
                        id="ssh",
                        description="ssh",
                        allowed_principals=(),
                        allowed_groups=("ops",),
                        ports=(PortConfig(protocol="tcp", port=22),),
                        max_timeout_seconds=60,
                        zone="public",
                        allow_source_cidrs=("0.0.0.0/0",),
                    )
                },
            )
            payload = make_payload()

            decision = evaluate_permission(payload, config, now=120)

        self.assertEqual(decision.timeout_seconds, 35)

    def test_permission_rejects_expired_user(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(
                temp_dir,
                users={
                    "jonhy": UserPolicy(
                        principal="jonhy",
                        enabled=True,
                        keys=(UserKeyPolicy(id="jonhy-laptop", public_key="ssh-ed25519 AAAAExample jonhy-key"),),
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

    def test_signer_file_content_can_be_generated_from_user_keys(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(temp_dir)

            signer_file_content = signer_file_content_for_principal(config, "jonhy")

        self.assertEqual(
            signer_file_content,
            "jonhy sk-ssh-ed25519@openssh.com AAAAExample jonhy-key\n",
        )

    def test_key_level_policy_filters_disabled_and_expired_keys(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(
                temp_dir,
                users={
                    "jonhy": UserPolicy(
                        principal="jonhy",
                        keys=(
                            UserKeyPolicy(id="disabled", public_key="ssh-ed25519 AAAADisabled", enabled=False),
                            UserKeyPolicy(id="expired", public_key="ssh-ed25519 AAAAExpired", expires_at=99),
                            UserKeyPolicy(id="active", public_key="ssh-ed25519 AAAAActive", expires_at=200),
                        ),
                    )
                },
            )

            keys = active_signing_keys_for_principal(config, "jonhy", now=120)

        self.assertEqual([key.id for key in keys], ["active"])

    def test_envelope_kid_must_match_payload_principal(self):
        payload = make_payload()
        envelope = build_envelope(canonical_json(payload), b"signature", kid="alice", created_at=100)

        with self.assertRaisesRegex(PermissionDenied, "kid_principal_mismatch"):
            validate_envelope_kid(envelope, payload)

    def test_queue_index_resolves_relative_command_urls(self):
        queue = canonical_json(
            {
                "queue_version": 1,
                "target": "x162",
                "commands": [
                    {
                        "command_id": "4ca1165b-37d3-4534-af9e-b4c2f5232b19",
                        "url": "/commands/x162/4ca1165b-37d3-4534-af9e-b4c2f5232b19.json",
                    }
                ],
            }
        ).decode("utf-8")

        urls = parse_queue_index(queue, source_url="https://publisher.example.com/commands/x162/index.json")

        self.assertEqual(
            urls,
            ["https://publisher.example.com/commands/x162/4ca1165b-37d3-4534-af9e-b4c2f5232b19.json"],
        )

    @patch("pullknock.agent.age_decrypt")
    def test_decrypt_envelope_if_needed_supports_v2(self, decrypt):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = make_payload()
            inner = build_envelope(canonical_json(payload), b"signature", kid="jonhy", created_at=100)
            decrypt.return_value = canonical_json(inner)
            config = make_config(temp_dir)
            config = AgentConfig(
                server=config.server,
                security=SecurityConfig(nonce_db=f"{temp_dir}/nonces.sqlite3", age=AgeConfig(identity_files=("/age.key",))),
                firewall=config.firewall,
                users=config.users,
                grants=config.grants,
            )
            outer = build_envelope_v2(
                b"ciphertext",
                kid="jonhy",
                encryption_key_id="x162-age-2026q3",
                created_at=100,
            )

            decrypted = decrypt_envelope_if_needed(outer, config)

        self.assertEqual(decrypted, canonical_json(inner))
        decrypt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
