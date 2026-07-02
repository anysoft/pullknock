import tempfile
import unittest

from pullknock.errors import ConfigError
from pullknock.config import load_agent_config, load_cli_config


class ConfigTest(unittest.TestCase):
    def test_agent_config_requires_user_keys(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/agent.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    f"""
server:
  id: "x162"
  control_url: "{temp_dir}/command.json"
security:
  nonce_db: "{temp_dir}/nonces.sqlite3"
grants:
  ssh:
    allowed_principals: ["jonhy"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0"]
users:
  jonhy:
    keys:
      - id: "jonhy-yubikey"
        public_key: "sk-ssh-ed25519@openssh.com AAAAExample jonhy-key"
    allowed_grants: ["ssh"]
    allow_source_cidrs: ["0.0.0.0/0"]
"""
                )

            config = load_agent_config(path)

        self.assertEqual(
            config.users["jonhy"].keys[0].public_key,
            "sk-ssh-ed25519@openssh.com AAAAExample jonhy-key",
        )
        self.assertEqual(config.server.control_urls, (f"{temp_dir}/command.json",))

    def test_agent_config_rejects_public_keys_field(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/agent.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    f"""
server:
  id: "x162"
  control_url: "{temp_dir}/command.json"
security:
  nonce_db: "{temp_dir}/nonces.sqlite3"
grants:
  ssh:
    allowed_principals: ["jonhy"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0"]
users:
  jonhy:
    public_keys:
      - "ssh-ed25519 AAAAExample jonhy-key"
    allowed_grants: ["ssh"]
"""
                )

            with self.assertRaisesRegex(ConfigError, "public_keys is unsupported"):
                load_agent_config(path)

    def test_agent_config_supports_control_url_fallback_audit_and_nftables(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/agent.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    f"""
server:
  id: "x162"
  control_urls:
    - "{temp_dir}/missing.json"
    - "{temp_dir}/command.json"
security:
  nonce_db: "{temp_dir}/nonces.sqlite3"
audit:
  log_file: "{temp_dir}/audit.log"
firewall:
  backend: "nftables"
  nft_cmd: "/usr/sbin/nft"
  nft_family: "inet"
  nft_table: "pullknock"
  nft_set_prefix: "pk"
  nft_setup_sets: true
grants:
  ssh:
    allowed_principals: ["jonhy"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0"]
users:
  jonhy:
    keys:
      - id: "jonhy-laptop"
        public_key: "ssh-ed25519 AAAAExample jonhy-key"
    allowed_grants: ["ssh"]
    allow_source_cidrs: ["0.0.0.0/0"]
"""
                )

            config = load_agent_config(path)

        self.assertEqual(config.server.control_url, f"{temp_dir}/missing.json")
        self.assertEqual(config.server.control_urls, (f"{temp_dir}/missing.json", f"{temp_dir}/command.json"))
        self.assertEqual(config.audit.log_file, f"{temp_dir}/audit.log")
        self.assertEqual(config.firewall.backend, "nftables")
        self.assertEqual(config.firewall.nft_set_prefix, "pk")

    def test_agent_config_supports_groups_grant_inheritance_and_age(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/agent.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    f"""
server:
  id: "x162"
  control_url: "{temp_dir}/command.json"
security:
  nonce_db: "{temp_dir}/nonces.sqlite3"
  age:
    identity_files:
      - "{temp_dir}/age.key"
groups:
  ops:
    allowed_grants: ["ssh-prod"]
    max_timeout_seconds: 40
    allow_source_cidrs: ["203.0.113.0/24"]
grants:
  ssh-base:
    allowed_groups: ["ops"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0"]
  ssh-prod:
    inherits: ["ssh-base"]
    description: "prod ssh"
    max_timeout_seconds: 30
users:
  jonhy:
    groups: ["ops"]
    keys:
      - id: "jonhy-laptop"
        public_key: "ssh-ed25519 AAAAExample jonhy-key"
"""
                )

            config = load_agent_config(path)

        self.assertEqual(config.security.age.identity_files, (f"{temp_dir}/age.key",))
        self.assertEqual(config.security.age.envelope_version, 2)
        self.assertEqual(config.users["jonhy"].groups, ("ops",))
        self.assertEqual(config.grants["ssh-prod"].ports[0].port, 22)
        self.assertEqual(config.grants["ssh-prod"].allowed_groups, ("ops",))
        self.assertEqual(config.grants["ssh-prod"].max_timeout_seconds, 30)

    def test_agent_config_supports_key_level_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/agent.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    f"""
server:
  id: "x162"
  control_url: "{temp_dir}/command.json"
security:
  nonce_db: "{temp_dir}/nonces.sqlite3"
grants:
  ssh:
    allowed_principals: ["jonhy"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0"]
users:
  jonhy:
    keys:
      - id: "jonhy-yubikey-2026"
        enabled: true
        public_key: "ssh-ed25519 AAAAExample jonhy-key"
        expires_at: "2027-01-01T00:00:00+00:00"
        comment: "Jonhy YubiKey"
    allowed_grants: ["ssh"]
    allow_source_cidrs: ["0.0.0.0/0"]
"""
                )

            config = load_agent_config(path)

        self.assertEqual(config.users["jonhy"].keys[0].id, "jonhy-yubikey-2026")

    def test_agent_config_rejects_bad_firewall_zone(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/agent.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    f"""
server:
  id: "x162"
  control_url: "{temp_dir}/command.json"
security:
  nonce_db: "{temp_dir}/nonces.sqlite3"
firewall:
  default_zone: "public;rm"
grants:
  ssh:
    allowed_principals: ["jonhy"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0"]
users:
  jonhy:
    keys:
      - id: "jonhy-laptop"
        public_key: "ssh-ed25519 AAAAExample jonhy-key"
    allowed_grants: ["ssh"]
    allow_source_cidrs: ["0.0.0.0/0"]
"""
                )

            with self.assertRaisesRegex(ConfigError, "firewall.default_zone"):
                load_agent_config(path)

    def test_cli_age_v2_requires_key_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/cli.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    """
defaults:
  principal: "jonhy"
  private_key: "~/.ssh/pullknock"
  age:
    envelope_version: 2
    recipients:
      - "age1exampleonlyreplacewithvalidrecipient000000000000000000000000000"
publishers:
  local:
    type: "file"
    path: "/tmp/pullknock-command.json"
targets:
  x162:
    target: "x162"
    grant_id: "ssh"
    publisher: "local"
"""
                )

            with self.assertRaisesRegex(ConfigError, "key_id"):
                load_cli_config(path)

    def test_cli_age_v2_loads_key_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/cli.yaml"
            with open(path, "w", encoding="utf-8") as file:
                file.write(
                    """
defaults:
  principal: "jonhy"
  private_key: "~/.ssh/pullknock"
  age:
    envelope_version: 2
    key_id: "x162-age-2026q3"
    recipients:
      - "age1exampleonlyreplacewithvalidrecipient000000000000000000000000000"
publishers:
  local:
    type: "file"
    path: "/tmp/pullknock-command.json"
targets:
  x162:
    target: "x162"
    grant_id: "ssh"
    publisher: "local"
"""
                )

            config = load_cli_config(path)

        self.assertEqual(config.defaults.age.envelope_version, 2)
        self.assertEqual(config.defaults.age.key_id, "x162-age-2026q3")


if __name__ == "__main__":
    unittest.main()
