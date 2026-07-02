import tempfile
import unittest
from pathlib import Path

import yaml

from pullknock.configgen import generate_configs


class ConfigGenTest(unittest.TestCase):
    def test_generate_configs_writes_agents_and_cli_targets(self):
        inventory = {
            "defaults": {
                "cli": {
                    "principal": "jonhy",
                    "private_key": "~/.ssh/pullknock",
                },
                "agent": {
                    "security": {"nonce_db": "/var/lib/pullknock/nonces.sqlite3"},
                    "firewall": {"backend": "firewalld"},
                },
            },
            "publishers": {
                "s3": {
                    "type": "s3_put",
                    "endpoint_url": "https://s3.example.com",
                    "bucket": "pullknock",
                    "key": "commands/x162.json",
                    "access_key_id": "${S3_ACCESS_KEY}",
                    "secret_access_key": "${S3_SECRET_KEY}",
                }
            },
            "users": {
                "jonhy": {
                    "keys": [{"id": "jonhy-laptop", "public_key": "ssh-ed25519 AAAAExample jonhy"}],
                    "groups": ["ops"],
                }
            },
            "groups": {
                "ops": {
                    "allowed_grants": ["ssh"],
                    "allow_source_cidrs": ["0.0.0.0/0"],
                }
            },
            "grant_templates": {
                "ssh": {
                    "allowed_groups": ["ops"],
                    "ports": [{"protocol": "tcp", "port": 22}],
                    "max_timeout_seconds": 60,
                    "allow_source_cidrs": ["0.0.0.0/0"],
                }
            },
            "servers": {
                "x162": {
                    "publisher": "s3",
                    "server": {"id": "x162", "control_url": "https://s3.example.com/pullknock/commands/x162.json"},
                    "grants": {"ssh": {"template": "ssh", "description": "x162 ssh"}},
                }
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            written = generate_configs(inventory, Path(temp_dir), force=False)

            agent = yaml.safe_load((Path(temp_dir) / "agents" / "x162.agent.yaml").read_text(encoding="utf-8"))
            cli = yaml.safe_load((Path(temp_dir) / "cli-config.yaml").read_text(encoding="utf-8"))

        self.assertEqual(len(written), 2)
        self.assertEqual(agent["server"]["id"], "x162")
        self.assertEqual(agent["grants"]["ssh"]["ports"][0]["port"], 22)
        self.assertEqual(cli["targets"]["x162-ssh"]["publisher"], "s3")


if __name__ == "__main__":
    unittest.main()
