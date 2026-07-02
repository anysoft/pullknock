#!/usr/bin/env python3
"""Run a local PullKnock end-to-end test using file publisher and agent dry-run."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    python = sys.executable
    with tempfile.TemporaryDirectory(prefix="pullknock-e2e-") as temp_dir:
        temp = Path(temp_dir)
        key_path = temp / "pullknock_test_key"
        command_path = temp / "command.json"
        cli_config = temp / "cli.yaml"
        agent_config = temp / "agent.yaml"
        nonce_db = temp / "nonces.sqlite3"

        run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path), "-C", "pullknock-e2e"], capture=True)
        public_key = key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()

        cli_config.write_text(
            f"""
defaults:
  principal: "e2e-user"
  signature_namespace: "pullknock-v1"
  private_key: {json.dumps(str(key_path))}
  command_ttl_seconds: 60
  requested_timeout_seconds: 30
publishers:
  local:
    type: "file"
    path: {json.dumps(str(command_path))}
targets:
  x162:
    target: "x162-e2e"
    grant_id: "ssh"
    publisher: "local"
""".lstrip(),
            encoding="utf-8",
        )

        agent_config.write_text(
            f"""
server:
  id: "x162-e2e"
  control_url: {json.dumps(str(command_path))}
security:
  signature_namespace: "pullknock-v1"
  nonce_db: {json.dumps(str(nonce_db))}
firewall:
  backend: "firewalld"
  firewall_cmd: "/usr/bin/firewall-cmd"
  default_zone: "public"
users:
  e2e-user:
    enabled: true
    keys:
      - id: "e2e-key"
        public_key: {json.dumps(public_key)}
    allowed_grants:
      - "ssh"
    max_timeout_seconds: 30
    allow_source_cidrs:
      - "203.0.113.0/24"
grants:
  ssh:
    description: "E2E SSH dry-run grant"
    allowed_principals:
      - "e2e-user"
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 30
    zone: "public"
    allow_source_cidrs:
      - "0.0.0.0/0"
""".lstrip(),
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo) + os.pathsep + env.get("PYTHONPATH", "")

        run(
            [python, "-m", "pullknock.cli", "open", "x162", "--config", str(cli_config), "--source-ip", "203.0.113.7"],
            env=env,
            capture=True,
        )
        result = run(
            [python, "-m", "pullknock.agent", "--config", str(agent_config), "--dry-run", "--once"],
            env=env,
            capture=True,
        )

        output = result.stdout + result.stderr
        if "success: grant_opened" not in output or "--add-rich-rule" not in output:
            print(output, file=sys.stderr)
            print("E2E failed: expected successful dry-run firewalld command", file=sys.stderr)
            return 1

        print("E2E file-mode dry-run OK")
        print(output.strip())
        return 0


def run(args: list[str], *, env: dict[str, str] | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=True,
        text=True,
        env=env,
        capture_output=capture,
    )


if __name__ == "__main__":
    raise SystemExit(main())
