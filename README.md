# PullKnock

PullKnock is a lightweight reverse-pull dynamic firewall authorizer. The server exposes no knock port. A client signs a short-lived authorization payload with an OpenSSH key, publishes the signed envelope to an untrusted fixed location, and the server agent polls that location, verifies the signature and local policy, then opens a temporary firewalld runtime rule.

The security boundary is not the secrecy of the URL. It is:

- OpenSSH SSHSIG signatures, ideally backed by a YubiKey/FIDO2 key
- server-side allowed signers
- short `expires_at`
- one-time `command_id` nonce storage
- local user and grant allowlists
- firewalld `--timeout` runtime rules

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

The package installs two commands:

```bash
pullknock --help
pullknock-agent --help
```

## Generate A Signing Key

Recommended YubiKey/FIDO2 key:

```bash
ssh-keygen -t ed25519-sk -f ~/.ssh/pullknock_ed25519_sk -C "jonhy-pullknock"
```

For local testing without a hardware key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/pullknock_ed25519_test -C "jonhy-pullknock-test"
```

## Create allowed_signers

On the server:

```bash
sudo install -d -m 700 /etc/pullknock
printf 'jonhy ' | sudo tee /etc/pullknock/allowed_signers
cat ~/.ssh/pullknock_ed25519_sk.pub | sudo tee -a /etc/pullknock/allowed_signers
sudo chmod 600 /etc/pullknock/allowed_signers
```

The principal before the key, such as `jonhy`, must match the signed payload principal and the agent policy.

## CLI Config

Copy and edit:

```bash
mkdir -p ~/.config/pullknock
cp examples/cli-config.yaml ~/.config/pullknock/config.yaml
```

Example:

```yaml
defaults:
  principal: "jonhy"
  signature_namespace: "pullknock-v1"
  private_key: "~/.ssh/pullknock_ed25519_sk"
  command_ttl_seconds: 60
  requested_timeout_seconds: 60

publishers:
  local:
    type: "file"
    path: "/tmp/pullknock-command.json"

targets:
  x162:
    target: "x162-43-32-23"
    grant_id: "x162-ssh"
    publisher: "local"
```

Open a target:

```bash
pullknock open x162 --source-ip 203.0.113.7 --reason "temporary ssh"
```

If `--source-ip` is omitted, the CLI asks multiple public IP providers. If they disagree, the command fails instead of guessing.

## Agent Config

Copy and edit:

```bash
sudo cp examples/agent.yaml /etc/pullknock/agent.yaml
sudo install -d -m 700 /var/lib/pullknock
sudo chmod 600 /etc/pullknock/agent.yaml
```

The agent supports multi-user permission management:

```yaml
users:
  jonhy:
    enabled: true
    allowed_grants: ["x162-ssh"]
    max_timeout_seconds: 60
    expires_at: "2027-07-01T00:00:00+00:00"
    allow_source_cidrs: ["0.0.0.0/0", "::/0"]

grants:
  x162-ssh:
    allowed_principals: ["jonhy"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    zone: "public"
    allow_source_cidrs: ["0.0.0.0/0", "::/0"]
```

Both user policy and grant policy must allow the request. The final timeout is capped by the lower of user and grant maximums. Ports, protocols, and zone always come from the server YAML, never from the remote payload.

## File Publisher Test

Terminal 1:

```bash
pullknock-agent --config examples/agent.yaml --dry-run --once
```

Terminal 2:

```bash
pullknock open x162 --config examples/cli-config.yaml --source-ip 203.0.113.7
pullknock-agent --config examples/agent.yaml --dry-run --once
```

In dry-run mode the agent prints the `firewall-cmd` call instead of changing the firewall.

## HTTP PUT Publisher

Configure the CLI publisher:

```yaml
publishers:
  x162-http:
    type: "http_put"
    url: "https://example.com/hidden/path/pullknock-command.json"
    timeout_seconds: 10
    headers:
      Authorization: "Bearer ${PULLKNOCK_UPLOAD_TOKEN}"
```

Configure the agent:

```yaml
server:
  control_url: "https://example.com/hidden/path/pullknock-command.json"
```

`pullknock` sends the envelope JSON as the PUT body with `Content-Type: application/json`. Non-2xx responses fail the command.

## systemd

```bash
sudo cp systemd/pullknock-agent.service /etc/systemd/system/pullknock-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now pullknock-agent
sudo journalctl -u pullknock-agent -f
```

The sample service runs as root because `firewall-cmd` usually needs privileges. Harden further with sudoers or a dedicated helper once your deployment is stable.

## firewalld Checks

List runtime rich rules:

```bash
sudo firewall-cmd --zone public --list-rich-rules
```

Expected IPv4 rule shape:

```text
rule family="ipv4" source address="203.0.113.7" port port="22" protocol="tcp" accept
```

Check firewalld state:

```bash
sudo firewall-cmd --state
sudo firewall-cmd --get-active-zones
```

PullKnock does not use `--permanent`; firewalld removes the rule automatically when `--timeout` expires.

## Security Notes

- Do not put shell commands in the payload. PullKnock only accepts `grant_id`.
- Keep `allowed_signers` and the nonce DB readable only by root.
- Keep `signature_namespace` fixed to `pullknock-v1`.
- Treat the control URL as untrusted and possibly public.
- Use short command TTLs and short grant timeouts.
- Prefer explicit `--source-ip` when your network has multiple public egress IPs.
- Disable users by setting `users.<principal>.enabled: false`.
- Expire temporary users with `users.<principal>.expires_at`.
