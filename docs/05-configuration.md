# 05-配置模型

## CLI 配置

默认路径：

```text
~/.config/pullknock/config.yaml
```

核心结构：

```yaml
defaults:
  principal: "jonhy"
  signature_namespace: "pullknock-v1"
  private_key: "~/.ssh/pullknock_ed25519_sk"
  command_ttl_seconds: 60
  requested_timeout_seconds: 60
  age:
    envelope_version: 2
    key_id: "x162-age-2026q3"
    recipients:
      - "age1..."

publishers:
  local:
    type: "file"
    path: "/tmp/pullknock-command.json"

  webdav-box:
    type: "webdav_put"
    url: "https://webdav.example.com/pullknock/pullknock-command.json"
    username: "${PULLKNOCK_WEBDAV_USER}"
    password: "${PULLKNOCK_WEBDAV_PASSWORD}"

  anonymous-ftp:
    type: "ftp_upload"
    url: "ftp://ftp.example.com/pub/pullknock-command.json"
    username: "anonymous"
    password: "anonymous@"

  ipfs-node:
    type: "ipfs_http"
    api_url: "http://127.0.0.1:5001"
    filename: "pullknock-command.json"
    ipns_key: "pullknock"

  s3-object:
    type: "s3_put"
    endpoint_url: "https://s3.example.com"
    region: "us-east-1"
    bucket: "pullknock"
    key: "commands/x162.json"
    access_key_id: "${PULLKNOCK_S3_ACCESS_KEY_ID}"
    secret_access_key: "${PULLKNOCK_S3_SECRET_ACCESS_KEY}"

targets:
  x162:
    target: "x162-43-32-23"
    grant_id: "x162-ssh"
    publisher: "local"
```

## Agent 配置

默认路径：

```text
/etc/pullknock/agent.yaml
```

核心结构：

```yaml
server:
  id: "x162-43-32-23"
  control_url: "https://publisher.example.com/pullknock-command.json"
  control_urls:
    - "https://publisher.example.com/pullknock-command.json"
    - "https://storage.example.com/pullknock-command.json"

audit:
  log_file: "/var/log/pullknock/audit.log"

security:
  signature_namespace: "pullknock-v1"
  nonce_db: "/var/lib/pullknock/nonces.sqlite3"
  age:
    envelope_version: 2
    key_id: "x162-age-2026q3"
    identity_files:
      - "/etc/pullknock/age-current.key"

firewall:
  backend: "firewalld"
  firewall_cmd: "/usr/bin/firewall-cmd"
  default_zone: "public"

users:
  jonhy:
    enabled: true
    groups: ["ops"]
    keys:
      - id: "jonhy-yubikey-2026"
        enabled: true
        public_key: "sk-ssh-ed25519@openssh.com AAAA... jonhy-yubikey"
        expires_at: "2027-01-01T00:00:00+00:00"
        comment: "Jonhy YubiKey 5C"
    allowed_grants: ["x162-ssh"]
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0", "::/0"]

groups:
  ops:
    allowed_grants: ["x162-ssh"]
    max_timeout_seconds: 45
    allow_source_cidrs: ["0.0.0.0/0", "::/0"]

grants:
  ssh-base:
    allowed_groups: ["ops"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0", "::/0"]

  x162-ssh:
    inherits: ["ssh-base"]
    allowed_principals: ["jonhy"]
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    allow_source_cidrs: ["0.0.0.0/0", "::/0"]
```

## Publisher 服务配置

默认路径：

```text
/etc/pullknock/publisher.yaml
```

核心结构：

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  path: "/pullknock-command.json"
  health_path: "/healthz"

storage:
  mode: "latest"
  envelope_file: "/var/lib/pullknock-publisher/command.json"
  queue_dir: "/var/lib/pullknock-publisher/commands"

auth:
  write_bearer_tokens:
    - "${PULLKNOCK_UPLOAD_TOKEN}"
  require_auth_for_read: false
  read_bearer_tokens: []
```

## 配置校验规则

- YAML 顶层必须是 mapping。
- `users` 至少包含一个用户。
- 每个用户必须配置至少一个 `keys[]`。
- 公钥必须是单行 OpenSSH public key。
- `grants` 至少包含一个 grant。
- grant port 必须为 `1..65535`。
- protocol 只能是 `tcp` 或 `udp`。
- CIDR 必须能被 `ipaddress.ip_network` 解析。
- publisher bearer token 支持环境变量展开，但不能残留未展开变量。
- WebDAV/FTP publisher 的账号密码支持环境变量展开。
- `ipfs_http` 通过 Kubo HTTP API `/api/v0/add` 上传 envelope，可选发布 IPNS。
- `s3_put` 使用 AWS Signature V4 PUT，适配 S3 兼容对象存储。
- publisher URL 和 agent `control_url` 支持环境变量展开。
- agent 可用 `server.control_urls` 配置多个控制位置；按顺序尝试，全部失败才报错。
- FTP/FTPS control URL 可直接写 `ftp://user:password@host/path/file`，也可用环境变量隐藏账号密码。
- `firewall.backend` 支持 `firewalld` 和 `nftables`。
- `audit.log_file` 可把 JSON Lines 审计日志写入文件；命令行 `--log-file` 会覆盖该配置。
- `defaults.age` 配置后 CLI 发布加密 envelope；默认 `envelope_version: 2`，需要配置 `key_id`。
- `defaults.age.envelope_version: 1` 可发布 v1 `age+plain+sshsig` 加密 envelope。
- `security.age.identity_files` 配置后 agent 可同时解密 v1 和 v2 加密 envelope。
- `users.<principal>.keys` 用于 SSHSIG 验签，并支持设备级 enabled、有效期和审计。
- `http_put.url` 支持 `{target}`、`{grant_id}`、`{command_id}`、`{principal}` 占位符，适合 publisher queue endpoint。
- 用户可通过 `users.<principal>.groups` 继承组策略。
- grant 可通过 `inherits` 继承父 grant，可通过 `allowed_groups` 授权整个用户组。

## 运维建议

- agent 配置文件权限：`600/root`。
- publisher 配置文件权限：`600`。
- token 放到 `EnvironmentFile`，不要硬编码进仓库。
- 修改用户公钥、权限、control URL、审计日志路径或防火墙配置后，可用 `systemctl reload pullknock-agent` 热重载 agent。

## nftables 后端

nftables 后端不会直接拼接 shell，也不会依赖 agent 自己延时删除规则。它会把来源 IP 添加到带 timeout 的 nft set：

```bash
nft add element inet pullknock pullknock_tcp_22_ipv4 { 203.0.113.7 timeout 60s }
```

生产环境需要在 nftables 规则集中引用这些 set，例如：

```nft
table inet pullknock {
  set pullknock_tcp_22_ipv4 {
    type ipv4_addr
    flags timeout
  }

  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr @pullknock_tcp_22_ipv4 tcp dport 22 accept
  }
}
```

agent 可选地尝试创建 table/set：

```yaml
firewall:
  backend: "nftables"
  nft_cmd: "/usr/sbin/nft"
  nft_family: "inet"
  nft_table: "pullknock"
  nft_set_prefix: "pullknock"
  nft_setup_sets: true
```

`nft_setup_sets: true` 只负责创建 table/set，不会替你设计完整防火墙策略；实际放行规则仍建议由运维在 nftables 配置里明确管理。

如果 firewalld 也启用了 nftables backend，不要单独创建另一个 input base chain 并依赖该 chain 的 `accept`。firewalld 后续 chain 仍可能 reject/drop。此时优先使用 `firewall.backend: firewalld`，或把 nftables set 接入 firewalld 管理的规则路径。

## 用户组与 grant 继承

用户组可定义共享限制：

```yaml
groups:
  ops:
    allowed_grants: ["x162-ssh"]
    max_timeout_seconds: 45
    allow_source_cidrs: ["203.0.113.0/24"]
```

用户加入组：

```yaml
users:
  jonhy:
    groups: ["ops"]
    keys:
      - id: "jonhy-laptop"
        public_key: "ssh-ed25519 AAAA... jonhy"
```

合并规则：

- 用户直接 `allowed_grants` 和启用组的 `allowed_grants` 取并集。
- timeout 上限取用户、组、grant 中的最小值。
- 用户和组的 `allow_source_cidrs` 取并集；之后仍必须同时通过 grant CIDR。
- grant 可用 `allowed_groups` 授权组成员。
- grant `inherits` 会继承父 grant 的 ports、principal/group 白名单、CIDR、zone 和 timeout 上限。

## 多服务器配置生成

使用 inventory 生成多台服务器配置：

```bash
pullknock-configgen examples/inventory.yaml ./generated --force
```

输出：

```text
generated/
  cli-config.yaml
  agents/
    x162.agent.yaml
```

inventory 支持共享 `publishers`、`users`、`groups`、`grant_templates`，每台服务器只声明自己的 `server` 和 `grants`。
