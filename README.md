# PullKnock

PullKnock 是一个轻量级的“反向拉取式”动态防火墙授权工具，用来替代传统 knock 服务端口常驻暴露的模式。

它的工作方式是：客户端用 OpenSSH 私钥，推荐 YubiKey/FIDO2 security key，对一次性授权 payload 做 SSHSIG 签名，然后把签名后的 envelope 发布到一个固定 HTTPS 页面、对象存储或本地文件。服务器上的 `pullknock-agent` 主动轮询这个位置，验证签名、防重放、检查本地用户和 grant 权限，最后通过 `firewall-cmd --timeout` 临时开放 SSH 或其他被允许的端口。

固定页面只是一个不可信的消息投递通道。PullKnock 的安全边界来自：

- OpenSSH SSHSIG 签名，推荐使用 YubiKey/FIDO2 私钥
- 服务端 `users.<principal>.keys` 公钥验签
- 短时效 `expires_at`
- 一次性 `command_id` nonce 防重放
- 服务端本地用户策略和 grant 白名单
- firewalld `--timeout` 或 nftables set `timeout`

## 设计文档

完整设计文档见 [docs/README.md](./docs/README.md)，包括需求范围、系统架构、协议、安全模型、配置模型、publisher 服务、部署运维、测试计划和路线图。

## 开发与发布自动化

仓库内置 GitHub Actions CI、TestPyPI/PyPI Trusted Publishing、draft release 自动生成、release notes 检查、Dependabot、CodeQL、依赖安全扫描和 PR title 检查。发布流程、版本策略和本地检查命令见 [docs/11-release.md](./docs/11-release.md)。

## 安装

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

安装后会提供两个命令：

```bash
pullknock --help
pullknock-agent --help
pullknock-publisher --help
pullknock-admin --help
```

也可以直接用模块方式运行：

```bash
python3 -m pullknock.cli --help
python3 -m pullknock.agent --help
python3 -m pullknock.publisher_server --help
python3 -m pullknock.admin_server --help
```

## 生成签名密钥

推荐使用 YubiKey/FIDO2 security key：

```bash
ssh-keygen -t ed25519-sk -f ~/.ssh/pullknock_ed25519_sk -C "jonhy-pullknock"
```

本地测试时也可以先用普通 ed25519 key：

```bash
ssh-keygen -t ed25519 -f ~/.ssh/pullknock_ed25519_test -C "jonhy-pullknock-test"
```

签名时使用 OpenSSH SSHSIG：

```bash
ssh-keygen -Y sign -f ~/.ssh/pullknock_ed25519_sk -n pullknock-v1 payload.json
```

`pullknock-v1` 是固定签名 namespace，用来避免签名被跨协议复用。

## 配置用户公钥

推荐把验签公钥直接放进 agent 的用户配置里，这样一个用户的身份、公钥、有效期和授权范围都在同一个地方：

```yaml
users:
  jonhy:
    enabled: true
    keys:
      - id: "jonhy-yubikey-2026"
        enabled: true
        public_key: "sk-ssh-ed25519@openssh.com AAAAC3NzaC1... jonhy-yubikey"
        expires_at: "2027-01-01T00:00:00+00:00"
        comment: "Jonhy YubiKey 5C"
    allowed_grants:
      - "x162-ssh"
    max_timeout_seconds: 60
    expires_at: "2027-07-01T00:00:00+00:00"
```

`public_key` 的值就是 OpenSSH `.pub` 文件里的 key 内容，不需要在前面再写 principal。PullKnock 不使用单独的 signer 文件；key 级配置便于设备级禁用、过期和审计。

## CLI 配置

复制示例配置：

```bash
mkdir -p ~/.config/pullknock
cp examples/cli-config.yaml ~/.config/pullknock/config.yaml
```

配置示例：

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

  publisher-service:
    type: "http_put"
    url: "https://publisher.example.com/pullknock-command.json"
    timeout_seconds: 10
    headers:
      Authorization: "Bearer ${PULLKNOCK_UPLOAD_TOKEN}"

targets:
  x162:
    target: "x162-43-32-23"
    grant_id: "x162-ssh"
    publisher: "local"
```

`defaults.age` 启用后，CLI 默认发布 envelope v2：外层声明 `encryption_alg: age-v1`、`encryption_key_id` 和内层 `plain+sshsig` 格式。显式设置 `defaults.age.envelope_version: 1` 时会发布 v1 `age+plain+sshsig` 外层。

打开目标：

```bash
pullknock open x162 --source-ip 203.0.113.7 --reason "temporary ssh"
```

如果不传 `--source-ip`，CLI 会查询多个公网 IP provider。多个 provider 返回不一致时命令会失败，不会猜测使用哪个 IP。

常用参数：

```bash
pullknock open x162 --timeout 60
pullknock open x162 --reason "maintenance"
pullknock open x162 --dry-run
```

## Agent 配置

复制示例配置：

```bash
sudo cp examples/agent.yaml /etc/pullknock/agent.yaml
sudo install -d -m 700 /var/lib/pullknock
sudo chmod 600 /etc/pullknock/agent.yaml
```

核心配置示例：

```yaml
server:
  id: "x162-43-32-23"
  poll_interval_seconds: 5
  poll_jitter_seconds: 2
  control_url: "/tmp/pullknock-command.json"
  control_urls:
    - "https://publisher.example.com/pullknock-command.json"
    - "https://storage.example.com/pullknock-command.json"
  http_timeout_seconds: 5

audit:
  log_file: "/var/log/pullknock/audit.log"

security:
  signature_namespace: "pullknock-v1"
  nonce_db: "/var/lib/pullknock/nonces.sqlite3"
  max_clock_skew_seconds: 30
  max_command_ttl_seconds: 120
  nonce_retention_seconds: 604800
  age:
    identity_files:
      - "/etc/pullknock/age-current.key"

firewall:
  backend: "firewalld"
  firewall_cmd: "/usr/bin/firewall-cmd"
  default_zone: "public"
```

`control_url` 适合单一控制位置；`control_urls` 支持 fallback，agent 会按顺序尝试多个位置。配置文件修改后可用 `systemctl reload pullknock-agent` 热重载。

配置 `security.age.identity_files` 后，agent 会同时支持加密 envelope v1 和 v2；未配置 age 时仍可处理明文 `plain+sshsig` envelope。

## 多用户与权限管理

Agent 支持完整的本地多用户权限管理：

```yaml
users:
  jonhy:
    enabled: true
    display_name: "Jonhy"
    keys:
      - id: "jonhy-yubikey-2026"
        enabled: true
        public_key: "sk-ssh-ed25519@openssh.com AAAAC3NzaC1... jonhy-yubikey"
        expires_at: "2027-07-01T00:00:00+00:00"
        comment: "Jonhy YubiKey 5C"
    allowed_grants:
      - "x162-ssh"
    max_timeout_seconds: 60
    not_before: "2026-07-01T00:00:00+00:00"
    expires_at: "2027-07-01T00:00:00+00:00"
    allow_source_cidrs:
      - "0.0.0.0/0"
      - "::/0"

  ops-temp:
    enabled: true
    display_name: "Temporary ops user"
    keys:
      - id: "ops-temp-laptop"
        public_key: "ssh-ed25519 AAAAC3NzaC1... ops-temp"
        expires_at: "2026-08-01T00:00:00+00:00"
        comment: "Temporary ops laptop"
    allowed_grants:
      - "x162-ssh"
    max_timeout_seconds: 30
    expires_at: "2026-08-01T00:00:00+00:00"
    allow_source_cidrs:
      - "203.0.113.0/24"
```

grant 定义真正能打开哪些端口：

```yaml
grants:
  x162-ssh:
    description: "Temporary SSH access for x162"
    allowed_principals:
      - "jonhy"
      - "ops-temp"
    ports:
      - protocol: "tcp"
        port: 22
    max_timeout_seconds: 60
    zone: "public"
    allow_source_cidrs:
      - "0.0.0.0/0"
      - "::/0"
```

一次授权必须同时通过用户策略和 grant 策略：

- `target` 必须等于 `server.id`
- `grant_id` 必须存在
- `principal` 必须在 grant 的 `allowed_principals`
- 如果配置了 `users`，`principal` 也必须存在于 `users`
- 用户必须 `enabled: true`
- 用户必须有至少一把 enabled 且处于有效期内的 `users.<principal>.keys[]`
- 用户账号必须处在 `not_before` 和 `expires_at` 有效期内
- 用户的 `allowed_grants` 必须包含本次 `grant_id`
- `source_ip` 必须同时落在用户和 grant 的 CIDR 白名单内
- 最终 timeout 取 `requested_timeout`、用户 `max_timeout_seconds`、grant `max_timeout_seconds` 三者中的最小值

端口、协议、zone 只来自服务器本地 YAML，远端 payload 不能指定这些执行参数。

## SQLite nonce DB 是做什么的

`security.nonce_db` 指向一个 SQLite 数据库，用来保存已经成功处理过的 `command_id`。它的作用只有一个：防重放。

表里保存的信息类似：

```text
command_id
principal
grant_id
source_ip
issued_at
expires_at
processed_at
```

它不是用户数据库，也不保存私钥、公钥或防火墙状态。用户、公钥和权限都来自 YAML 配置；临时防火墙放行由 firewalld `--timeout` 或 nftables set `timeout` 管理，到期后防火墙后端自己删除。

为什么还需要 SQLite：

- 固定页面可能被别人读到，攻击者可以复制旧 envelope
- 即使签名是真的，同一个 `command_id` 也只能执行一次
- agent 重启后仍然记得哪些 signed command 已经处理过
- 过期记录会按 `nonce_retention_seconds` 清理，默认保留 7 天

不要随便删除 nonce DB。删除后不会泄露密钥或权限，但会丢失防重放历史；如果某条未过期 signed command 被别人保存过，就可能被再次投递。

## 本地 file publisher 测试

先用普通测试 key 或 YubiKey key，把 `.pub` 文件内容填到 `examples/agent.yaml` 的 `users.jonhy.keys[].public_key`，并把 `examples/cli-config.yaml` 里的 `private_key` 指向对应私钥。

生成 signed command：

```bash
pullknock open x162 --config examples/cli-config.yaml --source-ip 203.0.113.7
```

让 agent 读取本地文件并 dry-run：

```bash
pullknock-agent --config examples/agent.yaml --dry-run --once
```

dry-run 模式只打印将要执行的 `firewall-cmd` 命令，不会修改 firewalld。

## 内置 Publisher 服务

如果不想依赖对象存储，可以单独找一台机器部署 `pullknock-publisher`。它是一个极小的 HTTP 布告栏服务：

- `PUT /pullknock-command.json`：CLI 上传 envelope，需要 bearer token
- `GET /pullknock-command.json`：agent 拉取 envelope，可配置为公开读取或 bearer token 读取
- `GET /healthz`：健康检查
- envelope 落盘保存，写入使用原子替换
- 支持 command queue endpoint，避免多用户并发写入互相覆盖
- publisher 不参与信任决策，真正的验签、防重放和权限检查仍然只在 agent 上执行

复制配置：

```bash
sudo cp examples/publisher.yaml /etc/pullknock/publisher.yaml
sudo install -d -m 700 /var/lib/pullknock-publisher
sudo chmod 600 /etc/pullknock/publisher.yaml
```

配置示例：

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  path: "/pullknock-command.json"
  health_path: "/healthz"
  max_body_bytes: 65536

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

校验配置：

```bash
export PULLKNOCK_UPLOAD_TOKEN='change-me-long-random-token'
pullknock-publisher --config examples/publisher.yaml --check-config
```

本地启动：

```bash
pullknock-publisher --config examples/publisher.yaml
```

生产环境建议把 `pullknock-publisher` 绑定在 `127.0.0.1`，前面放 Nginx/Caddy/Traefik 终止 HTTPS，再把固定路径反代到本服务。CLI 配置里的 `http_put.url` 指向公网 HTTPS 地址，agent 的 `server.control_url` 也指向同一个地址。

CLI 指向 publisher：

```yaml
publishers:
  publisher-service:
    type: "http_put"
    url: "https://publisher.example.com/pullknock-command.json"
    timeout_seconds: 10
    headers:
      Authorization: "Bearer ${PULLKNOCK_UPLOAD_TOKEN}"
```

Agent 指向 publisher：

```yaml
server:
  control_url: "https://publisher.example.com/pullknock-command.json"
```

多用户并发场景建议使用 queue endpoint。CLI 的 `http_put.url` 可带 `{target}` 和 `{command_id}` 占位符：

publisher 服务端开启 queue：

```yaml
storage:
  mode: "queue"
  envelope_file: "/var/lib/pullknock-publisher/command.json"
  queue_dir: "/var/lib/pullknock-publisher/commands"
```

```yaml
publishers:
  publisher-queue:
    type: "http_put"
    url: "https://publisher.example.com/commands/{target}/{command_id}.json"
    headers:
      Authorization: "Bearer ${PULLKNOCK_UPLOAD_TOKEN}"
```

agent 轮询对应 index：

```yaml
server:
  control_url: "https://publisher.example.com/commands/x162-43-32-23/index.json"
```

如果希望 agent 拉取也要求 token，可以设置：

```yaml
auth:
  write_bearer_tokens:
    - "${PULLKNOCK_UPLOAD_TOKEN}"
  require_auth_for_read: true
  read_bearer_tokens:
    - "${PULLKNOCK_READ_TOKEN}"
```

同时在 agent 配置里加读取 header：

```yaml
server:
  control_url: "https://publisher.example.com/pullknock-command.json"
  control_headers:
    Authorization: "Bearer ${PULLKNOCK_READ_TOKEN}"
```

## HTTP / WebDAV / FTP publisher 测试

CLI publisher 示例：

```yaml
publishers:
  x162-http:
    type: "http_put"
    url: "https://example.com/hidden/path/pullknock-command.json"
    timeout_seconds: 10
    headers:
      Authorization: "Bearer ${PULLKNOCK_UPLOAD_TOKEN}"
```

Agent 拉取同一个 URL：

```yaml
server:
  control_url: "https://example.com/hidden/path/pullknock-command.json"
```

`pullknock` 会用 `PUT` 上传 envelope JSON，并设置 `Content-Type: application/json`。HTTP 非 2xx 返回会被视为失败。

WebDAV 示例：

```yaml
publishers:
  webdav-box:
    type: "webdav_put"
    url: "https://webdav.example.com/pullknock/pullknock-command.json"
    username: "${PULLKNOCK_WEBDAV_USER}"
    password: "${PULLKNOCK_WEBDAV_PASSWORD}"
    timeout_seconds: 10
    create_collections: false
```

匿名 FTP 示例：

```yaml
publishers:
  anonymous-ftp:
    type: "ftp_upload"
    url: "ftp://ftp.example.com/pub/pullknock-command.json"
    username: "anonymous"
    password: "anonymous@"
    passive: true
    create_dirs: true
```

Agent 可直接拉取 FTP/FTPS：

```yaml
server:
  control_url: "ftp://ftp.example.com/pub/pullknock-command.json"
```

带认证的 FTP/FTPS 可以用环境变量隐藏账号密码：

```yaml
server:
  control_url: "ftps://${PULLKNOCK_FTP_USER}:${PULLKNOCK_FTP_PASSWORD}@ftp.example.com/pullknock-command.json"
```

FTP 是明文协议，带账号密码时优先使用 FTPS 或 WebDAV HTTPS。匿名 FTP 也只是布告栏，不能替代 agent 的签名、防重放和本地权限校验。

## IPFS 与分布式存储

PullKnock 支持 `ipfs_http` publisher，可通过 Kubo HTTP API 上传 envelope，并可选发布到 IPNS。但它不建议作为第一优先级的 SSH 临时开门通道，原因是 PullKnock 的授权通常只有几十秒 TTL，而 IPFS/IPNS/DNSLink 的传播和缓存不一定足够稳定。

如果要使用 IPFS，需要解决“固定地址”问题：

- 直接 `ipfs add` 得到的是 CID，内容一变 CID 就变，agent 不能只配置一个固定 URL
- 使用 `ipfs_http.ipns_key` 可以得到固定名字，例如 `https://gateway.example.com/ipns/<key>`，但发布和传播可能慢
- 使用 DNSLink 可以绑定固定域名，但 DNS TTL 和网关缓存也会影响时效
- 使用 Pinning Service 时，还要处理 API token、pin 完成状态和网关一致性

因此当前推荐路径仍是：优先部署 `pullknock-publisher`，或使用对象存储、WebDAV、FTP/FTPS 这类固定位置。使用 IPFS/IPNS 时，agent 仍然只通过固定 HTTPS gateway URL 或 IPNS URL 拉取。

## systemd 部署

```bash
sudo cp systemd/pullknock-agent.service /etc/systemd/system/pullknock-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now pullknock-agent
sudo journalctl -u pullknock-agent -f
```

热重载配置：

```bash
sudo systemctl reload pullknock-agent
```

审计日志落文件和 logrotate：

```bash
sudo install -d -m 750 /var/log/pullknock
sudo cp systemd/pullknock-agent.logrotate /etc/logrotate.d/pullknock-agent
```

示例服务默认以 root 运行，因为 `firewall-cmd` 通常需要系统权限。生产环境可以进一步拆分为专用用户、sudoers 规则或本地 helper。

## Web 管理界面

本地启动只读管理界面：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --host 127.0.0.1 --port 8765
```

允许保存配置和 reload：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --allow-write --allow-reload
```

开启认证、审计日志查看和配置历史目录：

```bash
export PULLKNOCK_ADMIN_TOKEN='change-me-long-random-token'
pullknock-admin \
  --config /etc/pullknock/agent.yaml \
  --auth-token "$PULLKNOCK_ADMIN_TOKEN" \
  --audit-log /var/log/pullknock/audit.log \
  --history-dir /var/lib/pullknock/config-history
```

默认只监听 `127.0.0.1`。生产环境建议放在 SSH tunnel、WireGuard 或反向代理认证之后使用，不建议直接暴露公网。

Publisher 服务可以用独立用户运行：

```bash
sudo useradd --system --home /var/lib/pullknock-publisher --shell /usr/sbin/nologin pullknock
sudo install -d -o pullknock -g pullknock -m 700 /var/lib/pullknock-publisher
sudo install -m 600 examples/publisher.yaml /etc/pullknock/publisher.yaml
sudo install -m 600 /dev/null /etc/pullknock/publisher.env
echo 'PULLKNOCK_UPLOAD_TOKEN=change-me-long-random-token' | sudo tee /etc/pullknock/publisher.env
sudo cp systemd/pullknock-publisher.service /etc/systemd/system/pullknock-publisher.service
sudo systemctl daemon-reload
sudo systemctl enable --now pullknock-publisher
sudo journalctl -u pullknock-publisher -f
```

## firewalld 排查

查看 firewalld 状态：

```bash
sudo firewall-cmd --state
sudo firewall-cmd --get-active-zones
```

查看 runtime rich rules：

```bash
sudo firewall-cmd --zone public --list-rich-rules
```

预期 IPv4 规则形态类似：

```text
rule family="ipv4" source address="203.0.113.7" port port="22" protocol="tcp" accept
```

PullKnock 不使用 `--permanent`。规则会在 `--timeout` 到期后由 firewalld 自动移除。

## nftables 排查

使用 nftables 后端时，agent 会把来源 IP 添加到带 timeout 的 set，例如 `pullknock_tcp_22_ipv4`：

```yaml
firewall:
  backend: "nftables"
  nft_cmd: "/usr/sbin/nft"
  nft_family: "inet"
  nft_table: "pullknock"
  nft_set_prefix: "pullknock"
  nft_setup_sets: true
```

查看动态 set：

```bash
sudo nft list table inet pullknock
sudo nft list set inet pullknock pullknock_tcp_22_ipv4
```

实际放行规则需要在 nftables 规则集中引用这些 set，详见 [docs/05-configuration.md](./docs/05-configuration.md)。
如果系统仍启用了 firewalld 的 nftables backend，不要额外创建独立 input base chain 并指望其中的 accept 全局生效；应使用纯 firewalld、纯 nftables，或把 set 接入 firewalld 管理链路。

## 测试

项目测试只依赖 Python 标准库：

```bash
python3 -m compileall pullknock tests
python3 -m unittest discover -s tests
```

入口检查：

```bash
python3 -m pullknock.cli --help
python3 -m pullknock.agent --help
python3 -m pullknock.publisher_server --help
```

本地端到端 dry-run：

```bash
python3 scripts/e2e_file_mode.py
```

生成配置 schema 文档：

```bash
python3 scripts/generate_config_schema_docs.py
```

发布前检查：

```bash
python3 -m pip install -e ".[release]"
python3 scripts/release_check.py
```

release notes 检查：

```bash
python3 scripts/check_release_notes.py
```

发布辅助检查：

```bash
python3 scripts/check_release_tag.py --tag v0.1.0 --require-tag
python3 scripts/verify_wheel_install.py
python3 scripts/generate_sbom.py
python3 scripts/verify_systemd_hardening.py
```

提取当前版本 release notes：

```bash
python3 scripts/extract_release_notes.py
```

pre-commit：

```bash
python3 -m pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
```

依赖安全扫描：

```bash
python3 -m pip install -e ".[security]"
python3 scripts/security_scan.py
```

## 安全注意事项

- 不要在 payload 中放 shell 命令。PullKnock 只接受 `grant_id`。
- 不要相信固定页面 URL 的保密性。它只是布告栏。
- agent 配置和 nonce DB 建议 root 拥有，并设置为 `600`。
- `signature_namespace` 建议固定为 `pullknock-v1`。
- `command_ttl_seconds` 和 grant timeout 应尽量短。
- 多出口网络下建议显式传 `--source-ip`。
- 临时用户用 `users.<principal>.expires_at` 设置过期时间。
- 禁用用户用 `users.<principal>.enabled: false`。
- 控制 URL 拉取失败不会影响已经存在的临时防火墙放行。
- Publisher 服务只负责投递，不负责授权；不要把它当成可信控制面。
