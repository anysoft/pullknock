# 07-部署与运维

## 安装

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

命令：

```bash
pullknock --help
pullknock-agent --help
pullknock-publisher --help
pullknock-admin --help
```

## Agent 部署

```bash
sudo install -d -m 700 /etc/pullknock
sudo install -d -m 700 /var/lib/pullknock
sudo cp examples/agent.yaml /etc/pullknock/agent.yaml
sudo chmod 600 /etc/pullknock/agent.yaml
```

systemd：

```bash
sudo cp systemd/pullknock-agent.service /etc/systemd/system/pullknock-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now pullknock-agent
sudo journalctl -u pullknock-agent -f
```

配置热重载：

```bash
sudo systemctl reload pullknock-agent
```

reload 会重新读取 `/etc/pullknock/agent.yaml`。如果新配置无效，agent 会记录 `agent_config_reload_failed`，并继续使用旧配置。

## Web 管理界面

只读启动：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --host 127.0.0.1 --port 8765
```

允许保存和 reload：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --allow-write --allow-reload
```

开启认证、历史目录和审计日志路径：

```bash
export PULLKNOCK_ADMIN_TOKEN='change-me-long-random-token'
pullknock-admin \
  --config /etc/pullknock/agent.yaml \
  --auth-token "$PULLKNOCK_ADMIN_TOKEN" \
  --history-dir /var/lib/pullknock/config-history \
  --audit-log /var/log/pullknock/audit.log
```

默认只监听本机。生产环境建议通过 SSH tunnel、WireGuard、mTLS 或可信反向代理认证访问。

## Publisher 部署

```bash
sudo useradd --system --home /var/lib/pullknock-publisher --shell /usr/sbin/nologin pullknock
sudo install -d -o pullknock -g pullknock -m 700 /var/lib/pullknock-publisher
sudo cp examples/publisher.yaml /etc/pullknock/publisher.yaml
sudo chmod 600 /etc/pullknock/publisher.yaml
```

环境变量：

```bash
sudo install -m 600 /dev/null /etc/pullknock/publisher.env
echo 'PULLKNOCK_UPLOAD_TOKEN=change-me-long-random-token' | sudo tee /etc/pullknock/publisher.env
```

systemd：

```bash
sudo cp systemd/pullknock-publisher.service /etc/systemd/system/pullknock-publisher.service
sudo systemctl daemon-reload
sudo systemctl enable --now pullknock-publisher
sudo journalctl -u pullknock-publisher -f
```

## firewalld 检查

```bash
sudo firewall-cmd --state
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone public --list-rich-rules
```

## nftables 检查

如果使用 `firewall.backend: nftables`，agent 会向端口和地址族对应的 set 添加带 timeout 的来源 IP，例如 `pullknock_tcp_22_ipv4`。

```bash
sudo nft list table inet pullknock
sudo nft list set inet pullknock pullknock_tcp_22_ipv4
```

最小规则示例：

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

不要在 firewalld 仍启用 nftables backend 时，单独创建另一个 `inet pullknock` input base chain 并指望这里的 `accept` 全局生效。nftables 多个 base chain 挂在同一个 hook 时，某个 chain 中的 `accept` 不一定阻止后续 firewalld chain 继续 reject/drop。

推荐三种模式：

- 纯 firewalld：`firewall.backend: firewalld`，使用 firewalld rich rule timeout。
- 纯 nftables：禁用 firewalld，由运维维护完整 nftables policy，并在最终有效 input chain 中引用 PullKnock set。
- firewalld + nftables set 集成：不要创建独立 base chain，把 PullKnock set 接入 firewalld 管理的链路。

## 日志

agent 输出 JSON 审计日志，典型字段：

```json
{
  "event": "grant_opened",
  "principal": "jonhy",
  "target": "x162-43-32-23",
  "grant_id": "x162-ssh",
  "source_ip": "203.0.113.7",
  "timeout": 60,
  "command_id": "0d7b73e2-8d4c-4d61-a0ad-0bb5a5403fc0",
  "result": "success"
}
```

落文件：

```yaml
audit:
  log_file: "/var/log/pullknock/audit.log"
```

logrotate 示例：

```bash
sudo cp systemd/pullknock-agent.logrotate /etc/logrotate.d/pullknock-agent
```

## 备份

建议备份：

- `/etc/pullknock/agent.yaml`
- `/etc/pullknock/publisher.yaml`
- `/etc/pullknock/publisher.env`

不强制备份：

- nonce DB。删除后不会泄露密钥，但会丢失防重放历史。
- publisher envelope 文件。它只是最新命令布告。

## 常见排障

| 现象 | 检查 |
| --- | --- |
| CLI 上传失败 | token、URL、TLS、HTTP 状态码。 |
| agent 拉不到命令 | `control_url`/`control_urls`、网络、防火墙、publisher GET。 |
| 签名失败 | principal 是否一致、公钥是否填入对应 user。 |
| target mismatch | CLI target 和 agent `server.id` 是否一致。 |
| source IP 被拒绝 | 用户和 grant 的 CIDR 白名单。 |
| 没有开放端口 | dry-run 输出、firewalld zone、firewall-cmd 路径，或 nftables set/chain 规则。 |
| 重复请求无效 | nonce DB 已记录该 `command_id`，这是预期行为。 |
