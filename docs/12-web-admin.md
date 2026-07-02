# 12-Web 管理界面

`pullknock-admin` 是 PullKnock 的专用本地 Web 管理界面。它复用现有 YAML 配置、schema 校验和 agent `--check-config`，不引入数据库，也不改变 agent 的授权事实源。

## 启动

只读模式：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --host 127.0.0.1 --port 8765
```

允许保存配置：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --allow-write
```

允许 reload：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --allow-reload
```

启用内置认证：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --basic-auth admin:change-me
pullknock-admin --config /etc/pullknock/agent.yaml --auth-token "$PULLKNOCK_ADMIN_TOKEN"
```

信任反向代理认证结果：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --trusted-user-header X-Remote-User
```

## 功能

- 总览 server、control URLs、users、groups、grants、firewall、audit 和 age 状态。
- 查看用户、用户组、grant 继承和端口策略。
- YAML 编辑器。
- 保存前完整校验 agent 配置。
- 保存时原子替换配置文件。
- 显示保存 diff。
- 每次保存前自动写入配置历史快照。
- 查看历史快照 diff。
- 从历史快照恢复配置。
- 查看 agent JSON Lines 审计日志。
- 运行 `pullknock-agent --check-config`。
- 可选触发 reload command，默认 `systemctl reload pullknock-agent`。

## 安全边界

- 默认绑定 `127.0.0.1`。
- 默认只读，必须显式 `--allow-write` 才能保存。
- 默认不能 reload，必须显式 `--allow-reload` 才能触发。
- 支持内置 Bearer token、HTTP Basic auth，以及反向代理认证 header。
- 所有 POST 写接口要求 `Content-Type: application/json`、`X-PullKnock-CSRF` token，并校验 `Origin` 或 `Referer` 与 `Host` 同源。
- 即使启用内置认证，也不建议直接暴露公网；生产环境建议放在 SSH tunnel、WireGuard、mTLS 或可信反向代理认证之后。
- 只有当 admin 服务只监听反向代理内网地址，且反向代理会覆盖并清洗该 header 时，才允许启用 `--trusted-user-header`。不要把该模式直接暴露给客户端。
- Web UI 只是配置管理面，不参与 envelope 验签、nonce、防火墙授权执行。

## 审计日志

默认从 agent 配置 `audit.log_file` 读取日志。如果想覆盖路径：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --audit-log /var/log/pullknock/audit.log
```

界面会解析 JSON Lines，最近事件倒序显示。非 JSON 行会以 `unparsed_log_line` 展示，便于排查日志污染。

## 配置历史

默认历史目录：

```text
<agent.yaml 所在目录>/.pullknock-history
```

也可以指定：

```bash
pullknock-admin --config /etc/pullknock/agent.yaml --history-dir /var/lib/pullknock/config-history
```

每次保存或恢复前，当前配置都会先写入历史快照。恢复历史配置仍会先运行完整配置校验，且需要 `--allow-write`。

## 运维建议

- 不建议直接暴露到公网。
- 如果需要团队访问，优先通过反向代理做认证和 TLS。
- 配置文件仍建议 `600/root`，运行 admin 的用户必须明确具备读取或写入该文件的权限。
- 开启 `--allow-write` 前先准备配置备份或 Git 管理。
- Basic auth 参数会出现在进程参数中；更推荐短期本机使用，或使用 Bearer token 环境变量/反向代理认证。
