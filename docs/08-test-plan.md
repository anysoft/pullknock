# 08-测试计划

## 自动化测试

当前测试使用 Python 标准库 `unittest`：

```bash
python3 -m compileall pullknock tests
python3 -m unittest discover -s tests
```

覆盖范围：

- canonical JSON 校验。
- envelope 解析。
- age 加密 envelope v1/v2 解析和 age 命令封装。
- 用户和 grant 权限判断。
- 用户组和 grant 继承。
- 时间窗口和 TTL 判断。
- firewalld dry-run 命令构造。
- nftables dry-run 命令构造。
- 多 control URL fallback。
- SQLite nonce 防重放。
- publisher 服务 PUT/GET 和鉴权。
- publisher queue endpoint 多 command 不覆盖。
- agent queue index URL 解析。
- WebDAV publisher 请求构造。
- FTP/FTPS publisher 上传流程。
- IPFS/IPNS publisher 请求构造。
- S3 SigV4 PUT publisher 请求构造。
- FTP fetcher 拉取流程。
- agent 配置内联用户公钥加载。
- agent key-level policy 加载、禁用和过期过滤。
- envelope/payload 未知字段拒绝。
- envelope `kid` 与 payload `principal` 不一致时拒绝。
- envelope v2 key_id、算法、内容类型和内层格式校验。
- payload 中 `cmd` 等执行语义字段拒绝。
- 非法 ID、超长 reason、超大 envelope 拒绝。
- 配置中的非法 firewalld zone 拒绝。
- agent 配置 `control_urls`、`audit.log_file` 和 nftables 字段解析。
- agent 配置 `groups`、grant `inherits` 和 `security.age` 字段解析。
- 多服务器配置生成器输出 agent/CLI 配置。
- Web 管理界面配置校验、只读保护和保存路径。
- Web 管理界面 CSRF token、Origin/Referer 和 JSON Content-Type 防护。
- firewalld 重复授权刷新 timeout 命令构造。
- WebDAV 非 HTTP URL 和 FTP 控制字符路径拒绝。
- 发布 tag、版本号和 CHANGELOG 一致性检查。
- wheel 干净 venv 安装和 CLI smoke test。
- CycloneDX SBOM 生成。
- systemd unit hardening 静态检查。

## SSHSIG 烟测

使用临时 ed25519 key：

1. 生成 key。
2. 构造 payload。
3. `ssh-keygen -Y sign` 签名。
4. 将 `.pub` 内容放入 `users.<principal>.keys[].public_key`。
5. 调用 agent 验签路径。

预期结果：验签成功。

## 本地 file 集成测试

1. 修改 `examples/agent.yaml` 中用户公钥。
2. 修改 `examples/cli-config.yaml` 中私钥路径。
3. 执行：

```bash
pullknock open x162 --config examples/cli-config.yaml --source-ip 203.0.113.7
pullknock-agent --config examples/agent.yaml --dry-run --once
```

预期结果：输出 `firewall-cmd` rich rule 命令。

## Publisher 集成测试

1. 启动 publisher：

```bash
export PULLKNOCK_UPLOAD_TOKEN=test-token
pullknock-publisher --config examples/publisher.yaml
```

2. CLI 使用 HTTP PUT publisher。
3. agent `control_url` 或 `control_urls` 指向 publisher URL。
4. agent dry-run 拉取。

预期结果：publisher 返回 stored，agent 成功解析并输出防火墙后端命令。

## 安全测试

必须覆盖：

- 修改 payload 后验签失败。
- 重放同一 command_id 被拒绝。
- 过期 command 被拒绝。
- target 不匹配被拒绝。
- principal 不存在被拒绝。
- 用户 disabled 被拒绝。
- 用户过期被拒绝。
- grant 不存在被拒绝。
- principal 不在 grant allowed_principals 被拒绝。
- source_ip 非法格式被拒绝。
- source_ip 不在 CIDR 白名单被拒绝。
- requested_timeout 超过上限时被截断。

## firewalld 手工验收

在测试服务器上：

1. 确认 SSH 默认不可从测试公网 IP 访问。
2. 执行 `pullknock open`。
3. 等待 agent 处理。
4. 查看 runtime rich rule。
5. 从 source IP 连接 SSH。
6. timeout 到期后确认规则消失。

## nftables 手工验收

在测试服务器上：

1. 配置 `firewall.backend: nftables`。
2. 准备引用 `pullknock_tcp_22_ipv4` 的 nftables input 规则。
3. 执行 `pullknock open`。
4. 查看 `sudo nft list set inet pullknock pullknock_tcp_22_ipv4`。
5. 从 source IP 连接 SSH。
6. timeout 到期后确认 set element 消失。
