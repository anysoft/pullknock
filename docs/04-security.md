# 04-安全设计

## 信任边界

可信：

- 客户端私钥或 YubiKey。
- agent 本地 YAML 配置。
- agent 本地 SQLite nonce DB。
- agent 机器上的 firewalld。
- agent 机器上的 nftables，如果选择 nftables 后端。

不可信：

- 固定 URL。
- publisher 服务。
- 对象存储。
- WebDAV。
- FTP/FTPS。
- IPFS gateway。
- S3 兼容对象存储。
- envelope 的可见性和可写性。

## 必须防御的攻击

| 攻击 | 防御 |
| --- | --- |
| URL 泄漏 | URL 不作为安全边界。 |
| envelope 被读取 | 没有私钥无法生成新授权。 |
| envelope 元信息泄漏 | 启用 age 后隐藏 payload 和 SSHSIG。 |
| 加密协议混淆 | envelope v2 显式声明 `content_type`、`encryption_alg`、`encryption_key_id` 和内层格式。 |
| envelope 被篡改 | SSHSIG 验签失败。 |
| 旧 envelope 重放 | SQLite nonce DB 拒绝重复 `command_id`。 |
| latest envelope 并发覆盖 | publisher queue endpoint 可按 target/command_id 保存多条命令。 |
| 用户请求未授权端口 | 端口只来自本地 grant。 |
| 用户请求超长 timeout | timeout 被 user/grant 上限截断。 |
| 用户伪造 target | `target` 必须等于 `server.id`。 |
| 用户伪造其他 principal | 签名必须匹配该 principal 的公钥。 |
| source_ip 注入 | 使用 `ipaddress` 解析，防火墙参数不经 shell。 |
| 命令注入 | payload 不支持命令字段，subprocess 禁止 `shell=True`。 |
| SQL 注入 | nonce DB 全部使用 SQLite 参数化查询。 |
| 协议混淆 | envelope/payload 未知字段一律拒绝。 |
| 资源消耗 | envelope、payload、signature、reason 设置大小上限。 |

## 权限模型

一次授权必须同时满足：

- payload `target == server.id`。
- payload `grant_id` 存在于 `grants`。
- payload `principal` 存在于 `users`。
- 用户 `enabled == true`。
- 用户有至少一个 `keys`。
- 命中的 key 必须 enabled 且在 key 级有效期内。
- SSHSIG 验签成功。
- 用户账号在有效期内。
- 用户或其启用用户组的 `allowed_grants` 包含本次 grant。
- grant `allowed_principals` 包含本次 principal，或 grant `allowed_groups` 包含用户所属启用组。
- `source_ip` 同时落在 user 和 grant 的 CIDR 白名单内。

## Timeout 策略

最终 timeout：

```text
min(payload.requested_timeout, user.max_timeout_seconds, group.max_timeout_seconds, grant.max_timeout_seconds)
```

这样客户端只能“请求”，不能决定最终开放时间。

## Nonce 防重放

SQLite 表 `used_nonces` 保存已成功执行的 command：

```sql
CREATE TABLE IF NOT EXISTS used_nonces (
    command_id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    processed_at INTEGER NOT NULL
);
```

只有防火墙后端执行成功后才写入 nonce DB。验签失败、权限失败、防火墙失败都不会写 nonce。

## Publisher 服务安全边界

`pullknock-publisher` 只负责保存 envelope：

- 写入可用 bearer token 限制。
- 读取可公开，也可用 bearer token 限制。
- 读取鉴权不是核心安全边界。
- latest endpoint 只保存最新 envelope；queue endpoint 可避免多用户并发覆盖。
- 对加密 envelope 只做外层浅校验，不解密、不解析 payload。
- 即使 publisher 被读取或覆盖，攻击者仍不能绕过 agent 验签和本地授权策略。

## 密钥管理建议

- 优先使用 YubiKey/FIDO2 security key。
- 临时用户设置 `expires_at`。
- 用户离职或临时授权结束后，删除对应 `users.<principal>` 或设为 `enabled: false`。
- 每个用户独立 key，不共享私钥。
- 多设备用户优先使用 `users.<principal>.keys`，为每个设备配置独立 `id`、`enabled`、`expires_at` 和备注。
- age 加密建议使用 envelope v2，并用 `defaults.age.key_id` 标记 recipient 轮换批次。
- age key 轮换使用多 recipient：先同时发布给新旧 recipient，再移除旧 recipient。
- agent 配置文件权限建议 `600/root`。

## 输入加固清单

- `principal`、`target`、`grant_id`、`kid` 和 key id 使用安全 ID 字符集。
- `kid` 不能作为授权身份，解密后内层 `kid` 必须匹配 payload `principal`。
- 配置中的 firewalld zone 和 nftables family/table/set 前缀使用安全字符集。
- `firewall_cmd` 必须是绝对路径。
- `nft_cmd` 必须是绝对路径。
- WebDAV URL 只允许 `http://` 或 `https://`。
- FTP/FTPS 路径、用户名、密码拒绝控制字符。
- agent `control_url`/`control_urls` 支持环境变量展开，但展开后仍会检查控制字符。
- S3 access key 支持环境变量展开，SigV4 Authorization header 运行时生成。
- age recipient 必须是 `age1...` 字符串，identity 文件路径拒绝控制字符。
- envelope v2 的 `encryption_key_id` 使用安全 ID 字符集，只作为审计和运维标识。
