# 03-协议设计

## Payload v1

payload 是被签名的数据，必须使用 canonical JSON 序列化：

```python
json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

示例：

```json
{
  "version": 1,
  "type": "pullknock.open",
  "command_id": "0d7b73e2-8d4c-4d61-a0ad-0bb5a5403fc0",
  "principal": "jonhy",
  "target": "x162-43-32-23",
  "grant_id": "x162-ssh",
  "source_ip": "203.0.113.7",
  "requested_timeout": 60,
  "issued_at": 1783000000,
  "not_before": 1783000000,
  "expires_at": 1783000060,
  "reason": "temporary ssh access"
}
```

## 字段说明

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `version` | 是 | 协议版本，当前为 `1`。 |
| `type` | 是 | 固定为 `pullknock.open`。 |
| `command_id` | 是 | UUID，一次性 nonce。 |
| `principal` | 是 | 用户身份，必须存在于 agent `users`。 |
| `target` | 是 | 目标服务器 ID，必须等于 agent `server.id`。 |
| `grant_id` | 是 | 请求的授权项 ID，必须存在于 agent `grants`。 |
| `source_ip` | 是 | 需要临时放行的公网 IP。 |
| `requested_timeout` | 是 | 请求开放秒数，最终会被本地策略截断。 |
| `issued_at` | 是 | 签发 Unix 秒。 |
| `not_before` | 是 | 最早生效 Unix 秒。 |
| `expires_at` | 是 | 过期 Unix 秒。 |
| `reason` | 否 | 审计说明。 |

## Envelope v1

固定布告栏中保存 envelope，而不是裸 payload。

```json
{
  "envelope_version": 1,
  "encoding": "plain+sshsig",
  "payload_b64": "base64(canonical_payload_json)",
  "signature_b64": "base64(openssh_sshsig_file_content)",
  "kid": "jonhy",
  "created_at": 1783000000
}
```

## age 加密 Envelope v1

加密 envelope v1 是可选发布格式。启用 `defaults.age.envelope_version: 1` 后，CLI 会先生成普通 `plain+sshsig` envelope，再把整个 signed envelope JSON 交给 age 加密，最后发布外层 envelope：

```json
{
  "envelope_version": 1,
  "encoding": "age+plain+sshsig",
  "ciphertext_b64": "base64(age_ciphertext)",
  "kid": "jonhy",
  "created_at": 1783000000
}
```

## age 加密 Envelope v2

加密 envelope v2 是默认格式。它保留内层 `plain+sshsig` envelope 和 SSHSIG 安全边界，同时在外层显式声明内容类型、加密算法、加密 key 标识和内层 envelope 格式：

```json
{
  "envelope_version": 2,
  "content_type": "pullknock.envelope",
  "encoding": "age",
  "encryption_alg": "age-v1",
  "encryption_key_id": "x162-age-2026q3",
  "inner_envelope_version": 1,
  "inner_encoding": "plain+sshsig",
  "ciphertext_b64": "base64(age_ciphertext)",
  "kid": "jonhy",
  "created_at": 1783000000
}
```

`encryption_key_id` 是运维标识，不参与密钥派生，也不替代 age recipient。推荐命名为服务器或集群加轮换批次，例如 `x162-age-2026q3`。agent 仍然通过 `security.age.identity_files` 交给 age 自行选择可解密的 identity。

`kid` 只用于日志、路由或快速定位候选 key，不能作为授权身份。最终身份只认内层 payload 的 `principal`，并且必须通过该 principal 配置下的 OpenSSH public key 完成 SSHSIG 验签。明文 envelope 或解密后的内层 envelope 中，如果 `kid` 与 `payload.principal` 不一致，agent 会拒绝该 command。加密外层的 `kid` 仍是不可信元信息。

agent 处理流程：

```text
外层 envelope -> age 解密 -> plain+sshsig envelope -> SSHSIG 验签 -> 本地授权策略
```

这样可以隐藏 `principal`、`grant_id`、`source_ip`、`reason` 等元信息，同时不改变原有认证边界：授权仍然依赖 SSHSIG、公钥、nonce 和本地 grant。

## 签名

CLI 使用：

```bash
ssh-keygen -Y sign -f ~/.ssh/pullknock_ed25519_sk -n pullknock-v1 payload.json
```

Agent 使用 `users.<principal>.keys` 为当前 principal 构造临时 signer 内容，再调用：

```bash
ssh-keygen -Y verify -f <temp-signer-file> -I <principal> -n pullknock-v1 -s signature.sig
```

## 版本支持规则

- agent 只接受 canonical JSON payload。
- agent 接受明文 `envelope_version: 1` + `encoding: plain+sshsig`。
- 配置 `security.age` 后，agent 同时接受加密 v1 `encoding: age+plain+sshsig` 和加密 v2 `envelope_version: 2` + `encoding: age`。
- envelope v1 只允许 `envelope_version`、`encoding`、`payload_b64`、`signature_b64`、`kid`、`created_at` 字段。
- 加密 envelope v1 只允许 `envelope_version`、`encoding`、`ciphertext_b64`、`kid`、`created_at` 字段。
- 加密 envelope v2 只允许 `envelope_version`、`content_type`、`encoding`、`encryption_alg`、`encryption_key_id`、`inner_envelope_version`、`inner_encoding`、`ciphertext_b64`、`kid`、`created_at` 字段。
- 加密 envelope v2 当前支持 `content_type: pullknock.envelope`、`encryption_alg: age-v1`、`inner_envelope_version: 1`、`inner_encoding: plain+sshsig`。
- payload v1 只允许必填字段和可选 `reason` 字段，未知字段一律拒绝。
- `source_ip` 必须能被 `ipaddress.ip_address` 解析。
- `command_id` 必须是 UUID。
- 时间字段必须是整数 Unix 秒。
- JSON 不允许重复 key。
- `principal`、`target`、`grant_id`、`kid`、`encryption_key_id` 只能使用字母、数字、下划线、点、冒号、at 和连字符。
- envelope、payload、signature、reason 均有大小限制，避免异常大输入造成资源消耗。

## 注入防护规则

- payload 不存在 `cmd`、`port`、`protocol`、`zone` 等执行字段。
- v1 未知字段拒绝，避免协议字段被不支持该语义的实现误解释。
- 所有 JSON key 必须是字符串。
- 字符串字段拒绝 NUL、CR、LF 等控制字符。
- SQL nonce 操作全部使用参数化查询。
- 防火墙后端和 ssh-keygen 调用全部使用 subprocess 参数数组，禁止 shell。
- 防火墙后端的端口、协议、zone 或 nftables set 只来自本地配置，不来自 payload。

## age 密钥轮换

PullKnock 使用 age 的多 recipient / 多 identity 能力完成平滑轮换：

1. 在新 agent 上生成新 identity，并导出新 recipient。
2. agent `security.age.identity_files` 同时配置旧 identity 和新 identity。
3. CLI `defaults.age.recipients` 同时配置旧 recipient 和新 recipient，并把 `defaults.age.key_id` 更新为当前轮换批次。
4. 确认所有 agent 都能解密后，CLI 移除旧 recipient。
5. 确认不会再发布给旧 recipient 后，agent 移除旧 identity。
