# 06-Publisher 服务设计

## 目标

`pullknock-publisher` 用于提供一个最小可部署的 envelope 布告栏，减少对对象存储或第三方服务的依赖。

它不是授权服务，不保存用户权限，不验签，不调用防火墙后端。

## HTTP API

### PUT envelope

```http
PUT /pullknock-command.json
Authorization: Bearer <token>
Content-Type: application/json
```

行为：

- 检查 bearer token。
- 检查 `Content-Length`。
- 限制最大 body。
- 对 envelope 做外层格式校验。
- 明文 `plain+sshsig` envelope 可做 payload 结构浅校验。
- 加密 envelope 只校验外层字段、大小和 base64，不解密、不验签、不解析 payload。
- 原子写入 `storage.envelope_file`。

成功响应：

```json
{
  "stored": true,
  "path": "/pullknock-command.json",
  "bytes": 1024
}
```

### GET envelope

```http
GET /pullknock-command.json
```

行为：

- 如果 `require_auth_for_read` 为 true，则检查读取 token。
- 如果还没有 envelope，返回 404。
- 返回最新 envelope JSON。
- 设置 `Cache-Control: no-store`。

### GET health

```http
GET /healthz
```

响应：

```json
{"ok": true}
```

### Queue mode

latest 模式只保存最新 envelope，适合单人或低并发场景。多用户并发时，后写入的 envelope 会覆盖前一个还没被 agent 拉取的 envelope。需要避免覆盖时，使用 command queue endpoint：

```http
PUT /commands/<target>/<command_id>.json
Authorization: Bearer <token>
Content-Type: application/json
```

agent 读取队列索引：

```http
GET /commands/<target>/index.json
```

响应示例：

```json
{
  "queue_version": 1,
  "target": "x162",
  "commands": [
    {
      "command_id": "0d7b73e2-8d4c-4d61-a0ad-0bb5a5403fc0",
      "url": "/commands/x162/0d7b73e2-8d4c-4d61-a0ad-0bb5a5403fc0.json",
      "size": 512,
      "mtime": 1783000000
    }
  ]
}
```

CLI 的 `http_put.url` 可使用 `{target}`、`{grant_id}`、`{command_id}`、`{principal}` 占位符：

```yaml
publishers:
  queue:
    type: "http_put"
    url: "https://publisher.example.com/commands/{target}/{command_id}.json"
```

agent 的 `server.control_url` 指向 index：

```yaml
server:
  control_url: "https://publisher.example.com/commands/x162/index.json"
```

## 鉴权模型

- 写入必须提供 `auth.write_bearer_tokens` 之一。
- 读取默认公开，因为读取 envelope 不应破坏安全边界。
- 如果需要降低元信息暴露，可启用 `require_auth_for_read`。

## 存储模型

- latest endpoint 保存最新 envelope。
- queue endpoint 按 `<target>/<command_id>.json` 保存多个 envelope。
- 写入使用临时文件加 `os.replace` 原子替换。
- 文件权限尽量设置为 `600`。
- queue 模式不要求 agent 删除远端文件；过期和已处理 command 由 agent 本地时间窗和 nonce DB 拒绝。

## 推荐部署

```text
Internet
  -> HTTPS reverse proxy
  -> 127.0.0.1:8080 pullknock-publisher
```

反向代理负责：

- TLS。
- 域名。
- 访问日志。
- 额外限流。

publisher 负责：

- bearer token。
- envelope 格式检查。
- 本地落盘。

## 与其他布告栏方案对比

| 方案 | 优点 | 缺点 |
| --- | --- | --- |
| pullknock-publisher | 可控、简单、延迟低 | 需要一台机器运行服务 |
| 对象存储 | 托管、高可用 | 配置 PUT 权限和缓存策略较麻烦 |
| WebDAV | 免费网盘和自建服务支持较多 | 不同服务对 MKCOL、覆盖写行为支持不完全一致 |
| FTP/FTPS | 可用匿名或廉价空间多 | FTP 明文传输，FTPS 兼容性取决于服务端 |
| 静态文件服务 | 简单 | 写入链路需要另配 |
| IPFS/IPNS | 分布式 | 固定地址、传播延迟和缓存不适合短 TTL |
