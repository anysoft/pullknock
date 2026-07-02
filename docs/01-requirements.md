# 01-需求与范围

## 功能需求

### CLI

- 读取本地 YAML 配置。
- 根据 target 别名生成授权 payload。
- 支持显式 `--source-ip`。
- 未传 `--source-ip` 时查询公网 IP，并在多个 provider 返回不一致时失败。
- 使用 OpenSSH SSHSIG 对 canonical payload 签名。
- 生成 envelope v1。
- 支持 file publisher。
- 支持 HTTP PUT publisher。
- 支持 WebDAV publisher，含可选 Basic Auth。
- 支持 FTP/FTPS publisher，含匿名或账号密码认证。
- 支持 IPFS/IPNS publisher。
- 支持 S3 兼容对象存储 publisher。
- 支持 age 加密 envelope。
- 支持 dry-run 输出 envelope。
- 支持本地 Web 管理界面查看和编辑 agent 配置。

### Agent

- 读取服务器 YAML 配置。
- 支持 HTTP/HTTPS URL、FTP/FTPS URL、file URL 和本地路径拉取 envelope。
- 支持多个 control URL fallback。
- 解析 envelope v1。
- 支持 age 加密 envelope 解密。
- 校验 payload canonical JSON。
- 使用 `users.<principal>.keys` 验签。
- 校验 target、时间窗口、TTL、nonce、用户、grant、source IP。
- 调用 firewalld runtime rich rule 或 nftables timeout set。
- 支持 dry-run。
- 写 JSON 审计日志，支持落文件。
- 支持 SIGHUP 配置 reload。
- 使用 SQLite 保存已处理 command_id。

### Publisher 服务

- 提供固定 HTTP 路径保存 envelope。
- 支持 bearer token 写入鉴权。
- 支持可选读取鉴权。
- 支持健康检查。
- 原子落盘保存 envelope。
- 不参与授权信任判断。

## 非功能需求

- 安全优先，固定 URL 泄漏不应导致未授权访问。
- 配置可读，用户、公钥、有效期和权限集中在 agent YAML。
- 依赖尽量少，核心依赖为 `click`、`PyYAML`、`requests`。
- 外部命令调用禁止 `shell=True`。
- 防火墙参数必须来自本地 YAML，不来自远端 payload。
- 可离线运行测试，测试使用 Python 标准库 `unittest`。

## MVP 范围

本项目当前版本聚焦：

- 单 agent 轮询。
- 多 control URL fallback。
- OpenSSH SSHSIG。
- 明文 envelope 和 age 加密 envelope。
- 本地 YAML 权限管理。
- 用户组和 grant 继承。
- 多服务器配置生成工具。
- 本地 Web 管理界面。
- firewalld 和 nftables backend。
- SQLite nonce DB。

## 暂不实现

- 远程命令执行。
- 从 payload 读取端口、协议、zone。
- 用户数据库、OAuth、SSO。
- 多 agent 并发协调。
- 自动管理 SSHD 配置。
