# Changelog

所有重要变更都会记录在这里。版本遵循 `docs/11-release.md` 中的版本策略。
## v0.1.1
- workflow

## v0.1.0

### Added

- 初始 PullKnock CLI、agent 和 publisher 服务。
- OpenSSH SSHSIG 签名和 `users.<principal>.keys` 验签。
- file、HTTP PUT、WebDAV、FTP、FTPS publisher。
- HTTP/HTTPS、FTP/FTPS 和 file control URL 拉取。
- SQLite nonce 防重放。
- firewalld runtime rich rule dry-run 和执行。
- 中文 README、示例配置、设计文档和配置 schema 文档。
- 本地 release check、E2E file-mode dry-run、GitHub Actions CI 和 PyPI Trusted Publishing workflow。
- GitHub draft release 自动生成，并附加构建后的 sdist/wheel。
- Dependabot、pre-commit、PR title 检查、CodeQL 和依赖安全扫描 workflow。
- agent 多 control URL fallback。
- nftables 防火墙后端，使用带 timeout 的动态 set。
- agent `audit.log_file`、logrotate 示例和 SIGHUP 配置 reload。
- 本地 Web 管理界面 `pullknock-admin`，支持查看、校验、编辑、保存和 reload agent 配置。
- Web 管理界面认证集成、审计日志查看和配置历史。
- envelope v2 age 加密外层格式，显式声明 `encryption_key_id`、`encryption_alg` 和内层 envelope 格式。
- 发布 tag/版本/CHANGELOG 一致性检查、wheel 干净安装 smoke、CycloneDX SBOM 生成和 systemd hardening 验证脚本。
- publisher command queue endpoint 和 agent queue index 消费，降低 latest envelope 并发覆盖风险。
- 用户 key 级策略，支持 key id、enabled、有效期和审计 fingerprint。

### Changed

- 用户公钥统一放在 agent `users.<principal>.keys`，每把 key 都有独立 id、开关、有效期和审计信息。
- CLI 默认发布 envelope v2 加密格式；显式设置 `defaults.age.envelope_version: 1` 可发布 v1 加密格式。
- 将 Python 包 license 元数据更新为 SPDX 字符串写法，避免新版 setuptools 废弃警告。
- agent 防火墙调用改为后端工厂，保留 firewalld 行为并新增 nftables。
- 新增专用 Web 管理面，默认本机只读运行，写入和 reload 需要显式开启。
- Web 管理面支持 Basic/Bearer/反代 header 认证，保存前自动创建配置历史快照。
- CI、release draft、PyPI/TestPyPI 和 security workflow 接入发布供应链检查与 SBOM 产物。
- firewalld 重复授权改为先移除同 rich rule 再添加 timeout，以刷新有效期。

### Fixed

- 加强 envelope、payload、配置、URL 和 FTP 路径校验。
- 明确并修正文档中 publisher 对加密 envelope 的职责分层：只做外层浅校验，不解密、不验签。
- 明确 nftables 与 firewalld nft backend 共存风险。

### Security

- 拒绝 envelope/payload 未知字段，防止协议混淆。
- publisher 服务写入时同时校验明文 v1、加密 v1 和加密 v2 envelope 外层结构。
- agent 拒绝内层 envelope `kid` 与 payload `principal` 不一致的 command。
- Web admin 写接口增加 CSRF token、Origin/Referer 和 JSON Content-Type 校验。
- 拒绝 payload 中的执行语义字段，例如 `cmd`。
- 所有 SQLite 操作使用参数化查询。
- 所有外部命令使用 `subprocess.run([...])` 参数数组，禁止 shell。

### Migration

- 当前版本尚无已部署实例迁移要求；用户公钥统一使用 `users.<principal>.keys`。
