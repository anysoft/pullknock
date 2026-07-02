# 09-路线图

## 短期（已完成）

- 增加更完整的 end-to-end 测试脚本：`scripts/e2e_file_mode.py`。
- 增加配置 schema 文档生成：`scripts/generate_config_schema_docs.py` 生成 [10-配置 Schema](./10-config-schema.md)。
- 增加 agent `--check-config`。
- 增加 publisher 请求日志结构化输出：每个 HTTP 响应输出 `publisher_request` JSON 日志。
- 增加包发布流程和版本策略：[11-发布流程与版本策略](./11-release.md)，并提供 `scripts/release_check.py`。

## 新短期候选（已完成）

- 增加 GitHub Actions CI：`.github/workflows/ci.yml`。
- 增加 PyPI Trusted Publishing workflow：`.github/workflows/publish.yml`。
- 增加 release notes 自动检查：`scripts/check_release_notes.py`，CI 和发布 workflow 都会执行。

## 下一批候选（已完成）

- 增加 GitHub Actions release notes 格式提示：`.github/workflows/release-notes.yml` 和 `scripts/check_release_notes.py`。
- 增加 TestPyPI 发布 workflow：`.github/workflows/testpypi.yml`。
- 增加依赖安全扫描：`.github/workflows/security.yml` 和 `scripts/security_scan.py`。

## 后续候选（已完成）

- 增加 Dependabot 配置：`.github/dependabot.yml`。
- 增加 pre-commit 配置：`.pre-commit-config.yaml`。
- 增加 GitHub release 自动生成草稿：`.github/workflows/release-draft.yml` 和 `scripts/extract_release_notes.py`。

## 新候选（已完成）

- 增加 GitHub release 自动附加构建产物：`.github/workflows/release-draft.yml` 会构建并上传 `dist/*`。
- 增加 Conventional Commits 或 PR title 检查：`.github/workflows/pr-title.yml` 和 `scripts/check_pr_title.py`。
- 增加 CodeQL 静态分析：`.github/workflows/codeql.yml`。

## 发布与供应链（已完成）

- 增加自动标签发布检查，确保 tag、版本号、CHANGELOG 版本一致：`scripts/check_release_tag.py`。
- 增加构建产物安装验证，在干净 venv 中安装 wheel 并运行 CLI smoke test：`scripts/verify_wheel_install.py`。
- 增加 CycloneDX SBOM 生成：`scripts/generate_sbom.py`，release draft 和 security workflow 会生成 `dist/*-sbom.cdx.json`。
- 增加 systemd hardening 验证脚本：`scripts/verify_systemd_hardening.py`。

## 中期（已完成）

- 支持多 control URL fallback：`server.control_urls`。
- 支持更多防火墙后端，例如 nftables：`firewall.backend: nftables`。
- 支持 grant 审计日志落文件和 logrotate 示例：`audit.log_file` 和 `systemd/pullknock-agent.logrotate`。
- 支持配置 reload：`SIGHUP` / `systemctl reload pullknock-agent`。
- 支持 publisher command queue endpoint，避免 latest envelope 并发覆盖。
- 支持 key 级用户公钥策略和 key 审计字段。
- 支持 Web admin 写接口 CSRF/Origin/JSON 防护。
- 明确并实现 firewalld duplicate grant refresh 语义。
- 明确 nftables 与 firewalld nft backend 共存风险和部署模式。

## 长期（已完成）

- 可选 Web 管理界面：`pullknock-admin`。
- 多服务器配置生成工具。
- IPFS/IPNS publisher backend。
- S3 兼容对象存储 publisher。
- age 加密密钥轮换。
- 更细粒度的用户组和 grant 继承。
- envelope v2 协议版本化加密，在保留当前 `age+plain+sshsig` 的基础上进一步规范密钥 ID 和算法协商。

## 长期候选

- agent status ack / CLI `--wait` 回执通道。
- TTL 与 poll interval、fallback timeout 的配置校验 warning。
- 验签成功但权限失败 command 的 rejected cache / backoff，降低重复日志噪音。
- 将 WebDAV、FTP/FTPS、IPFS/IPNS、S3、Web admin 等能力进一步拆成 optional extras。
- 远程集中管理、多 agent 状态汇总和策略审批流。

## 已知取舍

- latest publisher endpoint 仍只保存最新 envelope；需要并发可靠性时使用 queue endpoint。
- 当前 agent 单进程处理，避免 nonce 并发复杂性。
- 当前不做远程命令执行，避免扩大攻击面。
- 当前不把公钥放到独立 signer 文件，降低运维复杂度。
