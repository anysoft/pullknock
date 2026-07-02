# 11-发布流程与版本策略

## 版本策略

PullKnock 使用 SemVer 风格版本号：

- `MAJOR`：破坏性协议、配置或 CLI 行为变更。
- `MINOR`：向后兼容的新功能。
- `PATCH`：bugfix、安全加固、文档和测试改进。

在 `0.x` 阶段：

- `0.MINOR.0` 可以包含较大的配置或协议调整，但必须在 release notes 中明确迁移步骤。
- `0.MINOR.PATCH` 只做兼容修复。

版本号维护位置：

- `pyproject.toml` 的 `[project].version`
- `pullknock/__init__.py` 的 `__version__`

发布前必须保持两处一致。

## 发布前检查

```bash
python3 -m pip install -e ".[release]"
python3 scripts/release_check.py
```

该脚本会执行：

- tag、版本号和 CHANGELOG 一致性检查。
- release notes 检查。
- systemd hardening 静态检查。
- 重新生成配置 schema 文档。
- Python 编译检查。
- 单元测试。
- file publisher end-to-end dry-run。
- 构建 sdist/wheel。
- `twine check` 包元数据检查。
- 在干净 venv 中安装 wheel 并运行 CLI smoke test。
- 生成 CycloneDX SBOM。

单独检查 release notes：

```bash
python3 scripts/check_release_notes.py
```

单独检查 release tag、wheel 安装、SBOM 和 systemd hardening：

```bash
python3 scripts/check_release_tag.py --tag v<version> --require-tag
python3 -m build
python3 scripts/verify_wheel_install.py
python3 scripts/generate_sbom.py
python3 scripts/verify_systemd_hardening.py
```

## 构建包

建议在干净工作区执行：

```bash
python3 -m pip install -e ".[release]"
python3 -m build
python3 -m twine check dist/*
```

构建产物：

```text
dist/pullknock-<version>.tar.gz
dist/pullknock-<version>-py3-none-any.whl
dist/pullknock-<version>-sbom.cdx.json
```

## TestPyPI 验证

仓库提供 TestPyPI Trusted Publishing workflow：

```text
.github/workflows/testpypi.yml
```

该 workflow 需要在 GitHub Actions 手动触发，并且必须从 `v*` tag 运行。PyPI/TestPyPI 需要配置 trusted publisher：

- Repository owner/name：对应 GitHub 仓库。
- Workflow filename：`testpypi.yml`。
- Environment name：`testpypi`。

也可以手工验证：

```bash
python3 -m twine upload --repository testpypi dist/*
python3 -m venv /tmp/pullknock-testpypi
. /tmp/pullknock-testpypi/bin/activate
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple pullknock==<version>
pullknock --help
pullknock-agent --help
pullknock-publisher --help
```

## PyPI Trusted Publishing

仓库提供 GitHub Actions workflow：

```text
.github/workflows/publish.yml
```

该 workflow 在 GitHub Release 发布时触发，使用 PyPI Trusted Publishing 的 OIDC 流程发布，不需要在 GitHub Secrets 中保存 PyPI API token。

PyPI 项目需要配置 trusted publisher：

- Repository owner/name：对应 GitHub 仓库。
- Workflow filename：`publish.yml`。
- Environment name：`pypi`。

发布前 workflow 会执行：

- `scripts/check_release_tag.py`
- `scripts/check_release_notes.py`
- `scripts/release_check.py`
- `python -m build`
- `python -m twine check dist/*`
- `scripts/verify_wheel_install.py`
- `scripts/generate_sbom.py`

## 手工 PyPI 发布

```bash
python3 -m twine upload dist/*
```

手工发布仅作为备用路径。不要把 token 写进仓库、shell 历史或配置示例。

## Git 标签

发布成功后：

```bash
git tag -a v<version> -m "PullKnock v<version>"
git push origin v<version>
```

## GitHub Release 草稿

仓库提供自动生成草稿的 workflow：

```text
.github/workflows/release-draft.yml
```

触发方式：

- push `v*` tag。
- 手动触发 workflow，并输入 tag。

workflow 会：

- 使用 `scripts/check_release_tag.py` 检查 tag、版本号和 CHANGELOG 一致。
- 运行 `scripts/check_release_notes.py`。
- 使用 `scripts/extract_release_notes.py` 从 `CHANGELOG.md` 提取当前版本说明。
- 使用 `python -m build` 构建 sdist 和 wheel。
- 使用 `python -m twine check dist/*` 检查包元数据。
- 在干净 venv 中安装 wheel 并运行 CLI smoke test。
- 生成 CycloneDX SBOM。
- 创建或更新 GitHub draft release，并把 `dist/*` 附加为 release assets。

`0.x` 版本会自动标记为 prerelease。

## Release Notes 模板

`scripts/check_release_notes.py` 会检查当前版本是否存在以下结构，并在失败时输出格式提示：

```markdown
## v<version>

### Added

### Changed

### Fixed

### Security

### Migration
```

## 依赖安全扫描

本地运行：

```bash
python3 -m pip install -e ".[security]"
python3 scripts/security_scan.py
```

GitHub Actions workflow：

```text
.github/workflows/security.yml
```

该 workflow 会在 PR、主分支 push 和每周定时任务中运行 `pip-audit`。
同时会生成 CycloneDX SBOM 并作为 workflow artifact 上传。

## Dependabot

仓库提供：

```text
.github/dependabot.yml
```

Dependabot 每周检查：

- GitHub Actions。
- Python 运行依赖。
- 发布、安全和开发工具依赖。

## pre-commit

安装：

```bash
python3 -m pip install -e ".[dev]"
pre-commit install
```

手动运行全部钩子：

```bash
pre-commit run --all-files
```

当前钩子覆盖：

- YAML/TOML/JSON 基础检查。
- 行尾、末尾空行、大文件、冲突标记、私钥泄漏检查。
- release notes 检查。
- PR title 检查脚本示例运行。
- 配置 schema 文档生成。
- Python compileall。

## PR 标题规范

仓库提供 PR title 检查 workflow：

```text
.github/workflows/pr-title.yml
```

PR 标题采用 Conventional Commits 风格：

```text
feat(agent): add nftables backend
fix(protocol): reject malformed source IP
docs: update deployment guide
```

允许的 type：

```text
build, chore, ci, docs, feat, fix, perf, refactor, release, revert, security, test
```

本地调试：

```bash
python3 scripts/check_pr_title.py "feat(agent): add nftables backend"
```

## CodeQL

仓库提供 CodeQL workflow：

```text
.github/workflows/codeql.yml
```

该 workflow 在 PR、主分支 push 和每周定时任务中运行 Python CodeQL 分析，并启用 `security-extended`、`security-and-quality` 查询集。

## systemd hardening 检查

仓库提供：

```bash
python3 scripts/verify_systemd_hardening.py
```

该脚本静态检查 `systemd/pullknock-agent.service` 和 `systemd/pullknock-publisher.service` 的关键隔离配置，例如 `NoNewPrivileges`、`PrivateTmp`、`ProtectHome`、`ProtectSystem`、最小 capability 和可写路径。
