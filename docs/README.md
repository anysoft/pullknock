# PullKnock 设计文档索引

本目录保存 PullKnock 的项目级设计文档。README 面向快速上手；本目录面向设计评审、实现维护、部署交接和安全审计。

## 文档清单

- [00-项目总览](./00-overview.md)：项目目标、边界、组件和核心流程。
- [01-需求与范围](./01-requirements.md)：功能需求、非功能需求、MVP 范围和暂不实现内容。
- [02-系统架构](./02-architecture.md)：组件关系、数据流、模块职责和失败模式。
- [03-协议设计](./03-protocol.md)：payload、canonical JSON、envelope、签名和时效规则。
- [04-安全设计](./04-security.md)：信任边界、攻击面、防护策略和安全决策。
- [05-配置模型](./05-configuration.md)：CLI、agent、publisher 配置结构和字段说明。
- [06-Publisher 服务设计](./06-publisher-service.md)：内置布告栏服务的 API、鉴权、存储和部署边界。
- [07-部署与运维](./07-deployment-operations.md)：安装、systemd、防火墙后端、日志、备份和排障。
- [08-测试计划](./08-test-plan.md)：单元测试、集成测试、安全测试和手工验收。
- [09-路线图](./09-roadmap.md)：后续演进方向和已知取舍。
- [10-配置 Schema](./10-config-schema.md)：由脚本生成的配置字段清单。
- [11-发布流程与版本策略](./11-release.md)：PyPI 发布、版本号和发布前检查。
- [12-Web 管理界面](./12-web-admin.md)：本地 Web 管理面、安全边界、功能和部署建议。

## 设计原则

- 控制 URL 是不可信布告栏，不是安全边界。
- 服务端本地 YAML 是授权事实源。
- 用户、公钥、有效期和权限放在同一份 agent 配置里。
- 远端 payload 只能声明 `grant_id`，不能携带端口、协议、zone 或命令。
- 所有外部命令调用都必须使用参数数组，禁止 `shell=True`。
- 所有临时开放必须依赖防火墙后端自己的超时能力，例如 firewalld `--timeout` 或 nftables set `timeout`。
