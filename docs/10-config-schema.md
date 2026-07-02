# 10-配置 Schema
本文件由 `scripts/generate_config_schema_docs.py` 生成。修改 schema 说明时请更新脚本后重新生成。
通用类型：`safe-id` 只允许字母、数字、下划线、点、冒号、at 和连字符；字符串拒绝控制字符。
## CLI 配置

默认路径：`~/.config/pullknock/config.yaml`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `defaults.principal` | `string` | 客户端 principal，必须匹配 agent users 中的用户名。 |
| `defaults.signature_namespace` | `string` | SSHSIG namespace，默认 pullknock-v1。 |
| `defaults.private_key` | `path` | OpenSSH 私钥路径，支持 ~ 和环境变量。 |
| `defaults.command_ttl_seconds` | `integer` | signed command 有效秒数。 |
| `defaults.requested_timeout_seconds` | `integer` | 默认请求开放秒数。 |
| `defaults.ssh_keygen` | `string` | ssh-keygen 可执行文件名或路径。 |
| `defaults.age.enabled` | `boolean` | 是否启用 age envelope 加密。 |
| `defaults.age.age_cmd` | `string` | age 可执行文件路径或命令名。 |
| `defaults.age.envelope_version` | `enum` | 加密 envelope 外层版本：2 为默认值；1 用于发布 envelope v1 加密格式。 |
| `defaults.age.key_id` | `safe-id` | v2 加密 key 标识；defaults.age.envelope_version 为 2 时必填。 |
| `defaults.age.recipients` | `list[age-recipient]` | age recipient 列表，支持新旧 key 并行轮换。 |
| `defaults.age.recipient_files` | `list[path]` | age recipient 文件列表。 |
| `publishers.<name>.type` | `enum` | file、http_put、webdav_put、ftp_upload、ftps_upload、ipfs_http、s3_put。 |
| `publishers.<name>.path` | `path` | file publisher 写入路径。 |
| `publishers.<name>.url` | `url` | HTTP/WebDAV/FTP/FTPS 目标 URL，支持环境变量。 |
| `publishers.<name>.api_url` | `url` | ipfs_http 使用的 Kubo HTTP API URL。 |
| `publishers.<name>.ipns_key` | `string` | ipfs_http 可选 IPNS key 名称。 |
| `publishers.<name>.endpoint_url` | `url` | s3_put 使用的 S3 兼容 endpoint。 |
| `publishers.<name>.bucket` | `string` | s3_put bucket。 |
| `publishers.<name>.key` | `string` | s3_put object key。 |
| `publishers.<name>.region` | `string` | s3_put SigV4 region。 |
| `publishers.<name>.access_key_id` | `string` | s3_put access key，支持环境变量。 |
| `publishers.<name>.secret_access_key` | `string` | s3_put secret key，支持环境变量。 |
| `publishers.<name>.headers` | `map[string]string` | HTTP/WebDAV 附加请求头。 |
| `publishers.<name>.username` | `string` | WebDAV/FTP/FTPS 用户名，支持环境变量。 |
| `publishers.<name>.password` | `string` | WebDAV/FTP/FTPS 密码，支持环境变量。 |
| `publishers.<name>.timeout_seconds` | `integer` | 网络请求超时秒数。 |
| `publishers.<name>.create_collections` | `boolean` | WebDAV 是否尝试 MKCOL 创建父目录。 |
| `publishers.<name>.passive` | `boolean` | FTP/FTPS 是否启用被动模式。 |
| `publishers.<name>.create_dirs` | `boolean` | FTP/FTPS 是否尝试创建父目录。 |
| `targets.<name>.target` | `safe-id` | 目标服务器 ID，必须匹配 agent server.id。 |
| `targets.<name>.grant_id` | `safe-id` | 请求的 grant ID。 |
| `targets.<name>.publisher` | `safe-id` | 引用 publishers 中的名称。 |

## Agent 配置

默认路径：`/etc/pullknock/agent.yaml`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `server.id` | `safe-id` | 服务器唯一 ID，payload target 必须匹配。 |
| `server.control_url` | `url/path` | agent 拉取 envelope 的单一位置，支持环境变量。 |
| `server.control_urls` | `list[url/path]` | agent 拉取 envelope 的 fallback 列表，按顺序尝试。 |
| `server.poll_interval_seconds` | `integer` | 轮询基础间隔秒数。 |
| `server.poll_jitter_seconds` | `integer` | 轮询随机抖动秒数。 |
| `server.http_timeout_seconds` | `integer` | HTTP GET 超时秒数。 |
| `server.control_headers` | `map[string]string` | HTTP GET 附加 header。 |
| `audit.log_file` | `path` | 可选 JSON Lines 审计日志文件路径。 |
| `security.signature_namespace` | `safe-id` | SSHSIG namespace。 |
| `security.nonce_db` | `path` | SQLite nonce 防重放数据库。 |
| `security.max_clock_skew_seconds` | `integer` | 允许时钟偏差秒数。 |
| `security.max_command_ttl_seconds` | `integer` | payload 最大 TTL 秒数。 |
| `security.nonce_retention_seconds` | `integer` | nonce 记录保留秒数。 |
| `security.age.enabled` | `boolean` | 是否启用 age envelope 解密。 |
| `security.age.age_cmd` | `string` | age 可执行文件路径或命令名。 |
| `security.age.envelope_version` | `enum` | 配置对称字段；agent 启用 age 后同时接受 v1/v2 加密 envelope。 |
| `security.age.key_id` | `safe-id` | 可选 identity 批次标识，便于运维记录。 |
| `security.age.identity_files` | `list[path]` | age identity 私钥文件列表，支持新旧 key 并行轮换。 |
| `firewall.backend` | `enum` | firewalld 或 nftables。 |
| `firewall.firewall_cmd` | `absolute-path` | firewall-cmd 绝对路径。 |
| `firewall.default_zone` | `zone` | 默认 firewalld zone。 |
| `firewall.nft_cmd` | `absolute-path` | nftables 后端使用的 nft 可执行文件路径。 |
| `firewall.nft_family` | `safe-name` | nftables family，默认 inet。 |
| `firewall.nft_table` | `safe-name` | nftables table，默认 pullknock。 |
| `firewall.nft_set_prefix` | `safe-name` | nftables 动态 set 前缀。 |
| `firewall.nft_setup_sets` | `boolean` | 是否由 agent 尝试创建 table/set。 |
| `groups.<group>.enabled` | `boolean` | 是否启用用户组。 |
| `groups.<group>.display_name` | `string` | 用户组显示名。 |
| `groups.<group>.allowed_grants` | `list[safe-id]` | 用户组允许请求的 grant。 |
| `groups.<group>.max_timeout_seconds` | `integer` | 用户组级最大开放秒数。 |
| `groups.<group>.not_before` | `timestamp` | 用户组最早生效时间。 |
| `groups.<group>.expires_at` | `timestamp` | 用户组过期时间。 |
| `groups.<group>.allow_source_cidrs` | `list[cidr]` | 用户组允许的来源 CIDR。 |
| `users.<principal>.enabled` | `boolean` | 是否启用用户。 |
| `users.<principal>.display_name` | `string` | 用户显示名。 |
| `users.<principal>.groups` | `list[safe-id]` | 用户所属组。 |
| `users.<principal>.keys[].id` | `safe-id` | key 级标识，用于审计和设备级禁用。 |
| `users.<principal>.keys[].enabled` | `boolean` | 是否启用该 key。 |
| `users.<principal>.keys[].public_key` | `openssh-public-key` | 用于 SSHSIG 验签的 OpenSSH 公钥。 |
| `users.<principal>.keys[].not_before` | `timestamp` | key 最早生效时间。 |
| `users.<principal>.keys[].expires_at` | `timestamp` | key 过期时间。 |
| `users.<principal>.keys[].comment` | `string` | key 备注，例如设备名。 |
| `users.<principal>.allowed_grants` | `list[safe-id]` | 用户允许请求的 grant。 |
| `users.<principal>.max_timeout_seconds` | `integer` | 用户级最大开放秒数。 |
| `users.<principal>.not_before` | `timestamp` | 用户最早生效时间。 |
| `users.<principal>.expires_at` | `timestamp` | 用户过期时间。 |
| `users.<principal>.allow_source_cidrs` | `list[cidr]` | 用户允许的来源 CIDR。 |
| `grants.<grant_id>.description` | `string` | grant 描述。 |
| `grants.<grant_id>.inherits` | `list[safe-id]` | 继承的 grant ID 列表。 |
| `grants.<grant_id>.allowed_principals` | `list[safe-id]` | 允许使用 grant 的用户。 |
| `grants.<grant_id>.allowed_groups` | `list[safe-id]` | 允许使用 grant 的用户组。 |
| `grants.<grant_id>.merge_inherited_ports` | `boolean` | 继承 grant 时是否合并父子 ports。 |
| `grants.<grant_id>.ports[].protocol` | `enum` | tcp 或 udp。 |
| `grants.<grant_id>.ports[].port` | `integer` | 1..65535。 |
| `grants.<grant_id>.max_timeout_seconds` | `integer` | grant 最大开放秒数。 |
| `grants.<grant_id>.zone` | `zone` | firewalld zone。 |
| `grants.<grant_id>.allow_source_cidrs` | `list[cidr]` | grant 允许来源 CIDR。 |

## Publisher 服务配置

默认路径：`/etc/pullknock/publisher.yaml`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `server.host` | `string` | 监听地址。 |
| `server.port` | `integer` | 监听端口。 |
| `server.path` | `path` | PUT/GET envelope 路径。 |
| `server.health_path` | `path` | 健康检查路径。 |
| `server.max_body_bytes` | `integer` | 最大请求体字节数。 |
| `storage.mode` | `enum` | latest 或 queue；latest 保存单个 envelope，queue 支持 /commands/<target>/<command_id>.json。 |
| `storage.envelope_file` | `path` | 最新 envelope 落盘路径。 |
| `storage.queue_dir` | `path` | queue envelope 目录；默认在 envelope_file 同级 commands 目录。 |
| `auth.write_bearer_tokens` | `list[string]` | 允许 PUT 的 bearer token。 |
| `auth.require_auth_for_read` | `boolean` | GET 是否要求鉴权。 |
| `auth.read_bearer_tokens` | `list[string]` | 允许 GET 的 bearer token。 |

