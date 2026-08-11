# 企业十量 V3 自动采集连接器

`connector-service` 是独立进程，不导入 `agent`、`platform` 或 `edge-agent` 的任何
代码。它只使用版本化 HTTP 接口，把企业只读数据转换成十量 V3 月度来源快照，交给
企业 Agent 生成待复核草稿。

它不会确认、签名或提交报表。企业经办人仍需在 Agent 前端核对，监管平台也不会信任连接器自行生成的结论。

## 已实现能力

- `file-drop`：只读扫描 JSON/CSV，连续两次确认 `size + mtime` 稳定，使用 `O_NOFOLLOW` 和文件描述符复核，绝不移动或删除来源文件。
- `http-poll`：只发 GET；主机和端口显式 allowlist、DNS 解析后固定 IP、SSRF/云元数据地址防护、拒绝重定向、响应大小和超时上限。
- `sqlite-query`：以 `mode=ro` 打开，启用 `query_only`、SQLite authorizer 和查询 deadline，只允许单条 `SELECT`/只读 `WITH`。
- 异构字段映射：pipeline 提供默认值，每个 source 可分别覆盖 `timestamp_field`、`period_type`、`scope_field/scope_values`、`mapping` 和 `shifts`；不要假设 ERP、MES、火工品台账的列名和班次编码相同。
- 月度 V3：每个来源按月形成完整 `days`、日报、零点班、八点班、四点班结构。日报
  明确携带全部 11 个原子字段；来源没有的字段保持 `null + missing`，不以 0、历史值
  或模型结果补齐。三个班次必须携带前 7 个生产运行原子项；销售、运输、入洗、开票
  四项若该来源声明了对应班次映射但本期缺数则为 `null + missing`，未声明该班次口径则
  保持稳定单元格并标记 `null + not_applicable`，不会制造虚假缺报。
- 日期覆盖：先按企业时区计算“本地今日减 `reporting_lag_days`”的应报截止日；截止日所在月从月初补到截止日，更早月份补到月末，跨月时不会提前声明未来覆盖。整日缺报仍形成 44 个稳定单元格，并按上述班次适用性分别标记 `missing` 或 `not_applicable`。没有独立受控状态字段时，运行状态保持 `unknown`，不能仅凭产量推断停产。
- 多来源：同一 `(client_id, draft_key, source_id)` 由 Agent 保存最新来源快照并重算；不同来源非空值冲突时 Agent 阻断，绝不后写覆盖。
- 完整代次：所有 `required_sources` 的最新修订到齐后，最后一个事件才设置 `trigger_workflow=true`；来源修订后组合摘要变化可再次体检。
- 采集健康：每个 source/月度草稿持久记录 `success_nonempty/success_empty/error/stability_wait`，按状态变化或有界心跳投递。必需来源空、错误、过期，或 health 未绑定 Agent 当前已完成 contribution 时，不触发就绪预检。
- 耐久幂等：SQLite 保存队列、来源单调修订和重试状态。连续相同内容去重，`A→B→A` 被识别为三个修订；重启不丢队列。
- 安全投递：每次 HTTP attempt 使用新的 `request_id`/时间戳，稳定 `event_id` 承担业务幂等。即使 Agent 已落库但响应丢失，重试也不会重复导入。只有版本、状态和回显 `event_id` 均匹配的 JSON 成功合同才会出队；网关误回的 2xx HTML 或错事件响应会安全重试。

## 数据流

```text
ERP/MES/地磅/台账（只读）
        │
        ▼
connector-service ── 十量映射、显式缺失、来源修订、耐久双 outbox
        │  HMAC POST /api/v1/machine/source-health + /api/v1/machine/autofill
        ▼
企业 Agent ── 多来源合并/冲突阻断/草稿修订/只读预检
        │
        ▼
企业经办人核对 ── 十量 V3 草稿（人工确认后才可进入正式报送）
```

## 快速安装

需要 Python 3.11 或更高版本，运行时没有第三方依赖。

```bash
cd /home/sevan/coral/connector-service
python -m venv .venv
.venv/bin/pip install .
.venv/bin/enterprise-connector --version
```

生成至少 32 字节的独立随机密钥，分别注入两个进程。不要把真实密钥写进 TOML、Git 或命令历史。

```bash
export ENTERPRISE_CONNECTOR_HMAC_SECRET='replace-with-a-random-secret-of-at-least-32-bytes'

# Agent 进程使用相同密钥建立最小权限 allowlist：
export ENTERPRISE_AGENT_CONNECTOR_CLIENTS_JSON='[
  {"client_id":"mine-qy-001-connector","secret":"replace-with-a-random-secret-of-at-least-32-bytes","permissions":["autofill"],"allowed_sources":{"blasting-file":{"source_system":"blasting-ledger","required":true,"freshness_max_seconds":3600},"production-http":{"source_system":"production-mes","required":true,"freshness_max_seconds":3600},"energy-sqlite":{"source_system":"energy-sqlite","required":true,"freshness_max_seconds":3600},"business-sqlite":{"source_system":"business-sqlite","required":true,"freshness_max_seconds":3600}}}
]'
```

严格是“一矿一 connector 一个十量 pipeline”。`enterprise_id` 必须精确等于 Agent 的
`ENTERPRISE_OPERATOR_ID`。`report_type = "five-quantity"` 是为兼容既有 Agent
`draft_key` 保留的稳定路由名，不表示仍在生成 V2。实际来源内容会明确声明
`contract_version = "ten-quantity-submission-v3"`。`allowed_sources` 要把每个固定
`source_id` 绑定到 `source_system`，并与 connector 的
`required_sources/max_staleness_seconds` 逐项一致；不支持通配。多个上游系统都放在
这一 pipeline 的 `sources` 下。

密钥环境变量必须在两个服务启动前配置。修改后要重启对应服务；正在运行的进程不会重新读取父 shell 的环境变量。

验证并运行：

```bash
enterprise-connector validate --config /etc/enterprise-connector/config.toml
enterprise-connector run --config /etc/enterprise-connector/config.toml --once
enterprise-connector run --config /etc/enterprise-connector/config.toml
enterprise-connector status --config /etc/enterprise-connector/config.toml
enterprise-connector check --config /etc/enterprise-connector/config.toml
```

`validate` 会输出 `data_contract/atomic_metrics/mapping_coverage`。覆盖结果分别列出
`daily_total` 的 11 项必填覆盖，以及每个班次前 7 项必填和后 4 项可选覆盖；显式
`zero_shift.production_t` 不会被误算成日报覆盖。为兼容旧脚本，顶层 `mapped_metrics` /
`unmapped_metrics` 继续保留，但其含义明确限定为日报覆盖。若仍是六字段旧来源，命令可以
通过，但日报 `unmapped_metrics` 和 `warnings` 会列出五个缺口；运行时日报对应单元格只会
是 `null + missing`，未配置的商业班次单元格是 `null + not_applicable`。机器读取方可用
`mapping_coverage_version = 2` 识别这一 scope-aware 输出，并按
`mapping_coverage_compatibility` 解释两个兼容字段。

终端持续占用代表守护进程正在轮询，不是卡死。生产建议使用 [systemd 样例](deploy/systemd/enterprise-connector.service) 或 [Dockerfile](deploy/docker/Dockerfile)。

## 可运行演示（三种适配器）

演示配置同时使用文件投递、HTTP GET 和 SQLite 只读视图，四个来源故意使用不同的时间列、班次编码和业务字段，以验证 source 级映射。

```bash
cd /home/sevan/coral/connector-service
python examples/init_demo_db.py
python examples/mock_production_api.py --port 18092
```

另一个终端启动已经配置机器连接器 allowlist 的企业 Agent，然后运行：

```bash
export ENTERPRISE_CONNECTOR_HMAC_SECRET='replace-with-a-random-secret-of-at-least-32-bytes'
enterprise-connector validate --config examples/config.toml
enterprise-connector run --config examples/config.toml
```

文件来源默认要求稳定 2 秒，所以演示应运行常驻命令，或间隔两秒执行两次 `--once`。
演示覆盖全部 11 个原子字段：火工品/人员文件、生产与开采 HTTP、能耗与通风
SQLite、销售/外运/入洗/普通发票 SQLite。它只创建 Agent 草稿，不代替人工确认。

## 配置口径

完整样例见 [examples/config.toml](examples/config.toml)。关键字段如下：

| 配置 | 作用 |
|---|---|
| `enterprise_id + report_type` | 唯一确定该 pipeline 的月度 `draft_key`；配置禁止重复组合 |
| `timestamp_field` | ISO 8601、日期或 Unix 秒字段；无时区值按 pipeline 时区解释 |
| `scope_field` | 原始日报/班次字段；通过 `scope_values` 对齐日报和三个班次 scope |
| `sources.timestamp_field/scope_field/mapping/shifts` | 可选 source 级覆盖；未配时继承 pipeline 默认值 |
| `reporting_lag_days` | 应报截止日相对企业本地当天的延迟天数；跨月时目标月份和快照窗口都随该截止日切换，快照记录参数和 as-of 日期 |
| `mapping` | 目标只能是 11 个十量 V3 原子字段，或 `daily_total.production_t` 等显式单元格；TOML 中带点的目标键需加引号 |
| `required_sources` | 判断“完整来源代次”何时到齐并发出 workflow trigger；Agent 对每次成功机器导入都做修订/摘要绑定的只读体检，不能因本次未触发而漏检 |
| `max_staleness_seconds` | 300-2592000 的整数，默认 3600；Agent allowlist 必须配同值 |
| `max_files_per_poll/max_total_bytes/max_total_records` | file-drop 单轮总量上限，超限显式报错而不截断 |
| `truth_statement` | 给经办人看的来源声明；wire 上的确认值固定为布尔 `true` |
| `revision_seed` | 仅在 connector state 丢失后，按 Agent 中该来源最新修订设置；正常保持 0 |
| `secret_env` | HMAC 密钥环境变量名；密钥本身禁止进入配置 |
| `agent_ca_bundle` / `sources.ca_bundle` | 内网 HTTPS 私有 CA PEM 文件；相对路径按 TOML 目录解析 |

十个业务量对应以下 11 个原子字段（火工品拆成不可相加的雷管支数和炸药质量）：

- `ventilation_m3_min`
- `electricity_kwh`
- `detonators_count`
- `explosives_kg`
- `mine_entry_persons`
- `production_t`
- `extraction_t`
- `sales_t`
- `transport_t`
- `wash_feed_t`
- `invoiced_quantity_t`

每个来源、每个出现记录的月份必须至少映射出一个非空规范值，否则整批按字段漂移或
映射错误处理并上报健康异常，不能生成“全是 null 却显示采集成功”的快照。应把该来源
按业务约定必须出现的核心 mapping 显式配置为 `required = true`。配置文件各层均严格
拒绝未知键，字段名拼错会在 `validate` 阶段失败，不会静默采用默认值。

裸目标（如 `sales_t`）会跟随该行解析出的 scope；`current_shift.sales_t` 语义相同。
`scope_field + scope_values` 应完整声明该来源实际提供的日报/班次口径。显式目标（如
`"daily_total.sales_t"`）只覆盖指定 scope，适合仅有日报的销售、运输、入洗和开票台账；
不要为了消除提示而把日报字段伪装成班次字段。

如果一日内同一来源、同一班次、同一指标出现多个不同值，默认 `single` 会阻断。只有明确掌握来源口径后，才配置：

- `sum`：累加明细；
- `average`：算术平均；
- `latest`：按观测时间取最后值；相同业务时间若出现不同值会阻断，不能按输入顺序任取；
- `single`：只接受唯一值或多个完全相同值。

风量聚合口径是时间加权平均。若上游给的是瞬时序列，不应简单使用 `average`；应在来源只读视图中先按已批准口径生成结果。

`production_t` 是企业生产报表产量，`extraction_t` 是采掘/工作面计量；两者不能因为
名称相近而复用同一列。`transport_t` 是出矿/外运净吨，不是矿内皮带周转量。
`wash_feed_t` 是进入洗选环节的原煤量。

`invoiced_quantity_t` 只接受本期开具的普通/蓝票对应的非负实物吨数。红票、退货、
折让是辅助事件，应保留在来源系统的独立明细或凭证中；禁止把带符号发票净额映射到
主字段。连接器发现负值，或经 `factor/offset` 转换后得到负值，会阻断该来源快照并上报
健康异常，不会取绝对值或静默丢弃。

## V2 历史兼容边界

- 已经存在于 connector 状态库中的旧 observation/outbox body 不会在启动、重放或迁移
  时改写；灾备重放仍发送原始 bytes 对应的业务 JSON。
- 已签名或已归档的 `five-quantity-submission-v2` 只能按历史只读链路查看/重放，不能由
  connector 补五个字段后变成 V3。新 V3 必须从原始 ERP/MES/台账重新采集。
- 仍只有六列的上游可继续配置：新快照会声明 V3，但五个新增字段只生成明确的
  `null + missing`，等待其他权威来源合并或人工补充；绝不伪造数值。
- `/api/v1/machine/autofill` 和 `enterprise-autofill-ingestion/v1` 是 Connector→Agent
  的稳定机器传输合同，不等于报送 V1/V2。其 `source.content` 内才声明十量 V3 数据合同。

`source.observed_at` 是这份稳定快照的采集时间，`connector_snapshot.data_watermark` 是来源记录中最大业务时间，`coverage_as_of` 是该月应报窗口的声明截止日。三者不可混用；快照仍可含 `missing_dates`，`coverage_as_of` 不代表“数据无缺失”。

## 机器接口与签名

请求固定为：

```text
POST /api/v1/machine/autofill
```

Headers：

```text
X-Enterprise-Connector-Client
X-Enterprise-Connector-Timestamp
X-Enterprise-Connector-Request-Id
X-Enterprise-Connector-Signature
```

签名材料严格是六行，最后一行不再追加换行：

```text
ENTERPRISE-CONNECTOR-HMAC-SHA256-V1
POST
/api/v1/machine/autofill
{timestamp}
{request_id}
{sha256(raw_body)}
```

签名为 `HMAC-SHA256(secret, material)` 的小写十六进制。JSON 只序列化一次，签名与发送必须使用同一组 UTF-8 bytes。

`request_id` 是单次 HTTP attempt 的防重放 nonce，每次重试都不同；`event_id` 是稳定业务事件键。Agent 返回 5xx、408、425、429，或明确的 `connector_ingestion_in_progress` 409 时重试；普通业务 409/4xx 进入 dead，避免无限重放错误数据。

同一 HMAC 协议还投递：

```text
POST /api/v1/machine/source-health
```

签名材料第三行必须改为该 health path。Body 使用 `enterprise-source-health/v1`，含月度 `draft_key/source_id/source_system`、尝试与完成时间、结果、记录数和有界错误码。`success_nonempty` 必须同时绑定最终已编号 `source.content` 的 SHA-256、autofill event 和 source revision；其他 outcome 这三项及 `coverage_as_of` 必须为 null。Agent 只在绑定的 autofill 已完成且 hash/revision 匹配当前 contribution 时判定 fresh，避免“health 成功、快照却被拒绝”的假绿灯。

## 运维和恢复

查看队列：

```bash
enterprise-connector status --config /etc/enterprise-connector/config.toml
```

状态输出的 `pipelines[].sources` 只含来源元数据：最新修订/期间、采集 outcome、本地与 Agent health 投递状态、最后非空时间、TTL 和最后错误。`required_sources_not_ready` 会列出未出现、空、错误、stale、health 绑定不匹配或最新修订尚未导入的必需来源。它不显示原始记录、HTTP 凭据或 HMAC 密钥。`overall_status` 可直接给监控系统使用；`check` 在存在 dead 或必需来源未就绪时退出码为 1。

只有确定 Agent 没有持久该 event 的业务拒绝结果时，才可重试 dead 的原 event：

```bash
enterprise-connector retry-dead \
  --config /etc/enterprise-connector/config.toml \
  --event-id cevt_xxx
```

省略 `--event-id` 时，仅重试每个来源当前最新且不是 4xx 业务拒绝的 dead 修订。Agent 对已持久拒绝的 event 会幂等返回同一拒绝，不能用 `retry-dead` 修复。核对并修复原因后，使用显式新修订：

```bash
enterprise-connector supersede-dead \
  --config /etc/enterprise-connector/config.toml \
  --event-id cevt_xxx \
  --reason '已核对Agent暂停状态并由张三、李四复核' \
  --confirm SUPERSEDE-DEAD
```

该命令保留旧 dead，对同一规范化快照生成新 `event_id/source_revision`，并写入恢复审计记录。常驻服务持有租约时，`retry-dead/supersede-dead/replay` 都会拒绝执行。

### 两库灾备与受控重放

连接器状态库和 Agent 数据库必须作为同一业务恢复点备份。建议先暂停连接器，再暂停 Agent，备份 Agent 数据库和 connector state，并记录两份文件摘要。恢复时先恢复 Agent，再恢复连接器。

如果 Agent 数据库回退、但 connector state 仍完整，可把每个来源的最新已交付快照重新排队；`event_id`、来源修订和 body 保持不变，Agent 已存在时幂等返回，不存在时重新落库：

```bash
enterprise-connector replay \
  --config /etc/enterprise-connector/config.toml \
  --latest \
  --confirm REPLAY
```

也可以用 `--event-id cevt_xxx` 精确重放。该操作不会重采源数据，执行前必须停止常驻连接器并确认目标恢复点。

如果 connector state 丢失但 Agent 数据库仍在，不能直接从修订 1 重建。先从 Agent 草稿的“来源与机器导入记录”取得每个 `source_id` 最新修订的证据，由两人记录恢复点、原因和文件摘要，再将 `revision_seed` 设为该值；首个新事件使用 `seed + 1`。`validate/status` 会醒目标记任何非零 seed。恢复后不要为了“让号码好看”盲目修改；恢复旧 state 始终是首选。

空结果、读取错误或文件消失只会产生 health 状态，绝不自动清空 Agent 中旧 contribution。若上游确实撤回了整月记录，必须按现场制度在 Agent 中人工处理并保留凭证；当前版本不提供无审计 tombstone。

file-drop 文件名必须是有效 UTF-8，且不得含控制或格式控制字符。已知来源错误保留安全诊断；意外解析或编码异常会隔离为 `source_internal_error`，日志只记录异常类型并继续采集后续独立来源，避免正文或凭据进入日志。

状态库包含待投递的规范化业务数据，目录和数据库在 POSIX 上分别收紧为 `0700/0600`。Windows 部署必须给服务账号设置专用 NTFS ACL，移除普通用户继承权限。状态库需要备份，但不得同步到个人网盘。为限制高频健康心跳长期占用空间，系统只清理超过 90 天、已投递且不是对应 pipeline/source/draft 最新状态的 health 记录；pending、dead、每组最新 health、业务 observations 和恢复审计永不自动清理。

单实例 SQLite 租约防止两份连接器同时投递。`lease_seconds` 必须大于 Agent 请求超时的两倍；每个 HTTP/SQLite 来源也有独立 deadline。

### 部署路径与权限

systemd 样例用 `StateDirectory=enterprise-connector`创建 `/var/lib/enterprise-connector`。生产 TOML 建议显式设置：

```toml
[service]
state_db = "/var/lib/enterprise-connector/connector.sqlite3"
```

`ProtectSystem=strict/ProtectHome=true` 下，还必须在本机 unit override 中把每个 file-drop 目录、SQLite 文件和私有 CA 的精确绝对路径加入 `ReadOnlyPaths=`；不要为省事放开整个 home 或根目录。Docker 镜像使用非 root 用户并预创建 `/var/lib/enterprise-connector`，运行时应挂载持久卷，配置中使用同一绝对路径。上游目录/数据库只挂载为只读。

## 生产安全要求

- 跨主机连接默认必须使用 HTTPS。HMAC 只保证完整性和身份，不加密煤矿数据。
- HTTPS 默认使用系统 CA；内网私有 CA 应配置 `agent_ca_bundle` 或来源 `ca_bundle`，不能关闭证书校验。
- 本机 loopback HTTP 可用于联调；非本机明文 HTTP 必须显式开启高风险开关，并应尽快迁移到 TLS。
- HTTP 认证信息只能用 `headers = { Authorization = "env:ERP_TOKEN" }` 引用环境变量。
- 数据库账号必须是来源系统只读账号；连接器内部只读防护不是数据库权限控制的替代品。
- 文件生产方应写临时文件并在写完后原子 rename 到投递目录。连接器仍会执行稳定窗口和 descriptor 复核。
- 先影子运行一个完整业务周期：只生成草稿和预检，不确认、不提交；统计缺失、冲突、延迟、误映射后再启用正式辅助流程。
- 曾经在聊天、日志或代码中暴露的密钥必须在服务商/系统侧轮换，不能继续使用。

## 测试

```bash
python -m pip install -e '.[test]'
python -m ruff check .
python -m pytest
python -m build
```

测试覆盖十量 V3 月度结构、11 字段真实 Agent 消费、六字段来源显式缺失、开票负数
阻断、三种只读适配器、SSRF/重定向/大小限制、HMAC、多来源 generation、响应丢失后
exactly-once、SQLite 租约、来源 `A→B→A` 修订及重启幂等。
