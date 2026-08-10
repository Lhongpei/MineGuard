# 煤矿十量 V3 企业智能体

这是企业侧软件。一个运行实例固定代表一个煤矿和独立经营主体，负责取得十量、
规范化、人工复核、向政府报送、接收算法风险并形成企业回执。政府侧
`platform/` 只监管和分析；两端不共享运行时代码、数据库或领域类，只对齐
`contracts/` 发布的 V3 JSON/HTTP 合同。五量 V2 仅保留历史只读复核与审计。

当前默认主线只有两个产品：

```text
煤矿 Agent                              政府 Platform
人工上传 / 固定目录 / 设备 API            单矿及跨矿统一算法
        ↓                                     ↓
规范化建议 → 企业人工复核 → HMAC 报送 ───→ inbox / outbox / 算法报告
        ↑                                     │
风险解读 ← 验签拉取 ← delivery cursor ←───────┘
        ↓
原因 + 证据索引 + 措施 → 人工确认 → 风险回执 ─→ 政府留痕 / 必要时重算
```

固定目录和受控连接器都属于本 Agent 的采集能力，不再部署第三个 `edge-agent`
业务产品。简单目录监听内置于本进程；需要隔离访问企业 HTTP/SQLite 时，可在同一
矿区部署 `../connector-service/` 伴随进程，它只通过最小权限 HMAC 接口建待复核稿，
不能确认、报送或访问政府端。当前随仓连接器支持十量 V3 的 11 个原子字段，并已通过
真实 Agent HTTP 端到端验证；仍只有六字段的旧来源会把新增五项明确写成
`null + missing`，不会补零、推算或调用模型。连接器始终只建立待复核草稿，仍须经办人
核对并由另一具名负责人确认后才能报送。旧 `enterprise-submission-v1`、通用任务中心和新闻
对话代码只作 Legacy 迁移兼容，不在默认界面、V3 配置或部署流程中使用。

## 十量口径

十个业务量由 11 个不可混淆的原子字段传输：

```text
风量 ventilation_m3_min          电量 electricity_kwh
火工品量 detonators_count + explosives_kg（雷管与炸药不能相加）
入井人员量 mine_entry_persons    产量 production_t
开采量 extraction_t              销售量 sales_t
运输量 transport_t               洗煤量 wash_feed_t
开票量 invoiced_quantity_t
```

日报必须覆盖全部 11 个字段；前七个原子字段还要求三班数据，销售、运输、洗煤和开票
班次可选。`invoiced_quantity_t` 必须非负，只记录正常/蓝字发票对应实物吨数；红票、
退票、作废、折让和退货须在企业来源系统作为辅助明细独立留存，净额另算，不得把负数
写进开票主字段；当前 V3 主报文不传这些辅助事件。
完整字段、CSV 表头和迁移边界见
[十量 V3 部署与运行](../docs/十量V3部署与运行.md)。

## 已实现能力

- 一矿一实例：启动时固定 `mine_id`、经营主体、企业系统和政府接收方；页面不能跨矿切换；
- CSV 智能建稿主入口：下载 12 列日汇总模板或选择企业导出文件后，先预览日期、十量、单位与班次映射；陌生表头按“本矿已批准配置 → 本地规则 → 受约束模型建议”识别，人员确认后才生成待复核草稿；
- ET/XLS/XLSX/CSV/JSON/JSONL 安全导入，限制文件、压缩包、工作表、行列和单元格规模；
- 人工上传与直采并列合法，`acquisition_mode` 只追溯来源，不产生可信度等级、权重或阈值差异；
- 固定白名单目录监听、写入稳定等待、SHA-256 去重；异常文件复制到 Agent 状态目录隔离，原件不删除；
- 字段映射只允许 11 个 V3 原子字段和日报/三班次白名单；模型只接收表头与脱敏类型统计，不能读取或修改业务数值；缺失保持 `null`，不估算、不插补、不用 0 冒充；
- 未确认草稿可带原因“放弃”；这是保留原文、修订号和审计事件的软放弃，不做物理删除；
- 日报合计显式包含全部十量；零点、八点、四点三班至少包含前七个原子字段，商业四量班次可选；
- 人工复核后才形成不可变消息；上传文件绝不自动确认或报送，SQLite outbox 支持重启恢复、指数退避和幂等重试；
- 独立实现 RFC 8785 JCS、应用消息 HMAC 和 HTTP 运输 HMAC，不 import `platform/` 或 `contracts/` 运行时代码；
- 完整支持 V3 七条交换路径、opaque cursor、禁止 HTTP 重定向和可选私有 CA；
- 风险报告验签后事务落入 inbox，再发送 delivery ack；只有 ack 成功才推进 cursor；
- 当前/上一把政府应用签名密钥轮换；
- 只围绕当前风险报告的煤炭对话工具，以及逐 finding 的原因、证据索引、措施和更正引用；
- 企业人员再次确认后发送回复；政府接收回执明确不等于风险消除；
- append-only SHA-256 操作链；
- 面向非技术人员的四页前端：数据收件箱、规范化复核与报送、风险解读与回复、留痕与设置。

## 本机安装与启动

Windows 原生安装、逐矿实例、WinSW 服务、日志、完整业务状态备份和恢复见
[Windows 部署说明](deploy/windows/README.md)。Windows 配置由受 ACL 保护的严格
`KEY=VALUE` 文件在进程启动时读取，不执行 PowerShell 代码。正式 Windows runtime 和
服务安装都必须从线下审批材料输入独立 Authenticode signer 指纹；签名 Setup 本身还必须在
执行前按另一路线下 SHA-256/签名者值验真，runtime 指纹不能替代 Setup 的预执行信任。每个矿的服务使用
自己派生的 `NT SERVICE\MineGuardEnterpriseAgent-<实例>` 身份，不再共享 LocalService。

在仓库的 `agent/` 目录执行：

```bash
cd /home/sevan/coral/agent
python -m pip install -e .
enterprise-agent serve --host 127.0.0.1 --port 8090
```

若 shell 仍提示 `enterprise-agent: command not found`，直接使用当前 Python：

```bash
cd /home/sevan/coral/agent
PYTHONPATH=src python -m enterprise_agent serve --host 127.0.0.1 --port 8090
```

看到启动说明后终端持续占用、没有继续输出，是 HTTP 服务在正常等待请求，不是卡死。
浏览器打开 <http://127.0.0.1:8090/>。按 `Ctrl+C` 可正常停止。

CSV 智能映射不强制依赖模型 API：未配置时仍会使用标准模板、同矿已批准映射和本地
规则。若希望 Agent 为陌生表头给出受约束建议，请在启动前配置
`DEEPSEEK_API_KEY`（以及需要时的 `DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL`）；
运行中的进程不会读取新环境变量，修改后需重启服务。模型只接收表头和类型计数，
不会收到 CSV 原始业务数值。

仅本机、未配置逐用户账号时会启用演示账号：

```text
账号：demo
密码：123123123
```

演示账号被标记为必须换密，只能查看和编辑，不能确认或报送。正式测试完整流程必须
显式启用 `ENTERPRISE_AGENT_PRODUCTION_MODE=true` 和
`ENTERPRISE_AGENT_FOUR_EYES_REQUIRED=true`，并配置两个姓名不同、权限分离的逐用户
账号：经办人只拥有 `read/write`，复核人只拥有 `read/confirm/submit`。仅仅不使用
demo 账号不等于正式模式。

正式凭据建议这样生成（分别为两人运行一次）：

```bash
enterprise-agent hash-password --production --json
```

输出仅含 `password_hash`、`credential_provenance`、`must_change_password`，可复制进
用户 JSON，不含明文。正式启动前执行 `enterprise-agent config-check --production`；
最后创建或编辑草稿的人不能确认、排队或提交。CSV/连接器/目录监视自动生成的
草稿必须先由配置中的具名经办账号打开核对并保存，才能由另一复核账号
确认。正式模式禁用可自报 `--actor` 的变更 CLI；审计完整性使用全链+尾锚
校验，不会因前端只显示 200 条而放过后段篡改。

## 最小 V3 配置

复制 [.env.example](.env.example) 的变量到启动环境。Linux 可由 systemd
`EnvironmentFile`、容器 Secret 或受控 shell 注入；Windows 服务使用
`enterprise-agent --env-file <绝对路径> --authoritative-env-file serve` 读取严格 UTF-8
`KEY=VALUE` 文件，并先清除继承的 Agent 配置命名空间，防止机器级变量跨矿覆盖身份、状态库
或 HMAC。普通跨平台 CLI 仍保持已有进程环境变量优先；两种模式都不会执行配置文件，也不
支持变量展开或命令替换。

```bash
export ENTERPRISE_MINE_ID=MINE-QY-001
export ENTERPRISE_MINE_NAME=示例一号煤矿
export ENTERPRISE_OPERATOR_ID=operator-qy-001
export ENTERPRISE_OPERATOR_NAME=示例一号煤业有限公司
export ENTERPRISE_SYSTEM_ID=agent-mine-qy-001

export PLATFORM_V3_BASE_URL=http://127.0.0.1:8080
export PLATFORM_V3_SENDER_ID=agent-mine-qy-001
export ENTERPRISE_EXCHANGE_KEY_ID=enterprise-key-v3
export REGULATORY_EXCHANGE_KEY_ID=regulator-key-v3
export ENTERPRISE_EXCHANGE_HMAC_SECRET='replace-message-secret-at-least-32-bytes'
export PLATFORM_V3_TRANSPORT_HMAC_SECRET='replace-transport-secret-at-least-32-bytes'

enterprise-agent serve --host 127.0.0.1 --port 8090
```

`PLATFORM_V3_SENDER_ID` 必须等于 `ENTERPRISE_SYSTEM_ID`，并与政府逐矿登记完全
一致。只有显式配置 `PLATFORM_V3_BASE_URL`（或迁移期兼容的 `PLATFORM_V2_BASE_URL`）
才启用正式交换；Legacy V1 的 `PLATFORM_BASE_URL` 不会隐式启动 V3。新部署应使用
V3 名称，V2 名称只作为环境迁移别名。

生产远程地址必须使用 HTTPS。私有 CA 可配置：

```bash
export PLATFORM_V3_CA_BUNDLE=/etc/enterprise-agent/regulatory-ca.pem
```

客户端不跟随 301/302/307/308 等任何重定向，防止把带签名的请求重放到另一来源。
应用消息密钥与运输密钥都必须显式配置且内容不同，并使用两个固定签名域；配置相同
内容会在启动时失败。政府换钥的过渡期可同时
配置上一把入站验签密钥：

```bash
export REGULATORY_PREVIOUS_EXCHANGE_KEY_ID=regulator-key-previous
export REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET='replace-previous-secret-at-least-32-bytes'
```

## 获取数据

前端人工上传支持 `.et`、`.xls`、`.xlsx`、`.csv`、`.json`、`.jsonl`。标准日汇总
CSV 是“日期 + 11 个原子字段”的 12 列模板；旧五量文件只可生成历史复核内容，缺少
的新字段不会补数。固定目录
直采在启动前配置，例如：

```bash
export ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS=/srv/mine-readonly/five-quantity-inbox
```

多个目录使用操作系统路径分隔符连接。监听器只读取普通文件，不跟随符号链接；同一
大小和修改时间连续稳定后再读取，按内容摘要去重。解析失败文件会复制到数据库同级的
`five-quantity-quarantine/`，不会写回来源目录，也不会删除来源原件。

主页面和通用 API 不开放“任意 URL 定时 GET”。需要设备接口时使用仓库中的受控
`connector-service/`：每个 URL 固定 HTTPS origin、主机/端口 allowlist、私有 CA、
响应上限、超时、内容类型和仅从环境变量读取的身份凭据；页面用户不能临时改 URL。
它也支持只读 SQLite 和稳定文件投递，完整配置见
[企业数据自动采集连接器](../connector-service/README.md)。

## 企业 HTTP API

浏览器会话使用 `HttpOnly; SameSite=Strict` Cookie；修改请求必须携带
`/api/v1/auth/me` 返回、只保存在页面内存的 `X-CSRF-Token`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/v2/status` | 固定矿井、接口、监听目录和 cursor 状态 |
| `GET/POST` | `/api/v2/imports` | 收件记录 / 人工导入 base64 文件；`include_discarded=true` 可追溯已放弃项 |
| `POST` | `/api/v2/direct-ingest` | 受控设备/API 直采入口 |
| `POST` | `/api/v2/watch/scan` | 立即扫描固定目录 |
| `GET` | `/api/v2/drafts` | 月报复核稿列表；`include_discarded=true` 可追溯已放弃项 |
| `GET/PATCH/DELETE` | `/api/v2/drafts/{id}` | 读取 / 保存 / 带修订号和原因软放弃未确认稿 |
| `GET` | `/api/v2/drafts/{id}/ingestions` | 查看机器导入批次、来源、拒绝原因和数据就绪预检 |
| `POST` | `/api/v2/drafts/{id}/confirm` | 人工确认并可靠入队；同时需要 `confirm` 和 `submit` |
| `POST` | `/api/v2/drafts/{id}/send-now` | 手工触发一次 outbox 重试 |
| `GET` | `/api/v2/risks`、`/{id}` | 风险收件箱 / 已验签报告 |
| `POST` | `/api/v2/risks/poll` | 立即拉取一份新报告 |
| `GET/POST` | `/api/v2/risks/{id}/chat` | 当前报告范围内的只读解释 |
| `POST` | `/api/v2/risks/{id}/response` | 创建或取得结构化回复草稿 |
| `GET/PATCH` | `/api/v2/responses/{id}` | 读取 / 保存回复 |
| `POST` | `/api/v2/responses/{id}/confirm` | 人工确认回复并可靠入队 |
| `POST` | `/api/v2/exchange/run` | 立即执行一次发送与拉取 |
| `GET` | `/api/v2/audit` | 校验并查看当前操作链 |

这里的 `/api/v2/*` 是浏览器与本机 Agent 之间保留稳定的内部路由名，不是企业向政府
发送的合同版本。对政府的正式入口是 `/v3/ten-quantity-submissions` 及同组 V3 路径。

## 权限

- `read`：查看本矿数据、风险、对话和留痕；
- `write`：导入、直采、保存复核稿和回复草稿；
- `confirm` + `submit`：两者同时具备且账号不是临时/待换密，才可确认报送或回复。

角色名称只是展示文字，真正授权只取决于服务器端 permissions。各矿属于不同经营主体，
应使用各自数据库、系统账号、HMAC 密钥和 Agent 实例，不能共用一个企业端实例切换矿井。
软放弃也需要 `write`；仅 `ready_review` 且从未确认、从未进入 outbox 的草稿允许放弃。
已确认、排队、送达、风险报告、企业回复和回执均无删除接口。

## 测试

```bash
cd /home/sevan/coral/agent
python -m compileall -q src
ruff check src tests
pytest -q
```

专项测试覆盖安全导入、JSONL、ET/XLSX、十量 CSV、无插补、来源无信任分层、七条 V3 路径、
opaque cursor、双 HMAC、重定向拒绝、CA 配置、当前/上一把验签密钥、重启恢复、
目录去重与隔离、完整报送—风险—回复流程、HTTP API 和四页前端。

部署步骤、systemd、Nginx、备份和故障处置见
[部署与运维](docs/部署与运维.md)，账号说明见
[分级账号操作手册](docs/分级账号操作手册.md)。

## Legacy 兼容说明

仓库仍暂存 `/api/v1/drafts`、通用 Harness、任务/新闻等接口，以便旧数据库和旧调用方
迁移。它们不是当前十量 V3 主界面或默认部署合同。不得用 V1
`enterprise-submission-v1` 或五量 V2 代替本页的月度十量 V3，也不得重新把独立 `edge-agent`
作为第三个默认产品接入。待历史调用方完成迁移后可单独安排代码退役。
