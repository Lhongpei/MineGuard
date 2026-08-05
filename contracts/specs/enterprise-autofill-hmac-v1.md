# 企业连接器自动建稿与 HMAC 协议 V1

本协议是企业内部受控连接器到单矿企业 Agent 的唯一机器写入口。它不是 Agent 到
政府 Platform 的报送协议，也不赋予确认、提交、监管判断或来源签名权限。

权威请求 schema：
[`enterprise-autofill-ingestion-v1.schema.json`](../schemas/enterprise-autofill-ingestion-v1.schema.json)。
固定示例：
[`enterprise-autofill-ingestion-v1.json`](../examples/enterprise-autofill-ingestion-v1.json)。

## 1. 部署与授权

- 一个 Agent 固定代表一个煤矿和一个经营主体；最多配置一个权威机器连接器 client。
- 多个 ERP/MES/台账来源必须在该 client 内使用不同 `source_id` 聚合。
- Agent 配置把每个 `source_id` 精确绑定到 `source_system`，不接受通配或客户端临时
  声明的新来源。
- `draft_key` 固定为
  `draft:{operator_id}:five-quantity:monthly:{reporting_month}`。Agent 从自己的启动
  身份和规范化内容独立核对，不能只相信请求文本。
- 连接器密钥只允许 `autofill`；它与企业到政府的消息 HMAC、运输 HMAC 完全不同。

## 2. HTTP 请求

方法和路径必须逐字为：

```text
POST /api/v1/machine/autofill
```

不接受尾斜杠、query、fragment、重定向或其他方法。`Content-Type` 应为
`application/json`，正文是一次序列化后的 UTF-8 JSON bytes。

必需请求头：

```text
X-Enterprise-Connector-Client: {client_id}
X-Enterprise-Connector-Timestamp: {Unix秒}
X-Enterprise-Connector-Request-Id: {本次HTTP尝试的唯一nonce}
X-Enterprise-Connector-Signature: {64位小写十六进制HMAC}
```

时间戳只允许在 Agent 配置的时钟偏差窗口内。每次 HTTP 尝试必须生成新的
`request_id`；服务器在认证成功后立即持久登记 nonce，即使后续 JSON、来源授权或业务
校验失败，该 nonce 也不能重用。

## 3. 签名

先计算实际 HTTP body bytes 的 SHA-256 小写十六进制，再构造以下六行文本。最后一行
之后不追加换行：

```text
ENTERPRISE-CONNECTOR-HMAC-SHA256-V1
POST
/api/v1/machine/autofill
{timestamp}
{request_id}
{sha256(raw_body)}
```

签名：

```text
lower_hex(HMAC-SHA256(connector_secret, UTF8(material)))
```

签名与发送必须引用完全相同的 body bytes，不能签名后重新格式化 JSON。认证失败统一
返回 401，不透露客户端是否存在、时间、签名还是权限哪一项不正确。HMAC 不加密数据，
跨主机仍必须使用 HTTPS 和受控 CA。

仓库固定向量使用非生产密钥
`example-enterprise-connector-secret-not-for-production`：

| 示例 | Unix 时间 | request_id | body SHA-256 | HMAC |
| --- | --- | --- | --- | --- |
| `enterprise-autofill-ingestion-v1.json` | `1785475200` | `creq_example_autofill_001` | `6ac2d11c104e876dfb9167f5bc48f07ed27ba369ba312ffc17455e827bae2b48` | `0cb4651311da338f912185efded84d35d427af29d509e439b4163f0f082dad86` |
| `enterprise-source-health-v1.json` | `1785475260` | `creq_example_health_001` | `6a39402c350186ba63d1e6505d8b8161894eea2d42d227b5290a15d9ab1bda4e` | `0e968a5eeb8817be737e890a049fb5617f22bb3569711273b65c706ce832af4c` |

第二行签名材料中的方法都是 `POST`；第三行必须分别使用各自路径。发布门会重新计算
这两组向量，避免发送端和接收端对路径或原始 body 的理解漂移。

## 4. 两层幂等

- `request_id`：单次传输尝试。响应丢失后重试时必须更新 timestamp、request_id 和
  HMAC。
- `event_id`：持久业务事件。相同来源修订的重试保持同一 event_id 和完全相同 body；
  Agent 返回原结果且不重复修改草稿。event_id 不随 nonce 过期。

同一 `(client_id,event_id)` 不得绑定不同正文。来源 `revision` 从 1 开始严格单调；
连续相同快照不产生修订，而 `A→B→A` 必须形成三个修订，不能因摘要曾出现过就丢掉
第三次状态变化。

## 5. 来源快照和合并

连接器每个 `source_id`、每个 reporting month 发送一份完整来源快照。快照显式包含
日报合计、零点班、八点班、四点班和六个原子字段；缺失使用 `null + missing`，不估算、
不插值、不填 0。`source.observed_at` 是连接器成功读取这份精确快照的带时区时间，
`source.coverage_as_of` 是其业务日期覆盖截止日；二者都在 HMAC 正文内。Agent 校验未来
时间，并使用自己配置的来源时效阈值计算过期时间，不能由客户端随意延长。

Agent 保存每个来源的最新贡献并重新计算同一个草稿：

- 空值与非空值合并时保留非空事实和来源引用；
- 两个不同来源对同一日期、scope、metric 给出不同非空值时，整个新事件原子拒绝；
- 同一来源较高 revision 替换自己的旧快照，不执行 last-writer-wins 跨来源覆盖；
- 人工编辑后的草稿不允许后台覆盖，自动同步进入 paused，只有具名用户的显式恢复
  流程才能舍弃手工修改并从最新来源贡献重建；
- 放弃只适用于未确认草稿并保留审计，不能删除已确认或已发送材料。

原始正文和连接器密钥不返回浏览器。前端只展示认证 client、来源 ID/系统、来源修订、
事件/请求摘要前缀、时间、草稿修订、预检和安全拒绝原因。

## 6. `trigger_workflow`

wire 字段 `workflow_name=daily_coal_health` 是 V1 兼容标识。本版实际只运行确定性的
“五量数据就绪预检”。Agent 对每次成功机器导入都执行并持久保存一次绑定当前草稿
revision 和完整 payload SHA-256 的预检；`trigger_workflow` 仅表示连接器判断必需来源
的一个完整代次已经到齐，不得被实现成“false 就跳过预检”：

- 声明统计窗口内是否缺完整日报；
- 24 个日报/三班数据格的缺失数量；
- 可加指标的日报与三班算术关系；
- 来源数、绑定草稿 revision 和 payload SHA-256；
- 当前窗口是否只是 reporting month 的部分窗口。

它不运行政府监管算法，不读取其他煤矿，不给出正常/合法/风险结论，也不能确认或提交。
预检必须绑定精确草稿 revision 和 payload 摘要；草稿变化后旧预检在页面标为过期。

`required_sources` 是连接器侧的首次到齐门槛。门槛达到后，任何 required 或 optional
来源的新修订都必须计算包含全部最新来源的 generation hash，并重新触发一次预检。
健康心跳恢复但业务内容未变化时不会伪造新来源修订；因此先前以
`trigger_workflow=false` 导入的同一快照也必须已经具有上述绑定预检。人工修改使预检
绑定过期时，读取接口必须明确标记 obsolete/attention，确认事务应对当前版本重新执行
确定性预检并写入审计，不能沿用旧绿灯。

### 6.1 来源健康心跳

成功取得但内容未变化、空结果、采集错误和文件稳定等待不应伪造新的业务值。连接器改用
状态专用入口：

```text
POST /api/v1/machine/source-health
```

正文遵循
[`enterprise-source-health-v1.schema.json`](../schemas/enterprise-source-health-v1.schema.json)，
固定示例见
[`enterprise-source-health-v1.json`](../examples/enterprise-source-health-v1.json)。四种 outcome
分别是 `success_nonempty`、`success_empty`、`error`、`stability_wait`。错误只允许受限
`error_code`，不得发送上游 URL、SQL、响应正文、token 或人员信息。
只有 `success_nonempty` 可以声明实际 `coverage_as_of`；其他状态固定为 `null`，不得
把本轮期望截止日冒充已读取的业务覆盖。

`success_nonempty` 还必须绑定 `snapshot_sha256`、`autofill_event_id` 和
`source_revision`；其他 outcome 三项固定为 `null`。健康记录只有在摘要和修订与当前
来源贡献一致、且对应自动建稿事件已经 completed 时才可判为 fresh。若快照事件被人工
修改保护、多来源冲突或内容校验拒绝，先到达的健康心跳仍只能显示 waiting/error，不能
让旧草稿或旧预检继续呈绿色。

`snapshot_sha256` 精确覆盖最终发送的 `source.content` UTF-8 bytes，包括连接器写入的
最终 `connector_snapshot.source_revision`。它不是连接器用于判断业务内容是否变化的
semantic hash；两种摘要必须分开保存和命名，不能用注入 revision 之前的摘要与 Agent
实际收到的贡献正文比较。

HMAC header、nonce 和 body hash 规则与自动建稿相同，但签名材料第三行必须是实际健康
路径 `/api/v1/machine/source-health`。健康事件有自己的耐久 `event_id`；旧 `completed_at`
不能覆盖较新的状态。

健康入口只能更新来源时效证据，绝不能创建、修改、清空、放弃、确认或提交草稿。Agent
根据自己为 `source_id/source_system` 配置的 `required` 和 `freshness_max_seconds` 动态
计算 `fresh_until`：必需来源首次为空、采集错误、状态未知，或年龄达到/超过阈值时，
已有快照保持不变但就绪状态变为非绿色，旧预检不得用于确认。采集侧绝不能把“本轮没
看到记录”解释成删除、0、`null` 或撤回；业务撤回应另走具名人员明确接受并留痕的流程。

## 7. 状态码和重试

| 状态 | 含义 | 客户端行为 |
| --- | --- | --- |
| 200 | event 精确幂等重放 | 标记已送达 |
| 201 | 已建稿/修订，未请求预检 | 标记已送达 |
| 202 | 已建稿/修订并完成数据就绪预检 | 标记已送达 |
| 400/403/413/422 | 请求或来源永久无效 | 进入 dead，人工修正 |
| 401 | 统一认证失败 | 停止并检查密钥、时间和 client 配置 |
| 409 `connector_ingestion_in_progress` | 同 event 正在处理 | 退避后用新 request_id 重试 |
| 其他业务 409 | 冲突、人工编辑暂停或 revision 错误 | 进入 dead，人工处置 |
| 408/425/429/5xx | 暂时不可用/受限 | 有上限地指数退避 |

业务拒绝会耐久保存。重复发送同一被拒 event 返回同一安全拒绝结果，并标明幂等重放，
不会再次解析或部分写入。

发送端不能把“任意 2xx”直接记为送达。自动建稿成功响应必须是 JSON，且
`contract_version=enterprise-autofill-ingestion-result/v1`、`status=completed`、
`event_id` 与请求精确一致，并含安全的 `draft_id/ingestion_id`；健康成功响应必须是
`enterprise-source-health-result/v1`、`status=recorded` 且 event 精确一致。200 HTML、
重复 JSON 键、错 event 或未知结果版本均按可重试的协议错误处理，不能从 outbox 删除。

## 8. 容量、安全和恢复

- `source.content` 最大 2 MiB UTF-8；外层 JSON 因转义可更大，Agent 使用独立约 5 MiB
  机器请求上限，不复用人工上传的 30 MiB 上限。
- Agent 对新 event 速率、每日总量、历史月份绑定和每月唯一来源数执行耐久配额；反向
  代理再独立限制 body、连接数、速率和超时。
- connector SQLite 保存待投递正文、来源修订和 generation；Agent SQLite 保存 nonce、
  event 幂等、来源贡献、草稿和审计。二者应按同一维护窗口成对备份。
- Agent 回滚而 connector 未回滚时，使用受控 `replay --latest` 重放稳定 event；
  connector 状态丢失而 Agent 保留高 revision 时，核对 Agent 证据后为该来源配置
  `revision_seed=Agent最新revision`，使重建首事件从 `seed + 1` 开始。禁止手工修改
  SQLite 或清空幂等表，并须记录 seed 的操作者、原因和复核证据。

连接器采集、机器建稿、人工确认、政府接收和监管算法是五个不同责任层。任何一层成功
都不能被描述成后一层已经完成。
