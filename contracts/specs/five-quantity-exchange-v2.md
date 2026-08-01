# 五量双向交换协议 V2

本文规定一个煤矿企业智能体与政府监管平台之间的中立边界。两套软件只共享本目录
发布的 JSON Schema、OpenAPI、固定向量和本文，不共享运行时代码、数据库、领域类或
算法实现。

## 1. 固定部署和身份边界

- 一个企业智能体实例只代表一个煤矿；认证客户端、`sender.system_id`、
  `sender.party_id` 和 `mine_id` 必须在政府端预先形成唯一绑定。
- 一个报文只能包含一个煤矿。企业智能体不能代表另一个所有者的煤矿，也不能在
  `days` 中混入另一个煤矿的数据。
- 政府必须在验证 HMAC 前后都检查认证身份、报文发送方、矿井和请求资源的绑定，
  不能仅相信 JSON 中自报的 `mine_id`。
- 企业通过出站 HTTPS 主动报送并拉取自己的风险消息；政府不需要连接矿区内网。
- 政府业务前端是否只读属于产品权限约束；本协议中的“发送、分析、记录”均可由
  政府后台自动执行，不代表领导用户具有写权限。

## 2. 六类不可变消息

| 消息 | 方向 | 语义 |
|---|---|---|
| `five_quantity_submission` | 企业 → 政府 | 一份月度期间报表，包含逐日和三班五量，已经企业人员确认 |
| `intake_receipt` | 政府 → 企业 | 政府已可靠接收并排队，尚未得出监管结论 |
| `analysis_report` | 政府 → 企业 | 唯一五量监管引擎的版本化结果和结构化风险项 |
| `risk_delivery_ack` | 企业 → 政府 | 风险报告已在企业本地 inbox 可靠落库，不是原因回复 |
| `enterprise_risk_response` | 企业 → 政府 | 企业人员确认的原因、证据索引、措施和更正报表引用 |
| `response_receipt` | 政府 → 企业 | 回复已可靠记录，或者更正报表已触发重算；不表示风险消除 |

每类消息都有独立、不可变的 `contract_version`。OpenAPI 路径见
`openapi/five-quantity-exchange-v2.openapi.json`。schema 是结构约束的权威来源；
本文补充跨字段、签名、状态机和授权语义。

## 3. 月报、逐日和班次结构

一份 `five_quantity_submission` 修订整个月度期间，而不是把一个月拆成三十条互不
关联的风险流程：

```text
payload
├── mine                         单矿及独立经营主体
├── reporting_month              YYYY-MM
├── period_start / period_end    含首尾的本地统计日期
├── comparison_context           同类矿匿名分组上下文
├── days[]                       1..366 个按日期升序且不重复的日报
│   ├── date
│   ├── operating_state
│   └── reported_quantity
│       ├── daily_total
│       └── shifts
│           ├── zero_shift
│           ├── eight_shift
│           └── four_shift
├── sources[]
├── agent_processing
└── human_confirmation
```

监管“五量”是五个业务组，不是六个相互独立的业务量：

| 业务组代码 | 中文口径 | 规范原子字段 |
|---|---|---|
| `airflow` | 风量 | `ventilation_m3_min` |
| `electricity` | 电量 | `electricity_kwh` |
| `blasting_materials` | 火工品量 | `detonators_count`、`explosives_kg` |
| `mine_entry_personnel` | 入井人员量 | `mine_entry_persons` |
| `production` | 产量 | `production_t` |

每个 `daily_total` 和每班 `measurements` 都必须显式包含以下六个规范原子字段：

| 字段 | 固定单位 | 允许的聚合 |
|---|---|---|
| `ventilation_m3_min` | `m3/min` | `time_weighted_average` 或 `snapshot` |
| `electricity_kwh` | `kWh` | `sum` |
| `detonators_count` | `count` | `sum`，非空时必须为整数 |
| `explosives_kg` | `kg` | `sum` |
| `mine_entry_persons` | `person` | `sum`，非空时必须为整数 |
| `production_t` | `t` | `sum` |

`blasting_materials` 是一个业务量，但不是一个可直接相加的标量。雷管按数量、炸药
按质量分别保存；二者单位不同，传输端、算法和界面都不得把它们相加成无单位的
“火工品总量”。本版不定义无单位的通用火工品总量字段。

`mine_entry_persons` 表示统计窗口内的入井人员量，是非负整数可加指标。它不是企业
职工或用工总人数，也不是某一时点仍在井下的人数快照；如将来交换井下实时人数，
必须使用另一个有明确 `snapshot` 语义的指标，不能复用本字段。

平台内部若兼容旧名 `wind_m3_min`，只能在本地适配层转换；V2 线上规范名固定为
`ventilation_m3_min`。

`days[].date` 必须处于 `period_start..period_end`，并与 `reporting_month` 一致。
日期不得重复，发送方应按日期升序排列。班次必须满足 `end_at > start_at`，并使用
带时区偏移的 RFC 3339 时刻。接收端还应根据该矿登记班制核对班次边界。

`comparison_context` 的五项分别是 `capacity_band`、`mining_method`、
`shift_system`、`coal_type` 和 `operating_regime`。政府必须与矿井注册表核对，
并以五项规范值的 JCS 摘要形成匿名比较组。企业自报值不能自行改变所属分组。
默认分组不使用精确产能或小样本地区标识，避免从同类矿统计反向识别其他煤矿。

## 4. 空值、质量标志和来源

缺失值必须传 `null`，不得用 `0` 代替。`null` 必须至少同时带一个
`missing`、`unavailable` 或 `not_applicable`；非空值不得携带这三种标志。
`partial`、`unit_converted`、`corrected` 和 `source_format_warning` 只描述事实，
不能让企业端把异常声明为正常。

每个测量必须用 `source_refs` 指向 `payload.sources[]`。V2 只定义两个并列合法的
采集方式：

- `direct_collection`：设备、网关或受控接口直采；
- `manual_import`：人工选择文件、固定目录文件导入或经确认的人工录入。

`acquisition_mode` 只用于追溯，不是信任等级，也不得产生可靠性权重、风险加分、
阈值差异或优先采用关系。政府算法对两种方式使用相同数值规则。无论采用哪种
方式，都必须保存来源记录编号、采集时间和原始证据 SHA-256。原始 ET/XLS/PDF
可以留在企业侧，JSON 只传内容摘要、来源位置和必要的内容寻址证据元数据。

智能体可以识别字段、规范单位和追问歧义，但不能估算、插补、编造或为了通过算法
而修改数值。模型参与必须记录在 `agent_processing`；正式报送必须有
`human_confirmation.confirmed = true`。

## 5. 消息身份、关联、幂等和修订

- `message_id` 唯一标识不可变消息。重试不得生成新消息 ID。
- `idempotency_key` 的作用域为已认证的发送系统；同键同内容返回原结果，同键不同
  内容返回 HTTP 409 并记录安全审计。
- 初始月报 `revision = 1`、`predecessor = null`、`causation_id = null`，并令
  `correlation_id = message_id`。
- 月报更正必须创建 `revision > 1`，保持原 `correlation_id`，用
  `predecessor.message_id + predecessor.payload_sha256` 指向紧邻上一版，并让
  `causation_id` 指向触发更正的风险报告、企业回复或上一版消息。
- 任何修订只能追加，不能覆盖上一版。日期、来源、确认和全部月度内容都随新版本
  重新签名。
- 回执、报告、投递确认和企业回复沿用同一 `correlation_id`；`causation_id`
  必须指向直接导致本消息产生的消息。
- `report_id` 是一次算法报告的逻辑身份，`analysis_report.message_id` 是该不可变
  outbox 消息身份；二者不能混用。一个算法 run 产生一个 report/outbox 消息，
  多个 `finding_id` 只是该报告的子项，不能各自重复生成同一风险投递。

双方采用持久 inbox/outbox 实现至少一次传输、业务效果恰好一次。只有本地事务
落库完成后才能推进 cursor 或发送确认。断电重启不得丢失待发消息。

## 6. 应用消息签名

HTTP 必须使用 TLS，并按 OpenAPI 中 `X-Exchange-*` 头验证请求体、时间窗和 nonce。
此外六类消息自身都必须带 `signature_envelope`，因此政府产生的风险报告和回执也能
被企业离线验真。

### 6.1 HTTP 传输签名材料

所有企业发起的 POST 和 GET 都必须携带 OpenAPI 声明的六个 `X-Exchange-*` 头。
`X-Exchange-Signature` 是对下列 UTF-8 行的 HMAC-SHA256 小写十六进制结果，行尾
不追加换行：

```text
MINEGUARD-FIVE-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V2
UPPERCASE-HTTP-METHOD
exact-path-with-query
X-Exchange-Sender-Id
X-Exchange-Timestamp
X-Exchange-Nonce
X-Exchange-Contract-Version
X-Exchange-Content-SHA256
```

`exact-path-with-query` 只含 origin-form 的原始 path 和可选 raw query，不含 scheme、
host 或 fragment。例如：

```text
/v2/analysis-reports/next?after_cursor=mine-qy-001.cursor.00000042
```

签名必须覆盖实际发送的查询串；不能只签 path 后再让代理改写查询。V2 路径参数和
`after_cursor` 都被限制在无需百分号编码的安全字符范围。反向代理必须把原始
request target 原样传给验签层；若代理无法保证，应在网关完成验签，不能用重新
拼装的 URL 猜测原请求。查询参数重复、顺序不符合 OpenAPI 或含空参数时直接拒绝。

`X-Exchange-Content-SHA256` 是实际请求 body 字节的 SHA-256。GET 和无 body 请求
固定使用空字节摘要：

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

POST 的 `X-Exchange-Contract-Version` 必须与 body 的 `contract_version` 相同；GET
固定使用 `five-quantity-exchange-v2`。时间使用 UTC RFC 3339，建议容许窗口不超过
正负 300 秒。nonce 至少包含 128 位随机数，同一发送方重复 nonce 必须在保留窗口
内拒绝。HTTP 传输密钥和下面的应用消息签名密钥应分别派生或分别配置，即使采用
相同根密钥也必须依靠不同签名域隔离。

### 6.2 应用消息签名材料

1. 按 RFC 8785 JCS 规范化 `payload` 对象。
2. 计算 `payload_sha256 = lowercase_hex(SHA-256(canonical_payload))`。
3. 按以下顺序连接 UTF-8 行，缺失的可空身份行使用空字符串，行尾不再附加换行：

```text
MINEGUARD-FIVE-QUANTITY-EXCHANGE-HMAC-SHA256-V2
contract_version
message_type
message_id
correlation_id
causation_id-or-empty
idempotency_key
revision-as-decimal
predecessor.message_id-or-empty
predecessor.payload_sha256-or-empty
created_at
sender.system_id
sender.party_id
sender.role
recipient.system_id
recipient.party_id
recipient.role
mine_id
signature_envelope.algorithm
signature_envelope.canonicalization
signature_envelope.key_id
signature_envelope.signed_at
signature_envelope.nonce
signature_envelope.payload_sha256
```

4. 以 `signature_envelope.key_id` 对应的双向交换密钥计算 HMAC-SHA256，并把小写
   十六进制结果写入 `signature_envelope.signature`。

签名域固定为 `MINEGUARD-FIVE-QUANTITY-EXCHANGE-HMAC-SHA256-V2`，防止与 V1、HTTP
传输签名或其他 HMAC 用途混用。生产密钥必须逐矿不同，独立轮换、加密保存；示例
固定密钥仅用于测试：

```text
example-v2-exchange-secret-not-for-production
```

| 示例 | payload SHA-256 | HMAC-SHA256 |
|---|---|---|
| `five-quantity-submission-v2.json` | `cf22a046f2899e4f11dd91f76ef37e2040da6e20f541bf16943946b1300aff35` | `39cea3887d4897dc3a76d4a2e3cf0399cc8d20d9d0e7547debe44411396ff5ab` |
| `intake-receipt-v2.json` | `ce2c24c7a60b715a99e06b738539052eb5ca7b16c309b8188c4c9c8fab467f1e` | `5873ab8850fed8ac6821d9b75e47b6ffd3c471ec841ba45ea77f79d79b297339` |
| `analysis-report-v2.json` | `689af99d8cafb5799fe7845b020e4b4022c121a8f9219ecdf4b7dbe89b43b1b9` | `ad317641229a6d9221b4284b2eaf3cd2778c98577b4b46ae6650cd3f7e8953bd` |
| `risk-delivery-ack-v2.json` | `7c9a80c12e96a2d216533af95b8c5172d86a0b4ad74a5d3a4cc91ecd3fb0430c` | `f6919b16c14be7801a242a7a88f88e4075ce91eb655b861c7f1b474f25d25b49` |
| `enterprise-risk-response-v2.json` | `1785cf19e5a29ef8fb774a37138e6516e2d9d68f8a8ed21af01546dccfbff185` | `775d61e71d21d4da6b1b35277c795d56c2e23bc8b6c4abb14d30ffc27cc52a4b` |
| `response-receipt-v2.json` | `8a7a585a0bbeffc62f8e866cb590cd6dbb7b84a0594c241a6b75406ec9fba4d8` | `0ebde843d41519864c2054bb0a15466e94eda602fbd465a80c79b6a1ff0c8eaa` |

`scripts/validate_contracts.py` 独立重算这些向量。实现不得通过“信任示例里的摘要”
绕过重算。

## 7. 唯一监管引擎和报告语义

政府对外只有 `mineguard-five-quantity-engine`。内部模块可以包括：

- 完整性和日报/班次确定性对账；
- 加权 L1 联合协调及最小冲突集 MCS；
- 本矿稳健时序基线、漂移与变化点；
- 停产、检修、复产等工况分段；
- 同类矿匿名统计基线；
- 多证据校准。

这些模块不是可由企业或政府前端任选的多套算法。规则层先按报文声明的聚合语义完成
确定性检查；主 L1 用带容差观测和软参考区间寻找最小联合调整，MCS 再把容差/参考带
硬化以定位最小冲突指标和日期。历史和同类矿范围是有误差的软证据，不是物理真理。

`analysis_report.algorithm` 必须记录引擎版本、配置摘要、输入快照、本矿历史快照、
匿名同类矿快照、模块和起止时间。结果只有：

- `normal_candidate`：当前证据充分且未发现未解释风险；
- `risk`：存在需核查的结构化风险；
- `data_insufficient`：缺失或口径不足，不能判断。

历史证据不足不能伪装成正常。同类矿样本不足时不得输出可识别的其他矿明细。
`intake_receipt` 永远固定为 `not_determined_at_intake`。

## 8. 风险投递、解读和回复

企业主动拉取 `response_required = true` 的报告。报告入本地 inbox 后发送
`risk_delivery_ack`，其 `analysis_report_message_id`、`report_id` 和
`delivery_cursor` 必须与原报告完全一致。确认投递不表示企业接受结论。

企业智能体可以围绕报告和本矿材料解释风险、追问事实、列出候选原因和形成回复
草稿，但正式 `enterprise_risk_response` 必须经人员确认。每项回复必须绑定
`finding_id`，说明 `response_kind`、原因代码、企业事实、证据引用和措施。

二进制证据不嵌入 JSON；`attachments` 只描述企业本地内容寻址对象。证据引用必须
指向同一回复中声明的 `evidence_id`。若另有受治理附件上传服务，应独立定义协议，
不得把任意企业路径暴露给政府或模型。

原因说明只能变成 `explanation_recorded`。`response_kind = correction_submitted`
必须引用一份已经提交、血缘连续且经过同一算法处理的更正月报；因此当前同步实现返回
`response_receipt.disposition = reanalysis_completed` 和对应 run ID。若未来改为
异步队列，可在任务尚未完成时返回 `reanalysis_queued`。无论哪一种，`risk_status`
仍固定为 `not_cleared_by_receipt`；只有更正月报的新算法报告通过才能形成
`cleared_by_reanalysis` 的政府内部状态。

## 9. 端到端状态约束

```text
submission received
  -> contract_validated
  -> analysis_queued
  -> analyzing
  -> normal_recorded | risk_open | insufficient_data_recorded

risk_open
  -> notice_available
  -> enterprise_acknowledged
  -> response_received
  -> explanation_recorded | reanalysis_queued | reanalysis_completed
  -> risk_persists | cleared_by_reanalysis
```

所有状态、原始消息、摘要、签名验证、算法输入快照、报告、投递、回复和重算都必须
追加留痕。留痕不等于进入正常历史基线；风险、数据不足和一段企业解释不得直接污染
正常样本。双方不得删除或覆盖已签名消息。

## 10. 实现必须补做的跨字段检查

JSON Schema 之外，双方至少还要验证：

- 认证客户端只绑定一个矿，且所有信封、payload、路径参数和关联消息矿井一致；
- 时间顺序、日期范围、班次边界、无重复日期和来源 ID；
- 每个 `source_ref` 和 `evidence_ref` 均存在；
- 初始与后续修订的 predecessor、causation 和 payload 摘要连续；
- 六类消息的 correlation、submission、report、finding、response 和 receipt 引用
  属于同一工作流；
- 同一发送方的 message ID、幂等键、nonce 和 cursor 重放规则；
- 企业确认发生在所有数据/Agent 处理完成后；
- `acquisition_mode` 不进入信任分层或算法权重；
- 回复回执绝不直接改变算法风险结论。
