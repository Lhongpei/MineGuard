# 十量双向交换协议 V3

本文定义与“五量双向交换 V2”并行的十量边界。V3 是新契约，不是对 V2 schema、
示例、固定向量或线上语义的原地扩展。企业智能体和监管平台只能共享本目录发布的
schema、OpenAPI、固定向量与规范，不得共享运行时代码和数据库模型。

## 1. 十个业务组与十一个原子指标

| 顺序 | 业务组 | 中文口径 | 原子字段 | 单位 | 聚合 |
|---:|---|---|---|---|---|
| 1 | `airflow` | 风量 | `ventilation_m3_min` | `m3/min` | `time_weighted_average` 或 `snapshot` |
| 2 | `electricity` | 电量 | `electricity_kwh` | `kWh` | `sum` |
| 3 | `blasting_materials` | 火工品量 | `detonators_count` | `count` | `sum`，非空时为整数 |
| 3 | `blasting_materials` | 火工品量 | `explosives_kg` | `kg` | `sum` |
| 4 | `mine_entry_personnel` | 入井人员量 | `mine_entry_persons` | `person` | `sum`，非空时为整数 |
| 5 | `production` | 产量 | `production_t` | `t` | `sum` |
| 6 | `extraction` | 开采量 | `extraction_t` | `t` | `sum` |
| 7 | `sales` | 销售量 | `sales_t` | `t` | `sum` |
| 8 | `transport` | 运输量 | `transport_t` | `t` | `sum` |
| 9 | `coal_washing` | 洗煤量 | `wash_feed_t` | `t` | `sum` |
| 10 | `invoicing` | 开票量 | `invoiced_quantity_t` | `t` | `sum` |

火工品仍是一个业务组，但雷管数量和炸药质量单位不同，必须保留为两个原子指标，
不得相加成无单位的“火工品总量”。`sales_t` 固定指以完成销售出库并交付为确认点的
煤炭实物吨数，不是合同量、订单量或尚未交付量。`transport_t` 固定指出矿后用于对外运输
的煤炭净吨数，不是矿内倒运毛重。`wash_feed_t` 固定指进入洗选环节的原煤入料量，
不是精煤产出，也不是洗损；若未来需要精煤、煤泥、矸石等产出，必须新增不同字段。
`invoiced_quantity_t` 固定为本期已开具正常/蓝票所载的煤炭实物吨数，不是发票金额、
税额或红冲净额。红票、退货和折让作为辅助逐笔事件单独保留，不混入或静默冲减十量
主字段。销售、运输、开票可能跨日，不得假定三者同日严格相等。

本 V3 主报文不承载红票/退货事件、期初期末库存、洗后产品/矸石/损耗、在途批次、
逐批运输/开票日期或来源依赖域。接收端不得声称已根据这些未传输事实完成收发存、
洗选物料平衡或逐批账龄核验，也不得把缺少未发布字段算作 V3 主量缺报。将来若启用
这些高级模块，必须发布独立版本的辅助证据消息及 schema，并把其快照摘要绑定到分析
报告；不得原地扩展本合同或从 11 个主量推测辅助事实。

V3 wire 只允许上表中的规范名，不接受 `sales_shipped_t`、
`transport_shipped_t`、`invoiced_t` 等别名。旧表头转换只能发生在企业端本地适配层，
且必须记录原表头、转换规则和来源摘要。

## 2. 日报与班次粒度

`daily_total` 必须精确包含全部 11 个原子指标。每个班次 `measurements` 必须包含
以下前 7 个原子指标：

```text
ventilation_m3_min
electricity_kwh
detonators_count
explosives_kg
mine_entry_persons
production_t
extraction_t
```

以下 4 个指标在班次层可选：

```text
sales_t
transport_t
wash_feed_t
invoiced_quantity_t
```

班次来源确实没有该口径时，可以省略可选属性；若发送方选择显式表示不适用，必须
传完整 measurement，令 `value = null` 且 `quality_flags` 至少包含
`not_applicable`。暂时缺失用 `missing`，来源当前不可用用 `unavailable`。任何一种
情况都不得填 `0`。数值 0 只表示来源明确记录了真实的零业务量。全部 11 个原子
指标都必须非负；负值不是缺失、红冲或异常占位符。红字发票数量必须
在辅助凭证中单列，不能通过负主字段表达。

日报 11 项不能省略。日报口径不适用时同样用 `null + not_applicable`，这样可区分
“不适用”“暂时没有拿到”“真实为零”。所有 measurement 都必须至少有一个
`source_ref`，引用 `payload.sources[]` 中实际存在的证据来源。

日报和班次的数值关系必须根据聚合口径检查：可加指标可比较日报与班次之和；风量的
时间加权平均不能直接求和。可选的后 4 项没有完整班次覆盖时，不能据此宣告日报对账
异常。班次窗口、日报日期、统计时区、来源唯一性和修订链约束沿用 V2 的严格规则。

## 3. 业务语义与监管证据

V3 引擎标识固定为：

```text
mineguard-ten-quantity-engine
```

分析仍以数据质量、确定性规则、L1 联合协调、最小冲突集、本矿仅使用过去数据的稳健
时序基线、变化点和匿名同类矿基线作为并列证据。新增业务流关系用于提出“需复核”的
证据，不是绝对物理恒等式，至少要考虑：

- 开采、产量和洗选的统计边界、库存结转、煤种和损耗口径；
- 销售、运输、开票的跨日、跨月、退货、红冲、在途和结算时间差；
- 自用、外购、混煤、代洗、委托运输等登记业务场景；
- 计量设备误差、称重净重/毛重口径和来源时间对齐。

上述关系只能形成带容差、工况和历史基线的可解释证据，不能把简单不相等直接认定为
违法、瞒报或违规。`normal_candidate` 也只是当前证据下的正常候选，不是法律结论。
历史或来源不足必须输出 `data_insufficient`，不能用模型估算缺项后再判正常。

分析报告中的 `production_extraction_reconciliation`、
`production_sales_reconciliation`、`production_transport_reconciliation`、
`production_wash_reconciliation`、`sales_transport_reconciliation` 和
`sales_invoice_reconciliation` 仅表示相应同期间比率确实进入了本矿历史或匿名同类矿
软参考诊断；没有可用参考带时不得列出。它们不表示库存守恒、逐批凭证匹配或跨期账龄
已经执行。当前运行时不会输出 `inventory_flow_reconciliation`。

## 4. 新增消息与通用消息兼容矩阵

| 流程位置 | `contract_version` | 应用签名域 | V3 使用方式 |
|---|---|---|---|
| 十量报送 | `ten-quantity-submission-v3` | V3 | V3 新增 |
| 收件回执 | `intake-receipt-v2` | V2 | 结构通用，原样复用 |
| 十量分析 | `analysis-report-v3` | V3 | V3 新增 |
| 风险投递确认 | `risk-delivery-ack-v2` | V2 | 结构通用，原样复用 |
| 企业风险回复 | `enterprise-risk-response-v2` | V2 | 结构通用，原样复用 |
| 回复回执 | `response-receipt-v2` | V2 | 结构通用，原样复用 |

复用不表示修改 V2 文件，也不表示 V2 解析器可以接受 V3 字段。四个通用消息不包含
指标集合，已有 `message_id`、`submission_message_id`、`report_id`、`causation_id`、
`correlation_id` 和 payload 摘要足以把它们绑定到 V3 流程，因此保持原 schema 和
固定向量。它们仍按自身 `contract_version` 使用 V2 应用签名域。

验签端必须先读取被允许的精确 `contract_version`，选择唯一 schema、签名域和密钥
用途后再验签；不得在 V3 失败后回退尝试 V2，也不得把 `analysis-report-v2` 当作 V3
报告。所有 `/v3/*` HTTP 请求，无论 body 是 V3 新消息还是显式复用的 V2 通用消息，
运输层都使用第 6 节的 V3 HTTP 签名域。应用签名与 HTTP 运输签名是两个独立层次。

V3 收件回执必须让 `causation_id`、`submission_message_id` 和
`received_payload_sha256` 精确绑定 V3 报送；V3 分析报告必须绑定同一矿井、
`correlation_id`、报送消息 ID 和修订号。通用投递确认、回复和回复回执也必须绑定
V3 report/message ID。不得仅凭 ID 格式判定关联关系。

## 5. 应用消息签名

新增的 `ten-quantity-submission-v3` 和 `analysis-report-v3` 使用 RFC 8785 JCS
规范化 `payload`，计算其 SHA-256 后，把以下 UTF-8 行按顺序用换行符连接，末尾不
追加换行：

```text
MINEGUARD-TEN-QUANTITY-EXCHANGE-HMAC-SHA256-V3
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

`signature_envelope.algorithm` 固定为 `hmac-sha256-v3`，canonicalization 固定为
`rfc8785-jcs`。签名域与 V2 的
`MINEGUARD-FIVE-QUANTITY-EXCHANGE-HMAC-SHA256-V2` 不同。V3 生产密钥必须逐矿、
逐用途独立配置和轮换；示例密钥仅供固定向量测试：

```text
example-v3-exchange-secret-not-for-production
```

| 示例 | payload SHA-256 | HMAC-SHA256 |
|---|---|---|
| `ten-quantity-submission-v3.json` | `2e22623b7c9303cd3d26698533d8c26ac39d93e803b0fb1954a64ad7d9be885a` | `18703f0be96f66afaf0bf079ec89605eb3637fda6935332ef2bdde8a6ba98f89` |
| `analysis-report-v3.json` | `0a2580eb0ece19c1de0f9b2b9ba0cdc268a3800523c76d7d01eeb735b348b6f0` | `0c81e6689535ac7e7e18ec305943dd2e7c0e5eabb77fc644e0ae18a9a38fcdf3` |

`scripts/validate_contracts.py` 必须从示例 payload 重算摘要和签名，不得信任示例中
自报的值。

## 6. V3 HTTP 运输签名

OpenAPI 路径见 `openapi/ten-quantity-exchange-v3.openapi.json`。V3 请求签名材料为：

```text
MINEGUARD-TEN-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V3
UPPERCASE-HTTP-METHOD
exact-path-with-query
X-Exchange-Sender-Id
X-Exchange-Timestamp
X-Exchange-Nonce
X-Exchange-Contract-Version
X-Exchange-Content-SHA256
```

`X-Exchange-Signature-Version` 固定为 `hmac-sha256-v3`。POST 的契约版本头必须等于
body 的精确 `contract_version`，因此显式复用的通用 V2 body 仍发送它自己的 V2
版本名；GET 固定使用 `ten-quantity-exchange-v3`。签名域仍由 URL 所属 V3 路由决定，
不能由 body 版本切回 V2。GET 使用空字节 SHA-256；查询串必须按实际 origin-form
原样签名。重放窗口、nonce、客户端—矿井绑定和 TLS 要求与 V2 相同。

V3 POST 固定向量使用：

```text
method: POST
path: /v3/ten-quantity-submissions
sender: agent-mine-qy-001
timestamp: 2026-08-01T00:05:00Z
nonce: VGVuUXVhbnRpdHlIVFRQVmVjdG9yMQ
contract: ten-quantity-submission-v3
body SHA-256: 4286f4e0bac39f090d3c3805f233a33de3f322d1c7cbcf5593438410fdd801e4
secret: example-v3-transport-secret-not-for-production
signature: 8db2b067cbe5af7cabfe40cbb0887e42ec0384cbbac48cba3cab6e4ce11b7165
```

HTTP 运输密钥和应用消息密钥必须分别配置或通过不同用途可靠派生，不得直接复用。

## 7. 版本迁移和并行运行

V2 在本次发布后冻结。任何 V2 schema、示例、固定摘要或签名向量变化都属于破坏性
修改。迁移必须按以下方式进行：

1. 监管端先公布 V3 支持能力并部署独立 V3 路由、schema 与验签域；
2. 企业端在非生产或影子模式生成 V3，并与原始凭证核对，不发送或不进入监管结论；
3. 双方完成黄金向量、拒绝用例、重放、幂等、修订链和大包测试；
4. 按矿井明确选择 V2 或 V3，不靠“最高版本猜测”自动升级；
5. 同一业务期间若双报，只能指定一个权威版本，另一个标记为影子数据，不能重复计入；
6. V2 日落必须另行公告，历史 V2 原文、schema、签名材料和重放能力永久保留。

V2 报文不能通过补五个新业务量原地转换为 V3。缺失的新量必须在 V3 中明确报
`null + quality_flags` 并附实际来源，不能由 LLM 或迁移脚本估算。V3 更正只能指向
同一 V3 修订链，不能把 V2 消息放进 `predecessor`。

## 8. Schema 之外的强制检查

双方实现至少还要检查：

- 认证客户端、信封、payload、路径资源、回执和报告始终属于同一矿井；
- 报告日按时间升序、不得重复、处于声明期间；声明期间必须与首末数据日期一致，
  允许批次跨月，也允许日期不连续；
- 三个班次结束时刻严格晚于开始时刻，并符合矿井登记班制；
- source ID 唯一，所有 `source_refs` 均存在；
- 日报精确 11 项，班次必有前 7 项且不得出现目录外字段；
- 雷管和入井人员非空时为整数；所有数值非负，
  且全部处于跨语言安全范围；
- `null` 与缺失/不可用/不适用标志一致，非空值不得带这些标志；
- 首版修订和后续修订的 causation、correlation、predecessor 血缘连续；
- V3 引擎 ID、配置摘要、输入快照、历史/同类矿快照和模块列表完整留痕；
- 不把设备直采与人工导入编码成信任等级或算法权重；
- 不把 V2/V3 双报重复计入监管统计或历史基线。
