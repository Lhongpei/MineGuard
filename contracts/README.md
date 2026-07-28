# 企业智能体 ↔ 监管平台独立契约

这个目录是两套相对独立系统之间唯一共享的边界规范。企业智能体负责采集、提取、
追问、校验和形成待报送草稿；企业负责人确认后才发送。监管平台独立验证来源、
物理关系、历史证据和时序证据，并独立作出监管判断。两边不得互相 import 代码，
也不得共享数据库模型。

## 文件

```text
contracts/
├── schemas/
│   ├── enterprise-submission-v1.schema.json
│   ├── submission-receipt-v1.schema.json
│   ├── error-v1.schema.json
│   ├── capabilities-v1.schema.json
│   ├── edge-telemetry-batch-v1.schema.json
│   ├── edge-telemetry-receipt-v1.schema.json
│   └── edge-telemetry-capabilities-v1.schema.json
├── openapi/
│   ├── enterprise-submission-v1.openapi.json
│   └── edge-telemetry-v1.openapi.json
├── specs/
│   ├── hmac-transport-auth-v1.md
│   ├── edge-telemetry-hmac-v1.md
│   └── governed-observation-signature-v1.md
├── examples/
├── VERSIONING.md
└── scripts/validate_contracts.py
```

矿端边缘采集服务使用独立的 `edge-telemetry-batch-v1` 边界。它面向人员、甲烷、
通风、用电、产量和火工品等只读遥测，运输签名见
`specs/edge-telemetry-hmac-v1.md`。矿端产生的本地预警仅为提示，监管平台必须用
自己的规则版本重新计算，不能直接采信矿端级别。
主通风机运行、故障和倒机分别使用三个 `ventilation.main_fan_*` 二值指标，
单位固定为 `count`、值只能为 `0` 或 `1`，避免把含义不明的厂商状态码当作
监管事实。

V1 还定义了可选 `interval` 统计窗口，以及皮带瞬时产量/速度/运行/故障、
区域人数、无卡入井、人卡不符、超时和雷管计数等聚合非 PII 指标。窗口存在时
`start/end/timezone/aggregation` 必填，`shift_code` 可选；接收端必须验证
`end > start` 且 `end <= received_at`。数据源自身健康只使用
`source.heartbeat_age_seconds`（`s`）、`source.consecutive_failures`
（`count` 整数）和 `source.missing_state`（`count` 0/1），并强制
`location_code == source_id`，不在健康指标里夹带人员、设备操作或监管结论。
炸药质量固定用 kg，雷管数量固定用 count 整数。

矿端批号固定为
`{client_id}--batch_{32位小写十六进制摘要}`。接收端必须先完成 HMAC 客户端
认证，再同时核对报文 `client_id`、矿井授权和批号的精确客户端前缀，不能只看
后缀格式。这样即使两个客户端选择相同摘要，也会落在不同命名空间，不能抢占
全局 `batch_id`。为满足 128 字符批号上限，边缘客户端编码最长 88 个字符。

JSON Schema 使用 Draft 2020-12，OpenAPI 使用 3.1。schema 是权威约束；
OpenAPI 描述 HTTP 行为；Markdown 规范补充跨字段、哈希、重放和信任边界语义。

## 信任边界

企业智能体可以：

- 从设备、ERP、地磅、库存、运输、工单和已批准文件复制数据；
- 用 OCR/LLM 定位字段，并记录模型参与范围、来源位置和置信信息；
- 做单位换算等可复核的确定性计算；
- 对缺项追问、预检物理关系并向企业人员解释风险；
- 在人工确认后使用企业传输密钥发送。

企业智能体和 LLM 不可以：

- 发明、估算、插补或“修正得更合理”任何报送数字；
- 发明检修、审批、工作票、合法例外或其他事件；
- 自己宣告数据“正常、合法、合规、已核实”；
- 替代企业负责人确认，或替代监管人员审批；
- 把模型/API 密钥写入报文、来源证明、日志、浏览器或 prompt。

所有报送业务字段都有 `field_provenance`。它至少指向来源系统、来源记录、采集
时间、获取方式和不可变证据摘要。OCR/LLM 只是获取方式，不能成为事实来源。
空数组（例如无批准事件）也必须给出证明该查询结果的来源记录。LLM 声明和人工
确认还各自带有声明审计来源。`submission_id`、发送时间、摘要等信封元数据由
企业客户端确定性生成，并应在客户端不可篡改审计日志中留痕。

监管端还要把 `approved_event_codes` 与自己备案的“矿井 + 精确统计窗口 + 完整
代码集合 + 查询证据摘要”快照作等值比较；仅逐项检查企业声称的代码不够，空数组
也不能无条件通过。

`human_confirmation.confirmed` 必须为 `true`，确认人编号、姓名和岗位必须匹配
监管端备案的企业报送权限，`confirmation_evidence_sha256` 必填。当前内置流程只
支持经认证账号点击确认；合格电子签名和企业印章必须接入独立验证器后才能启用，
不能只相信报文自报。否则它只是本地草稿，不能调用提交接口。回执的 `accepted`
仅表示进入监管接收流程，固定返回
`regulatory_outcome = not_determined_at_intake`，绝不表示监管认可。
账号点击模式下该 SHA-256 应覆盖企业端完整的不可变确认审计记录（至少包括登录
身份、时间、声明、草稿修订号和确认时内容摘要），不应只散列一句声明文本。它不
等同于监管端已经取回或验证个人数字签名；个人身份仍由企业账号会话、企业运输
签名和监管备案三者共同约束。

## 三层完整性

| 层 | 覆盖范围 | 算法 | 密钥 |
|---|---|---|---|
| 单条观测 | 设备/网关业务载荷 | 观测摘要 + HMAC-SHA256 | 每个受信来源密钥 |
| 提交载荷 | `payload`（含来源、声明和观测） | SHA-256(RFC 8785 JCS) | 无 |
| HTTP 传输 | 实际 body、方法、路径、客户端、时间、nonce、版本 | HMAC-SHA256 | 企业传输密钥 |

`payload_sha256` 必须按 RFC 8785 对 `payload` 对象规范化后计算，不包含顶层
`payload_sha256`、`submission_id`、幂等键和发送时间。HTTP body 摘要则覆盖
实际传输的完整 JSON 字节，两者不可互换。详细算法和固定向量见 `specs/`。

## 接口映射

监管端应在自己的适配层完成以下转换，不能让契约包 import 监管领域代码：

```text
payload.mine.mine_id                  -> mine_id
payload.window.window_start/end       -> window_start/window_end
payload.profile.profile_id/version    -> profile_id/profile_version
payload.operational_context           -> operational_context
payload.observations[]                -> GovernedObservation 字段
```

`enterprise`、所有 provenance、LLM 声明和人工确认作为接入审计材料完整保存。
转换成分析请求时可以从单条观测中剥离 `field_provenance`，但不得丢弃原始提交
及其摘要。来源对应的指标、容差、可靠性、矿井归属和分析参数只从监管端已审批
注册表读取，企业报文不能覆盖。

除 schema 可表达的约束外，监管端还必须验证：

- `window_end > window_start`；
- 四轴工况全部有值，并且事件代码确实来自可验证来源；
- `received_at >= observed_at`，区间成对出现且结束晚于开始；
- 观测来源归属、单位、窗口覆盖、序列号和连续修订链；
- `payload_sha256`、逐条观测签名和 HTTP HMAC；
- provenance 覆盖每个字段，数组项可追溯，LLM 影响路径与
  `acquisition_method=llm_extraction` 一致；
- 确认人有企业报送权限，确认发生在所有数据和模型处理完成之后；
- 同一客户端的提交 ID 和幂等键没有被用于不同内容。

## 幂等调用

1. 读取 `GET /v1/enterprise-submission-capabilities`。
2. 构建并本地验证 `enterprise-submission-v1`。
3. 企业负责人完成确认。
4. 固定 body 字节，计算 body 摘要和传输签名。
5. `POST /v1/enterprise-submissions`。
6. 超时重试时保留提交 ID、幂等键和内容，但生成新时间、nonce 和 HMAC。

相同内容重试返回原回执并标记 `duplicate`；同幂等键不同内容返回 409。

## 本地校验

安装独立校验依赖后，可以检查全部 JSON、引用、Draft 2020-12 实例、示例摘要
和固定向量：

```bash
python -m pip install -r contracts/requirements-validation.txt
python contracts/scripts/validate_contracts.py
```

若环境没有 `jsonschema`，脚本仍做基础检查但会明确报告跳过完整实例校验；
发布门和 CI 不得接受该跳过。契约版本策略见
[VERSIONING.md](VERSIONING.md)。
