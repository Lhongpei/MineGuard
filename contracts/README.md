# 企业智能体 ↔ 监管平台独立契约

这个目录是两套相对独立系统之间唯一共享的边界规范。企业智能体负责采集、提取、
追问、校验和形成待报送草稿；企业负责人确认后才发送。监管平台独立验证来源、
物理关系、历史证据和时序证据，并独立作出监管判断。两边不得互相 import 代码，
也不得共享数据库模型。

## 独立部署边界：成对部署包 V1

正式接入不再要求现场人员手写 Agent 环境变量和 Platform `clients.json`。中立契约新增
`mineguard-provisioning-bundle-v1`：签发工具为每座矿、每个单调递增配置版本同时生成
企业 `.mgprov` 与 Platform `.mgreg` 两份包。二者共享唯一 `pair_id`，但各有独立
`bundle_id`、salt、nonce 和建议独立交接的包外激活码。

顶层信封固定为 `{protected,ciphertext,signature}`。payload 使用 AES-256-GCM，密钥由
包外高熵激活码经固定 scrypt 参数派生；AAD 是规范化 `protected`。Ed25519 签名覆盖
规范化 `{protected,ciphertext}`。密钥不进入 EXE，不为每矿维护代码分支；代码签名和
部署包签名是两套独立信任链。

企业 payload 只允许政府交换、固定企业身份/同类矿分组和生产策略 allowlist，全部键
都进入运行时锁。模型 API、用户密码/摘要、数据库、命令和自动监听目录禁止进入包。
Platform payload 是一条严格客户端登记项和 Platform 身份，并用签名摘要锁住 registry。
过期时间只约束首次导入/更新，不能让已导入配置日后自动停服；错矿、降级、版本冲突和
同 bundle ID 不同内容全部 fail-closed。

完整算法、安全边界、导入顺序和示例限制见
[`specs/provisioning-bundle-v1.md`](specs/provisioning-bundle-v1.md)。四个示例中的信封
密文/签名是不可解密、不可验签的结构占位符，不能作为生产材料。

## 企业专属模型授权包 `.mgllm`

模型 API 不进入企业/政府成对部署包，而由独立的
`mineguard-model-credential-bundle-v1` 投递。商业签发方用非敏感 profile 和另行读取的
供应商 API key，为每个企业生成独立 `.mgllm`；企业 Agent 验证预置 Ed25519 信任锚、
企业主体及 `.mgprov pair_id`、递增版本、有效窗口和配置摘要后才能使用。供应商身份、
API 地址、模型、`chat|extraction|coal-news-search` 能力、超时和重试策略与 key 一并受
签名保护，正式模式不得用普通环境变量或前端覆盖。

监管 Platform 完全不参与这条链路：不生成、导入、解密、保存或转发 `.mgllm`、API key
和激活码，也没有接收它们的接口。每个企业必须使用供应商侧独立 key、硬限额、告警、
账单标签和吊销范围，不能由政府持有一个共享 key。

Windows 导入后使用 DPAPI `LocalMachine`，它提供跨机器不可移植性，但同机隔离仍主要
依赖专用服务身份和文件 ACL；Linux V1 的 `0600` 是明文文件权限隔离，不是静态加密或
硬件绑定。拥有本机管理员/root 和可修改正式程序能力的人不在此包的绝对防护范围内。

完整格式、密码学顺序、配置闭包、逐次调用检查、存储边界和轮换/吊销规则见
[`specs/model-credential-bundle-v1.md`](specs/model-credential-bundle-v1.md)。profile、
payload、bundle 和发行方 trust store 四个示例只使用保留的 `example.invalid` 地址、明确
的 `EXAMPLE_ONLY` 非生产 key 哨兵及不可解密、不可验签的信封占位符。发行版信任库格式
固定为 `mineguard-model-issuer-trust-store-v1`。

## 当前目标契约：十量交换 V3

V3 在不改写 V2 的前提下，把监管业务组扩展为风量、电量、火工品量、入井人员量、
产量、开采量、销售量、运输量、洗煤量和开票量。十个业务组由十一个原子字段表达；
火工品仍分别保存雷管数量和炸药质量，不能相加成无单位总量。

11 个规范原子字段固定为 `ventilation_m3_min`、`electricity_kwh`、
`detonators_count`、`explosives_kg`、`mine_entry_persons`、`production_t`、
`extraction_t`、`sales_t`、`transport_t`、`wash_feed_t` 和
`invoiced_quantity_t`。日报必须包含全部 11 项；每班必须包含前 7 项，后 4 项可省略，
也可用 `null + not_applicable` 明确表示该班次口径不适用。

其中 `sales_t` 是以完成销售出库并交付为确认点的吨数，`transport_t` 是出矿对外运输净吨数，
`wash_feed_t` 是入洗原煤吨数，`invoiced_quantity_t` 是本期已开具正常/蓝票所载的
煤炭实物吨数，不是金额、税额或红冲净额。全部 11 项非空数值必须非负；红字发票、
退货和折让在企业来源系统作为辅助逐笔事件单列；当前 V3 主报文不承载这些事件。

V3 本次新增：

- `ten-quantity-submission-v3`
- `analysis-report-v3`
- `ten-quantity-exchange-v3` HTTP 边界

提交路径固定为 `/v3/ten-quantity-submissions`。V3 新增消息和 HTTP 运输分别使用
独立 V3 签名域与 `hmac-sha256-v3`，不能拿 V2 域作失败回退。接收回执、风险落库
确认、企业回复和回复回执继续使用不可变 V2 通用消息，并通过消息 ID、报告 ID 和
correlation 与 V3 流程绑定；这些复用消息仍按自身 V2 应用签名域验签。

权威字段、单位、日/班次空值语义、签名材料和双版本迁移规则见
[`specs/ten-quantity-exchange-v3.md`](specs/ten-quantity-exchange-v3.md)，HTTP 路径见
[`openapi/ten-quantity-exchange-v3.openapi.json`](openapi/ten-quantity-exchange-v3.openapi.json)。

## 保留兼容契约：五量双向交换 V2

V2 是“两套运行软件、一个煤矿一个智能体、政府唯一算法”的目标边界：企业智能体
发送整月逐日/班次五量，政府返回签名回执和唯一算法报告；企业主动拉取风险，智能体
辅助解释后由企业人员确认回复，政府再返回只表示“已记录”的签名回执。

V2 六类消息分别为：

- `five-quantity-submission-v2`
- `intake-receipt-v2`
- `analysis-report-v2`
- `risk-delivery-ack-v2`
- `enterprise-risk-response-v2`
- `response-receipt-v2`

五个业务组固定为风量 `airflow`、电量 `electricity`、火工品量
`blasting_materials`、入井人员量 `mine_entry_personnel` 和产量 `production`。
它们由六个规范原子字段表达：`ventilation_m3_min`、`electricity_kwh`、
`detonators_count`、`explosives_kg`、`mine_entry_persons` 和 `production_t`。
火工品是一个业务量，但雷管数量与炸药质量单位不同，必须分别保存且不得求和成
无单位“火工品总量”。`mine_entry_persons` 是统计窗口内的非负整数并按班次求和，
不是企业用工总人数，也不是某时点井下人数快照。

设备直采与人工导入是并列合法来源，`acquisition_mode` 只用于追溯，不能形成信任
等级或算法权重。一个月报包含 `days[]`，每天同时保留 `daily_total` 和零点、八点、
四点三个班次；缺失值使用 `null + quality_flags`，不得填零。

V2 的完整跨字段、签名、幂等、修订、求解器/时序模块和风险闭环规则见
[`specs/five-quantity-exchange-v2.md`](specs/five-quantity-exchange-v2.md)，HTTP 路径见
[`openapi/five-quantity-exchange-v2.openapi.json`](openapi/five-quantity-exchange-v2.openapi.json)。
旧 V1 和 edge telemetry 文件仅作为迁移期历史兼容材料保留，不定义新的目标运行
软件，也不得让独立 edge 服务绕过企业智能体直接进入 V2 主线。

企业 Agent 的可选伴随连接器使用独立的
[`enterprise-autofill-ingestion/v1`](specs/enterprise-autofill-hmac-v1.md) 协议。它只在
企业内部形成待复核稿，不是企业到政府的交换消息；机器 principal 没有确认或报送
权限。该协议放在中立目录是为了让 connector 与 Agent 独立实现和做固定向量校验，
二者运行时仍不得 import 本目录。内容不变、空结果、采集错误和文件稳定等待使用同一
规范中的 `enterprise-source-health/v1` 状态消息；健康消息没有业务值，不能改草稿或
把“没看到记录”解释成删除。

## 文件

```text
contracts/
├── schemas/
│   ├── provisioning-bundle-v1.schema.json
│   ├── enterprise-agent-provisioning-payload-v1.schema.json
│   ├── platform-client-registration-payload-v1.schema.json
│   ├── model-credential-bundle-v1.schema.json
│   ├── model-credential-profile-v1.schema.json
│   ├── model-credential-payload-v1.schema.json
│   ├── model-issuer-trust-store-v1.schema.json
│   ├── exchange-common-v3.schema.json
│   ├── ten-quantity-submission-v3.schema.json
│   ├── analysis-report-v3.schema.json
│   ├── exchange-common-v2.schema.json
│   ├── five-quantity-submission-v2.schema.json
│   ├── intake-receipt-v2.schema.json
│   ├── analysis-report-v2.schema.json
│   ├── risk-delivery-ack-v2.schema.json
│   ├── enterprise-risk-response-v2.schema.json
│   ├── response-receipt-v2.schema.json
│   ├── enterprise-autofill-ingestion-v1.schema.json
│   ├── enterprise-source-health-v1.schema.json
│   ├── enterprise-submission-v1.schema.json
│   ├── submission-receipt-v1.schema.json
│   ├── error-v1.schema.json
│   ├── capabilities-v1.schema.json
│   ├── edge-telemetry-batch-v1.schema.json
│   ├── edge-telemetry-receipt-v1.schema.json
│   └── edge-telemetry-capabilities-v1.schema.json
├── openapi/
│   ├── ten-quantity-exchange-v3.openapi.json
│   ├── five-quantity-exchange-v2.openapi.json
│   ├── enterprise-submission-v1.openapi.json
│   └── edge-telemetry-v1.openapi.json
├── specs/
│   ├── provisioning-bundle-v1.md
│   ├── model-credential-bundle-v1.md
│   ├── ten-quantity-exchange-v3.md
│   ├── five-quantity-exchange-v2.md
│   ├── enterprise-autofill-hmac-v1.md
│   ├── hmac-transport-auth-v1.md
│   ├── edge-telemetry-hmac-v1.md
│   └── governed-observation-signature-v1.md
├── examples/
├── VERSIONING.md
└── scripts/validate_contracts.py
```

## 历史 V1 与 edge 契约专用说明

以下内容只说明保留的 V1/edge 兼容契约，不是 V3 报文形状或 V3 调用步骤。V3 不使用
`field_provenance`、`approved_event_codes`、`payload.window/profile/observations` 或
`confirmation_evidence_sha256`；V3 分别使用 `payload.sources`、measurement 的
`source_refs`、`human_confirmation.content_sha256`、`signature_envelope` 和 `/v3/*`
路径，具体以十量 V3 schema 与规范为准。

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

### V1 信任边界

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

### V1 三层完整性

| 层 | 覆盖范围 | 算法 | 密钥 |
|---|---|---|---|
| 单条观测 | 设备/网关业务载荷 | 观测摘要 + HMAC-SHA256 | 每个受信来源密钥 |
| 提交载荷 | `payload`（含来源、声明和观测） | SHA-256(RFC 8785 JCS) | 无 |
| HTTP 传输 | 实际 body、方法、路径、客户端、时间、nonce、版本 | HMAC-SHA256 | 企业传输密钥 |

`payload_sha256` 必须按 RFC 8785 对 `payload` 对象规范化后计算，不包含顶层
`payload_sha256`、`submission_id`、幂等键和发送时间。HTTP body 摘要则覆盖
实际传输的完整 JSON 字节，两者不可互换。详细算法和固定向量见 `specs/`。

### V1 接口映射

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

### V1 幂等调用

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
