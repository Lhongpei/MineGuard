# edge-telemetry-batch-v1 上行协议

边缘节点固定调用：

```text
POST /v1/edge-telemetry-batches
Content-Type: application/json
```

## 批对象

```json
{
  "schema_version": "edge-telemetry-batch-v1",
  "batch_id": "QY-MINE-001-EDGE-01--batch_0123456789abcdef0123456789abcdef",
  "client_id": "QY-MINE-001-EDGE-01",
  "mine_id": "QY-MINE-001",
  "sent_at": "2026-07-28T00:00:10.123Z",
  "sequence_start": 1001,
  "sequence_end": 1003,
  "rule_profile": {
    "profile_id": "qinyuan-safety-default",
    "version": 1,
    "sha256": "..."
  },
  "observations": [],
  "local_alerts": []
}
```

观测至少包含：

- `source_id`
- `observation_id`
- `metric_code`
- `value`
- `unit`
- `location_code`
- `observed_at`
- `received_at`
- `sequence_no`
- `revision`
- `acquisition_mode`
- `source_record_sha256`
- `quality`
- `source_record_id`
- `source_signature`、`status_code`（可空）
- `interval`（可选统计窗口）
- `manual_attestation`（仅人工补录）

`source_record_sha256` 是边缘节点收到的原始记录规范 JSON SHA-256，用于核验采集
前后的记录身份；`observation_id + revision` 是业务幂等键。新批号固定为
`{client_id}--batch_{32位摘要}`，在本地落盘并在重试期间保持不变。客户端编码
最长 88 个字符，以确保整个批号不超过合同的 128 字符上限。接收端应校验
`batch_id` 以已认证的 `{client_id}--` 开头，再按批号幂等处理。

`interval` 一旦存在，必须包含 `start/end/timezone/aggregation`，可选
`shift_code`；接收端跨字段验证 `end > start` 和 `end <= received_at`。
聚合口径仅允许窗口总量、区间增量、累计表、时点值和瞬时流率五种标准枚举。
旧观测不带 `interval` 仍保持原有报文形状。

细化白名单包括皮带瞬时产量/速度/运行/故障、区域人数、无卡入井、人卡不符和
超时计数。它们只传聚合或设备状态，不传姓名、卡号和轨迹明细。数据源自身健康
使用 `source.heartbeat_age_seconds`、`source.consecutive_failures`、
`source.missing_state`；后两者为整数计数，缺数状态只允许 0/1，并要求
`location_code` 与 `source_id` 完全相同。炸药质量使用 kg，雷管数量使用
`count` 整数，两者不得混用。

## raw-body HMAC

发送方先生成最终 UTF-8 JSON 字节，不再改写，然后计算：

```text
CONTENT_SHA256 = lowercase_hex(SHA256(raw_body))
```

签名规范串由八行 UTF-8 文本组成，每行之间只有一个 LF，末尾没有 LF：

```text
MINE-EDGE-TELEMETRY-HTTP-HMAC-SHA256-V1
POST
/v1/edge-telemetry-batches
{X-Edge-Client-Id}
{X-Edge-Timestamp}
{X-Edge-Nonce}
edge-telemetry-batch-v1
{X-Edge-Content-SHA256}
```

```text
Signature = lowercase_hex(HMAC-SHA256(shared_secret, canonical_text))
```

请求头：

| 请求头 | 值 |
|---|---|
| `X-Edge-Client-Id` | 主管部门分配的客户端编码 |
| `X-Edge-Timestamp` | UTC RFC 3339 时间 |
| `X-Edge-Nonce` | 每次 HTTP 尝试新生成的 128 位随机十六进制数 |
| `X-Edge-Content-SHA256` | 原始请求体 SHA-256 |
| `X-Edge-Signature-Version` | `hmac-sha256-v1` |
| `X-Edge-Contract-Version` | `edge-telemetry-batch-v1` |
| `X-Edge-Signature` | 上述 HMAC 小写十六进制 |

接收端应先限制请求体大小，再核对客户端、协议版本、时间窗、nonce 防重放、
body 摘要、HMAC，最后解析 JSON 和执行批次幂等。时间戳/nonce 属于单次 HTTP
请求，可在同一批次重试时变化；`batch_id` 不变。

当前独立实现位于 `mine_edge.wire`，不依赖监管平台代码。双方各自实现
`contracts/` 中的 JSON Schema 和固定签名向量，仍通过 HTTP 契约而非源码
互相依赖。

密钥推荐通过 `MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64` 配置。平台端
`MINEGUARD_EDGE_CLIENTS_JSON` 登记同一个 base64 字符串，双方分别解码为原始
字节后计算 HMAC。兼容变量 `MINE_EDGE_UPSTREAM_HMAC_SECRET` 按 UTF-8 字节解释，
禁止和 base64 变量同时配置。

## 监管回执与本地确认

HTTP 2xx 只是传输成功的必要条件，不等于边缘端已经确认送达。接收端必须在
响应体返回完整的 `edge-telemetry-receipt-v1`：

```json
{
  "schema_version": "edge-telemetry-receipt-v1",
  "receipt_id": "edge-receipt-...",
  "batch_id": "QY-MINE-001-EDGE-01--batch_...",
  "client_id": "QY-MINE-001-EDGE-01",
  "mine_id": "QY-MINE-001",
  "status": "accepted",
  "received_at": "2026-07-28T00:00:11Z",
  "body_sha256": "原始请求体的64位小写SHA-256",
  "accepted_observations": 3,
  "rejected_observations": 0,
  "regulatory_outcome": "not_determined_at_intake",
  "links": {
    "receipt": "/v1/edge-telemetry-batches/.../receipt",
    "alerts": "/v1/safety/alerts?mine_id=QY-MINE-001"
  }
}
```

边缘端使用严格 UTF-8/JSON 解析，拒绝重复字段、缺失/额外字段、类型或格式错误。
只有回执合同有效，且 `batch_id`、`client_id`、`mine_id`、`body_sha256` 与本次
请求逐项相符，才把本地批次标记为 delivered。无效 2xx 与非 2xx 一样保留原
批号并指数退避；`accepted`、`duplicate` 和 `partially_accepted` 都是合同允许
的接收状态，监管结论仍固定为 `not_determined_at_intake`。

## URL 和重定向边界

`MINE_EDGE_UPSTREAM_URL` 只接受没有 userinfo、base path、query、fragment 的
origin，程序固定追加合同路径。生产环境仅允许 HTTPS；HTTP 只允许明确的
localhost 或回环 IP 联调。响应体最多读取 64 KiB。

边缘端不会跟随 301、302、303、307、308 或其他 HTTP 重定向。重定向按失败
处理，以免 `X-Edge-*` 签名头和原始业务数据被自动发送给第二个 origin。监管
地址迁移应修改配置并重启，经人工验证后再续传，不能依赖服务端重定向。
