# 受治理观测签名规范 V1

`enterprise-submission-v1` 中的每条 `observations[]` 都是来源设备或受信网关
签发的独立观测。企业智能体负责搬运和校验，不得用传输 HMAC 密钥代替来源密钥
重新签名，更不能为了通过检查改写数值。

## 1. 被签名业务载荷

V1 载荷包括：

- `source_id`
- `observation_id`
- `value`
- `unit`
- `observed_at`
- `received_at`
- `sequence_no`
- `revision`

`sequence_no` 和 `revision` 必须是 `0..9007199254740991` 范围内的整数，
以保证 Python、JavaScript 和 RFC 8785 JCS 实现之间不会发生精度漂移。
- 非默认时的 `interval_start`、`interval_end`、`reset_before`

兼容规则是：`interval_start = null`、`interval_end = null`、
`reset_before = false` 时，这三个字段不进入观测签名载荷；一旦非默认就必须进入。
`field_provenance` 属于提交层审计材料，不进入设备观测签名。

规范 JSON 使用 UTF-8、对象键升序、无多余空格、非 ASCII 字符不转义。时间必须
带时区并归一成签名实现约定的 RFC 3339 表达。不同语言的浮点和时间序列化存在
差异，因此接入方必须运行固定向量，不能直接假定默认 JSON 序列化兼容。

```text
payload_json   = canonical_json(observation_business_payload)
payload_sha256 = lowercase_hex(SHA256(UTF8(payload_json)))
envelope       = {"payload": observation_business_payload,
                  "payload_sha256": payload_sha256}
material       = UTF8("MINEGUARD-GOVERNED-OBSERVATION-V1") + 0x00
                 + UTF8(canonical_json(envelope))
signature      = lowercase_hex(HMAC-SHA256(source_secret, material))
```

来源密钥由监管平台注册的 `source_id` 决定，不能由请求体指定。平台还必须校验
来源归属矿井、计量单位、时间窗口、序列号单调性和修订链；HMAC 有效不等于业务
语义有效。

## 2. 固定测试向量

测试密钥：`example-device-secret-not-for-production`

```json
{
  "source_id": "mine-001-main-transport",
  "observation_id": "obs-20260727-0001",
  "value": 1000.25,
  "unit": "t",
  "observed_at": "2026-07-27T08:00:00Z",
  "received_at": "2026-07-27T08:00:05Z",
  "sequence_no": 202607270001,
  "revision": 0
}
```

预期值：

```text
payload_sha256 =
78a5d9cf36c2b566511bee3364ae714a02479da6ff8b02f2b996de5574c197a9

signature =
59dc38c6346e0f955976c541a093644276c9f36830de8d4c38aee79b56e82477
```

## 3. 必须拒绝的情况

- 任一载荷字段、摘要或签名被修改；
- `received_at < observed_at`；
- 只有一个区间边界，或 `interval_end <= interval_start`；
- 来源、序号和修订号重复但内容不同；
- 修订号跳跃，或修订改变观测身份字段；
- 来源未注册、已停用、跨矿井，或单位与监管端来源注册表不符；
- `field_provenance` 缺少原始证据，即使观测 HMAC 本身有效。
