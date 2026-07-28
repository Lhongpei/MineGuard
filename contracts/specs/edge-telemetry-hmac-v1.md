# 矿端遥测 HTTP HMAC V1

该规范只用于矿端边缘服务向县级平台回传遥测批次。边缘服务与监管平台分别实现
规范，不共享运行时代码或数据库。

请求必须包含：

```text
X-Edge-Client-Id
X-Edge-Timestamp
X-Edge-Nonce
X-Edge-Content-SHA256
X-Edge-Signature-Version: hmac-sha256-v1
X-Edge-Contract-Version: edge-telemetry-batch-v1
X-Edge-Signature
```

`X-Edge-Content-SHA256` 是实际 HTTP body 字节的 SHA-256 小写十六进制。
签名材料为下列八行以换行符连接后的 UTF-8 字节：

```text
MINE-EDGE-TELEMETRY-HTTP-HMAC-SHA256-V1
POST
/v1/edge-telemetry-batches
{client_id}
{timestamp}
{nonce}
edge-telemetry-batch-v1
{body_sha256}
```

`X-Edge-Signature` 为以该矿端客户端运输密钥计算的 HMAC-SHA256 小写十六进制。
密钥至少 32 字节，只能由矿端服务和监管接入层持有，不得交给浏览器、LLM、人工
填报页面或井下生产控制系统。运输密钥不能复用设备来源密钥。

监管端必须检查客户端与矿井绑定、时间偏差、nonce 重放、body 摘要、HMAC、
`client_id`/`mine_id` 一致性、客户端命名空间批号、批次幂等性和观测序列。
`batch_id` 必须严格等于 `{client_id}--batch_{32位小写十六进制摘要}`；不能只
检查后缀格式。相同 `batch_id` 与相同 body 摘要可返回原回执；相同 `batch_id`
对应不同内容必须返回冲突。

矿端 `local_alerts` 永远只是本地提示。监管端必须根据自己批准的规则版本和接收的
原始观测独立复算，不能把矿端级别直接写成监管结论。

## 固定互操作测试向量

下列值用于双方各自实现的自动化测试，不得用于生产：

```text
body 文件: examples/edge-telemetry-batch-v1.json 的原始字节
client_id: mine-edge-M001
timestamp: 2026-07-28T10:15:03Z
nonce: AAECAwQFBgcICQoLDA0ODw
secret UTF-8: example-edge-transport-secret-not-for-production
body_sha256: f289284d73836288cae3191eeac928b62d78c8988418e1016e4f956c08af2aab
signature: 8d56b417514d8f78c9d0e5c431880aa5eb5df49b15cbaea1ec59efe1ac0b6001
```

生产部署配置使用 Base64 表达密钥：监管端
`MINEGUARD_EDGE_CLIENTS_JSON` 中的 `secret`/`secrets` 先做严格 Base64 解码，
矿端也必须对相同配置做 Base64 解码后再计算 HMAC。固定向量为了便于人工复核，
明确标注为直接 UTF-8 测试密钥。
