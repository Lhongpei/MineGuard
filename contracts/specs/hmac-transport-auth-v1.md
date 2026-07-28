# HMAC 传输认证规范 V1

状态：稳定版  
标识：`hmac-sha256-v1`

本规范只约束企业智能体与监管平台之间的一次 HTTP 传输。它与单条设备观测
签名、提交载荷摘要是三个相互独立的完整性层。所有生产请求必须使用 TLS 1.2
或更高版本；HMAC 不能替代 TLS。

## 1. 必需请求头

| 请求头 | 要求 |
|---|---|
| `X-Enterprise-Client-Id` | 平台分配的客户端标识，1–128 个 ASCII 字符 |
| `X-Enterprise-Timestamp` | UTC RFC 3339 时间，如 `2026-07-27T08:05:00Z` |
| `X-Enterprise-Nonce` | 无填充 base64url；解码后至少 128 个随机比特；每次请求重新生成 |
| `X-Enterprise-Content-SHA256` | 对实际发送的原始 HTTP body 字节计算 SHA-256，小写十六进制 |
| `X-Enterprise-Signature-Version` | 固定为 `hmac-sha256-v1` |
| `X-Enterprise-Contract-Version` | 本版固定为 `enterprise-submission-v1` |
| `X-Enterprise-Signature` | 下述签名的小写十六进制 |

`Content-Encoding` 必须为空或 `identity`。客户端必须先把 JSON 完整序列化成
UTF-8 字节，再对这些字节取摘要并原样发送；签名后重新缩进、换行或转码都会导致
验签失败。GET 请求的 body 为空字节串，其摘要固定为
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。

## 2. 签名材料

使用 LF（单字节 `0x0a`）连接下列 8 行，最后一行后不追加换行：

```text
ENTERPRISE-SUBMISSION-HTTP-HMAC-SHA256-V1
{UPPERCASE_HTTP_METHOD}
{REQUEST_PATH}
{CLIENT_ID}
{TIMESTAMP}
{NONCE}
{CONTRACT_VERSION}
{LOWERCASE_BODY_SHA256}
```

`REQUEST_PATH` 是收到的、以 `/` 开头的百分号编码路径，不含 scheme、authority、
fragment 或 query。V1 定义的签名端点不接受 query 参数。路径不得在验签前解码、
合并斜杠、增删尾部斜杠或大小写归一化。反向代理必须把外部请求路径无损传递给
验签组件。

计算：

```text
signature = lowercase_hex(
  HMAC-SHA256(client_secret, UTF8(signing_material))
)
```

客户端密钥只能保存在企业侧密钥库或硬件安全模块中，不得放入提交 JSON、来源
证明、日志、LLM prompt、错误回执、浏览器存储或代码仓库。平台按 `client_id`
在服务端密钥库查找密钥。轮换期可在服务端为同一客户端短暂保留当前和前一把
密钥，逐一做常量时间比较，轮换完成后立即吊销旧密钥。

## 3. 服务端验证顺序

1. 限制请求头和 body 大小，拒绝不支持的编码。
2. 严格解析所有请求头、算法版本和契约版本。
3. 检查 `timestamp` 与服务端 UTC 时间的绝对差不超过 capabilities 公布值；
   V1 最大允许 300 秒。
4. 对实际收到的 body 字节计算 SHA-256，并与请求头做常量时间比较。
5. 按本规范重建签名材料，对 HMAC 做常量时间比较。
6. 验签成功后，以数据库唯一约束或等价原子操作消费
   `(client_id, nonce)`；已存在则拒绝为重放。
7. nonce 至少保存 600 秒，且不得短于时间容差的两倍。只有原子消费成功后才能
   产生业务副作用。
8. 再解析 JSON、验证 schema、`payload_sha256`、逐条观测签名和幂等约束。

平台不得用不同错误文案区分“客户端不存在”和“签名错误”。认证失败统一返回
HTTP 401；过期时间、重复 nonce 也返回 401。时间偏差错误可在通用错误对象的
`server_time` 中给出服务端时间，但不能回显签名材料或密钥信息。

## 4. 重放与幂等不是一回事

- nonce 防止同一个已签名 HTTP 请求在短时间内被重复执行，每次网络重试都必须
  生成新 nonce、时间和传输签名。
- `idempotency_key` 防止业务提交重复创建。重试必须保留原
  `submission_id`、`idempotency_key` 和内容。
- 相同客户端、相同幂等键、相同 `payload_sha256` 返回原回执并标记
  `duplicate`；同键不同内容返回 HTTP 409。
- nonce 校验成功不代表业务内容有效，幂等命中也不代表数据正常或合法。

## 5. 固定测试向量

以下值只用于互操作测试，绝不能用于生产：

```text
client_id:       enterprise-client-example
client_secret:   example-transport-secret-not-for-production
method:          POST
path:            /v1/enterprise-submissions
timestamp:       2026-07-27T08:05:00Z
nonce:           AAECAwQFBgcICQoLDA0ODw
contract:        enterprise-submission-v1
body:            examples/enterprise-submission-v1.json 的原始文件字节
body_sha256:     e4aab1c54596bded8e65dde774774b072f94b9d650629cc37b5eeeb2cda23c3b
signature:       1f26b2f2541ddefd388dba69fb9d601fb25a7d2448c2f0b021c198edba97795e
```

测试向量依赖示例文件的精确字节，包括文件末尾 LF。若格式化示例文件，必须重新
计算并同步更新本节。

## 6. 日志最小化

允许记录：`client_id`、签名版本、时间、nonce 的不可逆摘要、body 摘要、
submission id、结果码和 trace id。禁止记录：密钥、完整签名材料、认证请求头的
原样副本、来源文件内容、个人身份明文以及任何 LLM/API 凭据。

