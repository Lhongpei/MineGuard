# MineGuard 企业模型凭据包 V1

本规范定义商业签发方如何为单个企业 Agent 生成一个签名、加密并绑定企业身份的模型
凭据包。协议版本固定为 `mineguard-model-credential-bundle-v1`，推荐文件扩展名为
`.mgllm`。

扩展名不参与密码学计算。接收端必须根据已签名的
`protected.contract_version` 和 `protected.bundle_kind` 判定类型，不能相信文件名。

## 1. 定位与系统边界

`.mgllm` 只在以下三类主体之间流转：

1. 商业签发方：保管模型供应商凭据和模型凭据 Ed25519 私钥；
2. 企业 Agent：验证、导入、保存并在获准的模型请求中使用凭据；
3. 模型供应商：执行 OpenAI-compatible Chat Completions 请求并按企业凭据计量。

监管 Platform 不属于这条链路。Platform 必须满足以下隔离要求：

- 不生成、导入、解密、保存、转发或备份 `.mgllm`；
- 不接触模型 API key、包外激活码、解密后的 payload 或企业 Agent 模型请求；
- 不在 `.mgprov`、`.mgreg`、`clients.json`、十量业务消息、回执或监管报告中承载它们；
- 不提供 Agent 向 Platform 上传 `.mgllm` 或模型 key 的 API；
- 不因企业模型凭据失效而停止独立接收、验签和分析十量数据。

`.mgllm` 与成对部署包、政府交换 HMAC、Windows Authenticode/Linux 包签名是相互独立的
信任域。模型签发私钥不得复用部署包私钥、代码签名私钥或政府交换密钥。

## 2. 安全目标与非目标

V1 的目标是：

- API key 不以明文出现在交付包、普通配置文件、界面或日志中；
- 未持有受信签发私钥的人不能在未修改正式 Agent 的前提下替换 API key、供应商地址、
  模型或调用策略；
- 包只能导入到已完成正式企业接入且身份完全匹配的 Agent；
- 每次模型调用前都重新检查有效期、主体、版本和供应商配置摘要；
- 每个企业使用独立的供应商 key、配额、告警和吊销范围。

V1 不是 DRM，也不承诺抵御完全控制企业主机的攻击者。拥有本机管理员/root、调试器、
进程转储、TLS 注入能力或可替换 Agent 二进制/信任库的人，仍可能从运行内存取得 key、
绕过校验或改写请求。因此本协议主要防止误操作、普通用户查看、复制交付文件和随意替换
配置；主机加固、代码签名、服务账号 ACL、供应商侧限额和吊销仍是必要控制。

## 3. JSON 规范化

本协议的哈希、AAD 和签名统一使用以下规范化函数：

```python
json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

即 UTF-8、对象键按 Unicode 字符串顺序排序、无多余空白、中文不转义，并拒绝 NaN 和
Infinity。V1 的受保护对象和 payload 不依赖输入文件的键顺序。本规则是 MineGuard
模型凭据 V1 的专用规范化，不宣称等同 RFC 8785。

解析器必须拒绝重复对象键、未知字段、非 UTF-8、超出 schema 范围的值和超过实现上限
的输入。信封文件最大 2 MiB；解密后的规范 JSON 最大 1 MiB。

## 4. 签发输入：非敏感 profile 与独立 key 文件

签发 profile 精确为：

```json
{
  "credential_id": "33333333-3333-4333-8333-333333333333",
  "credential_version": 1,
  "subject": {
    "mine_id": "MINE-QY-001",
    "system_id": "agent-mine-qy-001",
    "party_id": "operator-qy-001",
    "pair_id": "11111111-1111-4111-8111-111111111111"
  },
  "provider": {
    "provider_id": "example-openai-compatible-provider",
    "protocol": "openai-compatible-chat-completions",
    "base_url": "https://api.example.invalid/v1",
    "model": "example-coal-model",
    "capabilities": ["chat", "coal-news-search", "extraction"],
    "timeout_seconds": 20,
    "max_retries": 2
  },
  "install_before": "2026-08-18T08:00:00Z",
  "runtime_not_after": "2026-11-11T08:00:00Z",
  "issuer_id": "example-model-credential-authority",
  "issuer_key_id": "example-model-ed25519-2026q3",
  "issuer_key_epoch": 1
}
```

profile 是可审批、可版本化的非敏感输入，绝不能包含 `api_key` 或其他任意扩展配置。
API key 必须通过另一个仅含原始 ASCII key 的秘密文件、受控标准输入或操作系统秘密存储
单独交给签发器；不得作为命令行参数，以免进入 shell 历史和进程列表。秘密文件只能由
签发账号读取，签发后应安全删除或回收到秘密管理系统。

`credential_id` 是规范小写 UUIDv4，在同一企业的轮换链上保持稳定；`bundle_id` 则在每
个版本重新生成。`credential_version` 从 1 开始，每次轮换精确增加 1。`subject` 必须
来自已经验签并成功导入的企业 `.mgprov` 身份，四个字段均不能由现场人员临时填写或通过
模型推断；其中 `pair_id` 必须等于该 `.mgprov` 的受保护配对 ID。

`provider` 的字段语义如下：

| 字段 | 规则 |
|---|---|
| `provider_id` | 签发方批准的供应商逻辑标识，进入审计和逐次调用检查 |
| `protocol` | 固定为 `openai-compatible-chat-completions` |
| `base_url` | 规范 HTTPS URL；禁止 userinfo、query、fragment，可包含批准的路径前缀 |
| `model` | 签发方批准并锁定的模型标识 |
| `capabilities` | 排序、去重、非空，且只能取 `chat`、`coal-news-search`、`extraction` |
| `timeout_seconds` | `1..120` 秒 |
| `max_retries` | `0..5`，不含首次请求 |

`base_url` 必须使用小写 HTTPS scheme/主机、规范端口且省略默认 `443`；禁止空主机、空白、
控制字符、百分号编码、重复斜线、`.`/`..` 路径段和末尾 `/`。路径可以为空，也可以是
类似 `/v1` 的非空基础路径前缀。运行时必须按同一规则复算规范形式，并拒绝凭据或调用
响应把请求重定向到另一个地址。

## 5. 顶层信封与受保护字段

顶层对象精确为：

```json
{
  "protected": {},
  "ciphertext": "base64url-no-pad",
  "signature": "base64url-no-pad"
}
```

`ciphertext` 是 AES-GCM 密文后直接附加 16-byte tag，再作 base64url 无填充编码。
`signature` 是 64-byte Ed25519 签名的 base64url 无填充编码。

`protected` 精确包含：

```json
{
  "contract_version": "mineguard-model-credential-bundle-v1",
  "bundle_kind": "enterprise-agent-model-credential",
  "bundle_id": "UUIDv4",
  "credential_id": "33333333-3333-4333-8333-333333333333",
  "credential_version": 1,
  "issued_at": "2026-08-11T08:00:00Z",
  "install_before": "2026-08-18T08:00:00Z",
  "runtime_not_after": "2026-11-11T08:00:00Z",
  "issuer_id": "example-model-credential-authority",
  "issuer_key_id": "example-model-ed25519-2026q3",
  "issuer_key_epoch": 1,
  "subject": {
    "mine_id": "MINE-QY-001",
    "system_id": "agent-mine-qy-001",
    "party_id": "operator-qy-001",
    "pair_id": "11111111-1111-4111-8111-111111111111"
  },
  "payload_sha256": "64-char-lowercase-hex",
  "provider_config_sha256": "64-char-lowercase-hex",
  "encryption": {
    "algorithm": "aes-256-gcm",
    "kdf": "scrypt",
    "salt": "16-byte-base64url-no-pad",
    "n": 16384,
    "r": 8,
    "p": 1,
    "nonce": "12-byte-base64url-no-pad"
  }
}
```

`bundle_id` 与 `credential_id` 都是规范小写 UUIDv4；前者每次签发都更新，后者跨轮换
保持稳定。`system_id` 是 Agent 实例的逻辑身份绑定，`pair_id` 把模型凭据绑定到已验签
的 `.mgprov` 配置对；二者都不是硬件指纹，物理机器绑定由导入后的存储机制另行提供。

时间全部是无小数秒的 UTC `Z`。签发器和导入器必须满足：

```text
issued_at < install_before <= runtime_not_after
issued_at <= now + 5 minutes
```

当 `now >= install_before` 时不得首次导入或更新；当 `now >= runtime_not_after` 时不得
发起任何模型请求。边界时刻本身即为失效，不使用本地时区猜测。

## 6. 解密后的 payload

payload 精确为：

```json
{
  "kind": "enterprise-agent-model-credential",
  "bundle_id": "UUIDv4",
  "credential_id": "33333333-3333-4333-8333-333333333333",
  "credential_version": 1,
  "subject": {
    "mine_id": "MINE-QY-001",
    "system_id": "agent-mine-qy-001",
    "party_id": "operator-qy-001",
    "pair_id": "11111111-1111-4111-8111-111111111111"
  },
  "provider": {
    "provider_id": "example-openai-compatible-provider",
    "protocol": "openai-compatible-chat-completions",
    "base_url": "https://api.example.invalid/v1",
    "model": "example-coal-model",
    "capabilities": ["chat", "coal-news-search", "extraction"],
    "timeout_seconds": 20,
    "max_retries": 2
  },
  "api_key": "EXAMPLE_ONLY_NOT_A_REAL_PROVIDER_CREDENTIAL_2026"
}
```

签发器和导入器必须验证：

```text
payload.kind == protected.bundle_kind
payload.bundle_id == protected.bundle_id
payload.credential_id == protected.credential_id
payload.credential_version == protected.credential_version
payload.subject == protected.subject
protected.payload_sha256 == SHA256(canonical_json(payload))
protected.provider_config_sha256 == SHA256(canonical_json(payload.provider))
```

`api_key` 必须是 16 至 4096 个可打印 ASCII 字符，不得有前后空白、换行或 NUL。它是
每个企业独立的供应商凭据，不能与其他企业、测试环境或签发工具自身共用。

## 7. 加密、AAD 与签名

包外激活码必须由 CSPRNG 生成 32 bytes，再编码为恰好 43 个 base64url 无填充字符。
不得执行 `strip()`、Unicode 归一化或大小写转换；接收端只可从受保护输入移除一个末尾
`LF` 或 `CRLF`。激活码不得进入 JSON、文件名、日志、命令行、发行清单或二维码旁明文。

AES key 固定按以下方式派生：

```text
scrypt(
  password = activation_code 的原始 ASCII bytes,
  salt = base64url_decode(protected.encryption.salt),
  n = 16384,
  r = 8,
  p = 1,
  dklen = 32
)
```

salt 每包独立随机 16 bytes，nonce 每包独立随机 12 bytes；同一派生 AES key 下不得重复
nonce。AES-256-GCM 的明文是 `canonical_json(payload)`，AAD 是
`canonical_json(protected)`。解码后的 ciphertext 至少 17 bytes，仅有 16-byte tag 的
值必须在执行 KDF 前拒绝。

Ed25519 签名输入精确为：

```text
canonical_json({"protected": protected, "ciphertext": ciphertext})
```

这里的 `ciphertext` 是顶层原始 base64url 字符串，不是解码后的 bytes。导入器必须先做
大小、JSON、schema、base64url 和时间的低成本检查，再验证 Ed25519；只有签名通过后才
提示激活码和执行 scrypt。认证失败统一报告“激活码错误或包损坏”，不能暴露内部差异。

## 8. 固定发行方信任锚

Agent 使用由正式签名安装包预置的只读信任库。逻辑格式为：

```json
{
  "format": "mineguard-model-issuer-trust-store-v1",
  "issuers": [
    {
      "issuer_id": "example-model-credential-authority",
      "issuer_key_id": "example-model-ed25519-2026q3",
      "issuer_key_epoch": 1,
      "public_key_pem": "PEM-encoded Ed25519 public key",
      "public_key_sha256": "SHA256-of-SPKI-DER-lowercase-hex"
    }
  ]
}
```

指纹固定为 `SHA-256(SubjectPublicKeyInfo DER)`。信任库必须包含 1 至 32 个发行方并按
`issuer_key_id` 字典序排列；`issuer_id + issuer_key_id`、全局 `issuer_key_id` 和 SPKI
指纹均不得重复。同一 `issuer_id` 下每一把不同公钥必须分配唯一、严格正整数
`issuer_key_epoch`；新密钥世代必须大于旧密钥世代。`public_key_pem` 必须是规范
SubjectPublicKeyInfo PEM、只能包含 Ed25519
公钥且不得包含私钥，解析后的 SPKI 指纹必须与登记值固定时间比较。信任库不能来自
`.mgllm`、包旁文件、profile、HTTP 响应或企业输入；把恶意包和自签公钥一起替换必须失败。

信任库更新属于 Agent 正式发行流程，必须经过代码签名/软件包签名、版本审批和审计。
Windows 上使用安装目录 ACL 只允许管理员和 Agent 服务身份读取、只允许受控安装器写入；
Linux 上至少由 root 拥有并设置 `0644` 或更严格权限，普通 Agent 账号不得写入。完全控制
主机的管理员仍能替换二进制和信任库，这是第 2 节明确接受的边界。

## 9. 生成与导入流程

签发器按以下顺序生成：

1. 严格校验非敏感 profile；从独立秘密通道读取 API key；
2. 核对企业正式身份和该 `credential_id` 的上一版本；
3. 生成新的 `bundle_id`、salt、nonce 和包外激活码；
4. 构造 payload，计算 payload 与 provider 配置摘要；
5. 构造 `protected`，以它为 AAD 加密规范 payload；
6. 签名规范信封子集并自验签；
7. 输出 `.mgllm`、激活码交接记录和不含秘密的签发审计。

企业 Agent 按以下顺序导入：

1. 确认已经成功导入正式 `.mgprov`，并读取其已验证主体；
2. 以拒绝重复键的解析器读取文件，执行大小、schema 和固定算法参数检查；
3. 根据本地信任库定位发行方公钥，核对受签名 `issuer_key_epoch`，再验证指纹和 Ed25519 签名；
4. 核对时间和 `subject` 四个字段与当前已验签 `.mgprov` 主体完全一致；
5. 核对版本：首次必须是 1，更新必须是同一 `credential_id` 的上一版本加 1；
6. 通过非回显安全输入取得激活码，派生 AES key 并解密；
7. 严格校验 payload、跨层字段和两个 SHA-256；
8. 按第 11 节保护 API key，原子替换已安装记录并持久化最高版本/包摘要；
9. 清理激活码、派生 key 和明文临时缓冲，写入不含秘密的审计结果。

导入不能自动启动模型调用、提交草稿、签名或向政府发送数据。失败时不得覆盖当前可用
版本。相同 `bundle_id` + 相同摘要可以幂等返回已导入；相同 ID 不同内容必须拒绝并告警。

## 10. 正式模式的配置闭包与逐次调用检查

正式模式启用 `.mgllm` 后，以下明文模型配置族只要任一项存在就必须拒绝启动或拒绝启用
LLM，不能静默选择优先级：

- `MINEGUARD_AGENT_API_KEY`、`MINEGUARD_AGENT_BASE_URL`、
  `MINEGUARD_AGENT_MODEL`、`MINEGUARD_AGENT_TIMEOUT_SECONDS`、
  `MINEGUARD_AGENT_MAX_RETRIES`；
- 兼容期旧名 `DEEPSEEK_API_KEY`、`DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL`、
  `DEEPSEEK_TIMEOUT_SECONDS`、`DEEPSEEK_MAX_RETRIES`。

前端、HTTP API、数据库通用设置、插件、命令行和进程环境都不得覆盖已签名的 API key、
base URL、模型、超时或重试次数。无合法 `.mgllm` 且无获准开发模式明文配置时，LLM
功能应显示“未授权/不可用”，但 CSV 导入、十量草稿、人工复核、签名报送和本地规则校验
继续工作。

只读状态与审计摘要中的规范字段名同样固定为 `base_url`；不得重新引入过渡字段
`api_origin`，也不得在状态接口中返回 API key。

模型提供器必须在首次请求和每一次重试发送前调用配置守卫，至少重新检查：

- 已安装记录仍存在且摘要、版本、主体与已加载配置一致；
- `now < runtime_not_after`；
- 当前 provider 配置规范摘要等于 `protected.provider_config_sha256`；
- 当前企业正式主体仍等于包中 `subject`。

能力检查同样 fail-closed：对话只能使用 `chat`，结构化填报提取只能使用 `extraction`，
联网煤炭新闻检索与总结链路只能使用 `coal-news-search`。缺少对应已签名 capability 时不得
调用模型，也不能把一个能力的许可泛化成所有模型功能。

守卫失败不得打开网络连接。HTTP 3xx 一律拒绝，不能把 Bearer Authorization 转发到
Location；响应、异常、追踪和重试日志不得包含 key 或完整 Authorization header。

## 11. 导入后存储的真实安全边界

`.mgllm` 解密后不长期保存激活码或派生 AES key。已安装记录分为 lock、受保护的 API key
secret store 和由 lock 固定路径派生的 anti-rollback state。state 至少保存
`credential_id`、已接受最高版本、`bundle_id`、规范 envelope/payload SHA-256、issuer key
epoch 和接受时间，并以当前 API key 做域分离 HMAC。运行时必须同时校验三者；state 缺失、
HMAC 失败或版本/摘要不一致时关闭全部模型出站，但不能阻断 CSV、复核、签名和报送主线。

### 11.1 Windows

Windows 使用 DPAPI `LocalMachine` 保护 API key。该模式提供物理机器绑定：直接把密文
记录复制到另一台机器不能解密。但 `LocalMachine` 不是同机用户隔离；同一主机上能读取
密文并调用 DPAPI 的主体可能解密。因此文件 ACL 才是同机主要边界：应使用专用低权限
服务身份/服务 SID，只允许该服务和受控管理员读取，普通登录用户不得访问数据目录。

本机管理员仍能接管服务、读取进程内存或修改 ACL，DPAPI 不解决这一威胁。备份迁移到新
机器时不能直接复制已安装 DPAPI blob，应在新机完成正式接入后重新导入一个新版本包。

### 11.2 Linux

Linux V1 的 `0600` 文件是由专用服务账号拥有的明文 JSON，只提供 owner/root 文件权限
隔离；它不是加密、不是硬件绑定，也不能抵御 root。父目录应为 `0700`，服务应使用专用
无登录账号，并禁止其他进程读取其数据目录。

若部署要求真正的 Linux 静态加密或硬件绑定，必须另行接入操作系统 keyring、TPM、HSM
或企业秘密管理器，并新增明确协议版本；不得把 `0600` 宣传成等同 DPAPI 的加密。

## 12. 轮换、限额和吊销

每个企业必须在模型供应商处创建独立 API key，不得按矿组、地区或所有客户共享。供应商
侧至少配置企业级月度硬限额、速率限制、异常调用告警、账单标签和独立吊销能力。企业
更换、欠费、泄露或离场时，只吊销该企业 key，不影响其他企业和政府 Platform。

轮换保持 `credential_id`、`subject` 和 `issuer_id` 不变，生成新的 `bundle_id`，版本精确
加 1；可更换 API key、provider 配置、有效窗口和已受信的 `issuer_key_id`。换用新签发
公钥时 `issuer_key_epoch` 必须严格增加；同一公钥续签允许保持相等，任何较低 epoch 都必须
在签发和导入两端拒绝。导入成功后立即停止使用旧 key，不保留自动回退；确认新版本可用后
在供应商侧吊销旧 key。

删除本地凭据只能立即禁用该 Agent 的 LLM，不能替代供应商吊销。`runtime_not_after` 是
离线强制失效边界；需要提前紧急吊销时，必须在供应商侧撤销 key，并向企业发布更高版本
或执行本地禁用。V1 不定义在线吊销列表。

Agent 应持久化该 `credential_id` 已接受的最高版本和包摘要并拒绝降级。完全控制文件系统
的管理员可以同时回滚程序、数据库和防回滚状态，所以供应商吊销与短有效期才是最终控制，
本地版本状态不能被描述为对管理员的绝对防回滚。

## 13. 交付、审计与泄露处置

`.mgllm` 和激活码应通过两个独立渠道交付。签发私钥只存在于商业签发环境或 HSM；不得
发给企业或政府。企业收到的是受信发布版 Agent、企业专属 `.mgllm` 和包外激活码，政府
只收到与模型无关的 `.mgreg`。

允许记录的审计字段包括：动作、结果、时间、操作者、`bundle_id`、`credential_id`、版本、
主体、issuer 标识、payload/provider 摘要和错误类别。禁止记录 API key、激活码、派生
key、解密 payload、Authorization header、完整请求/响应正文或 DPAPI 明文。

发现疑似泄露时应先在供应商侧吊销企业 key，再停止企业 LLM、保全不含秘密的审计、签发
更高版本并调查主机。不能仅靠重新打包同一 API key 处置泄露。

## 14. 示例与互操作测试

权威结构文件为：

- [`model-credential-profile-v1.schema.json`](../schemas/model-credential-profile-v1.schema.json)
- [`model-credential-payload-v1.schema.json`](../schemas/model-credential-payload-v1.schema.json)
- [`model-credential-bundle-v1.schema.json`](../schemas/model-credential-bundle-v1.schema.json)
- [`model-issuer-trust-store-v1.schema.json`](../schemas/model-issuer-trust-store-v1.schema.json)

`contracts/examples/` 中的 profile、payload、bundle 和 trust store 只用于结构与跨字段
校验。示例 `api_key` 是带 `EXAMPLE_ONLY` 的明确非生产哨兵；bundle 的 ciphertext 和
signature 是全 `A`、不可解密、不可验签的长度占位符。示例 provider 使用保留的
`example.invalid` 域，示例不得复制到生产环境，也不能被签发器或 Agent 当作有效凭据接受。

实现至少应覆盖以下反例：未知/重复字段、错误 UUID 版本、未来签发、安装或运行边界失效、
错矿/错系统/错运营方、未知发行方、替换自签公钥、签名篡改、tag-only ciphertext、错误
激活码、payload/provider 摘要不一致、版本跳跃/降级、正式模式明文变量冲突、重试期间
过期、HTTP 重定向以及日志/异常中出现秘密。
