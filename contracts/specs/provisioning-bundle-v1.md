# MineGuard 成对部署包 V1

本规范定义同一套签名程序如何为一座煤矿生成两份相互对应、但分别交给企业 Agent
和监管 Platform 的部署包。它解决的是身份、政府交换地址、双 HMAC 和正式运行策略的
一次性配置与后续受控更新，不改变十量 V3 业务契约。

协议版本固定为 `mineguard-provisioning-bundle-v1`。推荐文件扩展名是：

- 企业 Agent：`.mgprov`
- 监管 Platform：`.mgreg`

扩展名不参与密码学计算；接收端必须根据已签名的 `protected.bundle_kind` 判定类型，
不能相信文件名。

## 1. 安全目标与边界

一座矿使用一个唯一 `pair_id`，配对生成：

1. `enterprise-agent-provisioning`：企业身份、锁定策略和政府交换配置；
2. `platform-client-registration`：同一矿在监管端的客户端登记和 Platform 身份。

两份包的业务身份、密钥和版本必须一致。所有企业继续运行同一份代码签名二进制；
不得复制源码、维护“太岳矿分支”或把每矿密钥编译进 EXE。每矿部署包可以不同，程序
二进制摘要应相同。

部署包提供两种独立保护：

- AES-256-GCM 使用包外激活码派生的密钥保护配置机密性和密文完整性；
- Ed25519 使用部署签发机构密钥证明包的来源和全部信封内容。

Windows Authenticode、Linux 包签名等**代码签名**证明程序发布者；本规范的 Ed25519
**部署包签名**证明某矿配置由受信 provisioning authority 签发。二者密钥、信任库、
轮换、吊销和审计必须分开，任何一个都不能替代另一个。

本包不是通用远程执行或秘密分发容器。企业 `config` 只允许 schema 明列的企业身份、
五项正式分组、三项生产策略、政府交换地址/身份和双 HMAC 及其轮换项。以下内容禁止
进入包：

- LLM、搜索或其他外部服务/API 密钥；
- 用户密码、密码摘要、会话密钥或首次管理员凭据；
- Agent 数据库路径、数据库内容或备份密钥；
- 命令、脚本、服务参数、任意环境变量或插件；
- 自动监听目录、设备凭据、Connector 配置和原始企业数据。

`ENTERPRISE_AGENT_PUBLIC_ORIGIN` 和 `PLATFORM_V3_CA_BUNDLE` 是唯一纳入 allowlist
的部署路径/入口例外。前者必须是无路径的 HTTPS origin；后者只锁定本机 CA 文件位置，
**不把 CA 文件内容装入本包**。安装介质仍须独立核对 CA 文件 SHA-256、批准的证书链和
文件 ACL，导入器必须拒绝缺失、可被普通用户写入或不符合批准摘要的 CA 文件。

## 2. JSON 规范化

本协议所有哈希、AAD 和签名使用同一个规范化函数。对 JSON 值执行等价于：

```python
json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

即 UTF-8、对象键按 Unicode 字符串顺序排序、无多余空白、中文不转义、禁止 NaN 和
Infinity。协议 V1 的受保护对象与明文 payload 只使用字符串、布尔语义字符串、整数、
数组和对象，不使用 JSON 浮点数。生成器不得依赖输入文件原有键顺序。

该规范化是 MineGuard provisioning V1 的明确规则，不宣称是 RFC 8785。其他业务
契约使用 JCS 时仍以各自规范为准，不能混用。

## 3. 顶层信封

顶层对象必须精确为：

```json
{
  "protected": {},
  "ciphertext": "base64url-no-pad",
  "signature": "base64url-no-pad"
}
```

`ciphertext` 是 AES-GCM 输出的密文后直接附加 16-byte tag，再作 base64url 无填充
编码。`signature` 是 64-byte Ed25519 签名的 base64url 无填充编码。

`protected` 精确包含：

| 字段 | 约束 |
|---|---|
| `contract_version` | `mineguard-provisioning-bundle-v1` |
| `bundle_kind` | `enterprise-agent-provisioning` 或 `platform-client-registration` |
| `bundle_id` | 每个包唯一的 UUID |
| `pair_id` | 同一次企业/Platform 配对共享的 UUID |
| `profile_version` | 从 1 开始单调递增，最大 `2147483647` |
| `issued_at` | UTC `Z` 时间，可有 1–6 位小数秒 |
| `expires_at` | 晚于 `issued_at` 的 UTC `Z` 时间，可有 1–6 位小数秒 |
| `issuer_id` | 签发机构标识 |
| `issuer_key_id` | 本地受信 Ed25519 公钥标识 |
| `subject` | `{mine_id, system_id, party_id}` |
| `payload_sha256` | 规范化明文 payload 的 SHA-256 小写十六进制 |
| `locked_config_sha256` | 第 7 节定义的运行时锁摘要 |
| `locked_keys` | 企业包为全部 config 键；Platform 包固定为空数组 |
| `encryption` | 固定密码学参数和每包随机 salt/nonce |

`subject` 始终表示被接入的企业 Agent，而不是政府机构：

- `mine_id` 对应企业 `ENTERPRISE_MINE_ID` / Platform `client.mine_id`；
- `system_id` 对应企业 `ENTERPRISE_SYSTEM_ID` / Platform `client.sender_id`；
- `party_id` 对应企业 `ENTERPRISE_OPERATOR_ID` / Platform `client.party_id`。

`issuer_key_id` 只用于查询安装器本地、只读、预置的受信公钥，不得从部署包本身导入
公钥。未知、已撤销或超出批准有效期的 issuer key 必须拒绝。
介质外审批的公钥指纹统一计算为
`SHA-256(SubjectPublicKeyInfo DER)`，以 64 位小写十六进制表示。不得将 Ed25519
原始 32-byte 公钥的摘要、PEM 文本摘要或文件摘要冒充该指纹。
导入命令必须从介质外同时取得 expected 指纹和 expected issuer key ID；先重新计算本地
PEM 的 SPKI-DER 摘要，再核对受签名的 `protected.issuer_key_id`，不能仅相信包旁公钥。

## 4. 加密与签名

### 4.1 激活码和 KDF

激活码在部署包文件外单独交接，不得写入 JSON、文件名、README、日志、命令行参数、
二维码旁的明文或发行清单。它应由 CSPRNG 生成并至少包含 128 bit 随机性；V1 仅接受
生成器产生的 ASCII base64url 无填充字符，不做 Unicode 归一化或大小写转换。

企业包和 Platform 包默认使用两个独立激活码并通过不同授权渠道交接。两者即便实现上
使用相同码，密码学格式仍可工作，但会扩大介质同时泄露时的影响范围，不建议这样做。

AES key 计算为：

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

salt 必须是每包独立随机 16 bytes。激活成功后不得长期保存激活码或派生 AES key；内存
应尽快清零。连续失败必须限速并写不含秘密的安全审计。

### 4.2 AES-256-GCM

`encryption` 固定为：

```json
{
  "algorithm": "aes-256-gcm",
  "kdf": "scrypt",
  "salt": "16-byte-base64url-no-pad",
  "n": 16384,
  "r": 8,
  "p": 1,
  "nonce": "12-byte-base64url-no-pad"
}
```

明文为对应 payload 的规范化 UTF-8 bytes。合法 ciphertext 解码后至少 17 bytes（至少一个
明文字节和 16-byte GCM tag）；只有 tag、没有明文的 16-byte 值必须在执行 KDF 前拒绝。
AAD 必须是：

```text
canonical_json(protected)
```

nonce 必须由 CSPRNG 每包生成 12 bytes；对同一派生 AES key 不得重复。认证失败时只能
报告“激活码错误或包损坏”，不能泄露明文、tag、派生密钥或逐字段解析差异。

接收端只允许从受保护文件移除一个末尾 `LF` 或 `CRLF`；不得对激活码执行 `strip()`、
Unicode 归一化或大小写转换。V1 生成式激活码必须是恰好 43 个 base64url 字符，对应
32-byte CSPRNG 随机值。

### 4.3 Ed25519

签名输入精确为：

```text
canonical_json({"protected": protected, "ciphertext": ciphertext})
```

其中 `ciphertext` 是顶层原始 base64url 字符串，不是解码后的 bytes。生成器先完成加密，
再签名。导入器必须在提示激活码和尝试解密之前先验证 Ed25519，避免对未受信输入执行
高成本 KDF。

## 5. 企业 Agent 明文 payload

企业明文精确为：

```json
{
  "kind": "enterprise-agent-provisioning",
  "bundle_id": "UUID",
  "pair_id": "UUID",
  "profile_version": 1,
  "config": {"允许的环境变量名": "字符串值"},
  "locked_keys": ["按字典序排列的全部 config 键"]
}
```

`kind`、三个 ID/版本字段必须与 `protected` 一致。`config` 不接受未知键；允许的键以
[`enterprise-agent-provisioning-payload-v1.schema.json`](../schemas/enterprise-agent-provisioning-payload-v1.schema.json)
为权威清单。24 个正式基线键全部必填，三个历史/轮换键可选。生产模式、四眼复核和
Secure Cookie 三项必须是字符串 `"true"`。

额外语义必须校验：

- `PLATFORM_V3_SENDER_ID == ENTERPRISE_SYSTEM_ID`；
- `ENTERPRISE_EXCHANGE_HMAC_SECRET != PLATFORM_V3_TRANSPORT_HMAC_SECRET`；
- 当前 message/transport secret 均至少 32 bytes，不能是 demo、replace、change-me
  等占位值；
- 若出现 `REGULATORY_PREVIOUS_EXCHANGE_KEY_ID` 和
  `REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET`，必须成对出现；
- `ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON` 必须通过 Agent 已有的严格轮换解析器，
  不得包含当前 key ID 或重复 key ID；
- 五项 comparison context 不得是“未知”“待替换”等占位值；
- `PLATFORM_V3_BASE_URL` 与 `ENTERPRISE_AGENT_PUBLIC_ORIGIN` 必须是规范 HTTPS origin：
  无 userinfo、query、fragment、百分号编码或空白，只允许空路径或一个末尾 `/`（保存时
  去掉），主机必须小写，可选端口为 `1..65535` 且默认 `443` 必须省略；禁止
  localhost、`.localhost`、`.example`、`.invalid`、`.test`、`example.com/.net/.org`
  及其子域等保留/示例主机，以及 loopback、unspecified、multicast、link-local IP。

用户账号和密码在目标机器现场建立，不属于部署包。模型 API、自动采集和 Connector
可以后续独立审批配置，不得借 provisioning allowlist 绕过各自权限边界。

## 6. Platform 明文 payload

Platform 明文精确为：

```json
{
  "kind": "platform-client-registration",
  "bundle_id": "UUID",
  "pair_id": "UUID",
  "profile_version": 1,
  "client": {},
  "platform_identity": {
    "system_id": "...",
    "party_id": "...",
    "key_id": "..."
  }
}
```

`client` 是一条严格的 `clients.json` 登记项，包含企业 sender/party/mine、矿名、五项
正式分组、当前应用消息 key ID、最多当前加上一把历史消息密钥，以及最多当前加上一把
历史运输密钥。`active_message_key_id` 必须存在于 `message_keys`。

两类 payload 必须逐项配对：

| 企业 config | Platform payload |
|---|---|
| `ENTERPRISE_MINE_ID` | `client.mine_id` |
| `ENTERPRISE_MINE_NAME` | `client.mine_name` |
| `ENTERPRISE_OPERATOR_ID` | `client.party_id` |
| `ENTERPRISE_SYSTEM_ID` | `client.sender_id` |
| 五项 `ENTERPRISE_*` 分组 | `client.comparison_context` |
| `ENTERPRISE_EXCHANGE_KEY_ID` | `client.active_message_key_id` |
| 当前/历史应用消息密钥 | `client.message_keys` |
| 当前/历史运输密钥 | `client.transport_secrets` |
| `REGULATORY_SYSTEM_ID` | `platform_identity.system_id` |
| `REGULATORY_PARTY_ID` | `platform_identity.party_id` |
| `REGULATORY_EXCHANGE_KEY_ID` | `platform_identity.key_id` |

Platform 导入不得覆盖已登记的其他矿。若同一 `mine_id`、`sender_id` 或 `pair_id` 已归属
不一致的主体，必须拒绝并要求管理员审查，不能合并或猜测。

## 7. 运行时配置锁

企业包的：

```text
protected.locked_keys == payload.locked_keys == sorted(payload.config.keys())
protected.locked_config_sha256 == SHA256(canonical_json(payload.config))
```

也就是说本协议投递的每个键都锁定，不能在前端、普通环境文件或启动参数中覆盖。Agent
每次启动和每次报送前重新构造已生效的锁定 config，常量时间比较摘要；不一致时进入
fail-closed 状态，禁止确认和报送，并写安全审计。只读展示应对两个 HMAC 和历史秘密
脱敏，日志不得打印 config 全文。

Platform 包的 `protected.locked_keys` 固定为空，因为 registry 不是环境变量键集合；但：

```text
protected.locked_config_sha256 ==
  SHA256(canonical_json({"client": payload.client,
                         "platform_identity": payload.platform_identity}))
```

Platform 每次启动和处理该客户端请求前校验对应登记摘要。人工修改 `clients.json`、替换
密钥或改变矿井归属都应使该客户端 fail-closed，直到导入更高版本的有效配对更新包。

## 8. 导入顺序与原子性

接收端按以下顺序执行；任一步失败都不得留下部分生效配置：

1. 限制文件大小，按 UTF-8 严格解析 JSON，拒绝重复键和未知字段；
2. 用 Draft 2020-12 schema 校验信封；
3. 查找本地受信 `issuer_key_id`，验证 Ed25519 签名；
4. 检查 `issued_at < expires_at`、`issued_at` 不得超过本机可信时间 5 分钟，且当前首次
   导入时间未超过 `expires_at`；
5. 检查 bundle kind、目标角色、本机已绑定 subject、pair 和版本/重放状态；
6. 通过安全输入读取包外激活码，执行 scrypt 和 AES-GCM 认证解密；
7. 按 bundle kind 校验明文 payload schema；
8. 核对 payload hash、ID/版本、subject、locked keys/hash 和配对语义；
9. 检查 CA 文件、HTTPS origin、密钥差异和正式配置门禁；
10. 在覆盖完整读取、验证、合并和提交的跨进程排他锁内工作；提交前复核原文件摘要，
    再在同卷受限临时文件中写入、fsync 并原子替换；
11. 将秘密移入目标平台的机器级保护存储，记录非秘密审计和 envelope 摘要；
12. 重载后再次校验运行时锁，再返回成功。

Windows 应使用服务账号 ACL 和机器级秘密保护；Linux 应使用 root/服务账号受限文件或
批准的 secret store。是否使用 DPAPI、CNG、systemd credential 或 HSM 是实现选择，
不得改变本契约信封。

## 9. 错矿、过期、降级与重复

- **错矿/错主体**：已绑定实例的 `mine_id/system_id/party_id/pair_id` 任一不一致即拒绝；
  未绑定实例只能在明确的“首次接入”向导中认领 subject，不能后台静默认领。
- **过期**：`expires_at` 只限制首次导入或配置更新。包在成功导入后即使后来过期，运行时
  锁校验也不得因此自动停服；撤销必须通过显式受控更新/撤销流程完成。
- **降级**：按 `(bundle_kind, subject.system_id, pair_id)` 保存最高成功
  `profile_version`。更低版本永远拒绝；相同版本只允许相同 bundle 的幂等重试。
- **重复**：已成功的 `bundle_id` 加相同完整 envelope SHA-256 返回“已导入”且不再次写
  秘密；相同 `bundle_id` 配不同字节属于安全事件并拒绝。相同 profile version 配不同
  bundle ID 属版本冲突并拒绝。
- **配对**：生成器必须在同一事务中生成两包，且 `pair_id/profile_version/subject` 相同。
  任一侧导入成功不代表另一侧已成功；联通检查只有在两侧均应用同一 pair/version 后
  才能标记“配置配对完成”。

更高版本必须沿用原 `pair_id` 和完整 `subject`，且 `profile_version` 精确增加 1。企业
active message key ID 和双 HMAC 随版本轮换，但新包必须保留紧邻上一版的 message 与
transport secret。政府 key ID 是所有矿共享的 Platform 身份，逐矿轮换保持该 ID 不变；
Agent 用同一政府 key ID 依次尝试新旧 secret，避免多矿逐个更新时陷入全局 key ID 死锁。

### 9.1 Platform 外部受管锚

正式 Platform 必须把下列值放在独立、受服务 ACL 保护的配置中，而不是只放在可一起
替换的 `clients.json`：

```text
MINEGUARD_PROVISIONING_MANAGED_REQUIRED=true
MINEGUARD_PROVISIONING_TRUSTED_PUBLIC_KEY_FILE=<Ed25519 PEM 绝对路径>
MINEGUARD_PROVISIONING_EXPECTED_PUBLIC_KEY_SHA256=<SPKI-DER SHA-256>
MINEGUARD_PROVISIONING_EXPECTED_ISSUER_KEY_ID=<批准的 issuer key ID>
```

注册锁只记录 key ID 和 expected fingerprint，不内嵌一个可随 registry 一起替换后自我
背书的公钥。受管模式下删除 `provisioning_lock`、追加未锁客户端或替换 trust binding
都必须阻断启动和正式检查，不能静默降级为手工兼容模式。

V1 没有定义远程“自动撤销”消息。紧急撤销应先在 Platform 禁用客户端/防火墙，再由
授权人员签发更高 profile version 的轮换包。以后如需在线撤销清单，应发布独立契约，
不能把过期时间误用成运行时 kill switch。

## 10. 生成与交付

生成器必须使用密码学安全随机源创建：两个 bundle ID、pair ID、两把互不相同且每矿
唯一的 HMAC、每包 salt/nonce、激活码。provisioning Ed25519 私钥只存在于受控签发机
或 HSM，不能随生成结果、源代码、CI 日志或安装包交付。

每次签发必须默认使用四个互不相等、也不互为父子目录的交付树：

```text
enterprise-delivery/
  <mine>-v<profile>.mgprov
  <mine>-v<profile>.issuer-public.pem
  <mine>-v<profile>.enterprise-handover.json
government-registration/
  <mine>-v<profile>.mgreg
  <mine>-v<profile>.provisioning-manifest.json
enterprise-secret-channel/
  <mine>-v<profile>-agent.activation
government-secret-store/
  <mine>-v<profile>-platform.activation
```

政府完整 manifest 记录两份 bundle 和公开 PEM 的文件名、文件 SHA-256、pair ID、目标矿、
版本和签发身份；企业 handover 只记录企业 bundle 和公开 PEM，不得引用 `.mgreg`。公开
PEM 条目同时记录 PEM 文件 SHA-256 与 SPKI-DER SHA-256；SPKI 指纹仍须从介质外审批记录
独立核对，同盘公钥不是信任锚。

两份清单均不得包含 HMAC、任何 activation 字段/文件名/摘要、payload 明文、scrypt 派生
密钥或 Ed25519 私钥。激活文件名必须包含 `profile_version`，使同一矿 v1→v2 可在同一受控
秘密目录中并存且不会拿错。激活码不与包放在同一 U 盘或同一聊天消息中；导入后销毁
激活码文件和临时明文，部署包可作为密文审计介质归档。

旧版 `output_directory + activation_directory` 两树布局只为已有自动化兼容；正式生成器和
GUI 必须采用上述四区布局，并在写入前拒绝目录相等、父子嵌套、符号链接和 Windows
reparse point。

## 11. 示例说明

`examples/` 同时保存两个明文 payload 示例和两个 envelope 示例。payload/hash/配对关系
是真实可校验的，但 envelope 中 `ciphertext` 与 `signature` 只是满足 schema 的全零
占位符，**不是可解密或可验签的密码学固定向量，也不能用于生产**。正式实现测试必须
另外生成临时 Ed25519 key 和 activation code，覆盖成功、篡改、错码、过期、错矿、
重放、降级和原子回滚。

权威 schema：

- [`provisioning-bundle-v1.schema.json`](../schemas/provisioning-bundle-v1.schema.json)
- [`enterprise-agent-provisioning-payload-v1.schema.json`](../schemas/enterprise-agent-provisioning-payload-v1.schema.json)
- [`platform-client-registration-payload-v1.schema.json`](../schemas/platform-client-registration-payload-v1.schema.json)
