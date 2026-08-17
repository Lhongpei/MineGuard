# mineguard.cn 正式上线步骤

> **旧版网络/证书方案，不用于当前新装。** 当前企业 Agent 只监听
> `127.0.0.1`，不需企业域名；企业只需政府 Platform 的一个 HTTPS 地址和一个
> `.mgprov` 文件。以 [Platform Windows 说明](../platform/deploy/windows/README.md) 和
> [Agent Windows 说明](../agent/deploy/windows/README.md) 为准。

> 适用范围：MineGuard Platform 政府端和梗阳矿 Enterprise Agent 首次正式试运行。
> 推荐域名：Platform 使用 `platform.mineguard.cn`，梗阳矿 Agent 使用
> `gengyang.mineguard.cn`。
> 核心顺序：**先定服务器和网络 → 再完成 DNS/HTTPS → 验证域名可用 →
> 最后重新生成梗阳矿正式接入包**。

## 1. 正式上线目标

最终网络应形成以下链路：

```text
政府办公网浏览器
        |
        | HTTPS 443
        v
https://platform.mineguard.cn
        |
        | 政府服务器本机反向代理
        v
127.0.0.1:8080  MineGuard Platform

梗阳矿企业浏览器
        |
        | HTTPS 443
        v
https://gengyang.mineguard.cn
        |
        | 企业服务器本机反向代理
        v
127.0.0.1:8090  Enterprise Agent
        |
        | 主动出站 HTTPS 443
        v
https://platform.mineguard.cn
```

政府端不需要主动连接矿区 Agent。Agent 主动向 Platform 报送数据、拉取报告和
回执。

## 2. 开始前必须填齐的信息

下表任一关键项为空时，可以安装软件，但不得生成第一份正式逐矿接入包。

### 2.1 服务器与网络

| 项目 | 现场填写 | 要求 |
| --- | --- | --- |
| 政府端固定公网 IPv4 |  | 不应使用会频繁变化的家庭宽带地址 |
| 政府公网 443 映射到的服务器 |  | 写明内网 IP 和责任人 |
| 政府 Platform 操作系统 |  | Windows 10 1809+/11 x64 或 Server 2019/2022 x64 |
| 梗阳 Agent 操作系统 |  | Windows 10 1809+/11 x64 或 Server 2019/2022 x64 |
| 梗阳 Agent 服务器内网 IP |  | 用于企业内部 DNS 或 hosts |
| 政府可访问办公网段 |  | 用于 443 入站白名单 |
| 梗阳矿公网出口 IP |  | 有固定出口时纳入 Platform 443 白名单 |
| 统一时间源 |  | 两台机器 W32Time/NTP 均必须正常 |

Windows Server 2012 R2 不在正式支持范围内。Windows 10 应同时核对组织 ESU 或
LTSC 生命周期；“能安装”不等于满足正式安全基线。

### 2.2 梗阳矿正式业务字段

下列内容必须由企业和监管业务人员核对，不得填“测试”“待定”“未知”或临时值。

| 字段 | 现场填写 |
| --- | --- |
| 煤矿正式名称 |  |
| 煤矿稳定 ID（拟用 `GENGYANG-001`） |  |
| 企业工商正式全称 |  |
| 企业主体稳定 ID |  |
| Agent 系统 ID（拟用 `gengyang-agent`） |  |
| 核定产能区间 |  |
| 开采方式 |  |
| 班次制度 |  |
| 主要煤种 |  |
| 生产制度 |  |

上表最后五项是监管算法同类矿比较的正式分组依据，不是页面展示备注。

## 3. 只下载正式 Windows Action 产物

当前无 Authenticode 代码签名证书时，正式发行路线是
`INTERNAL-UNSIGNED + 介质外 SHA-256`，不是 `UNSIGNED-TEST-ONLY`。

- 在 GitHub Actions 中手工运行 **Windows binary installer release**。
- 分支选择 `main`。
- `release_mode` 选择 `internal-unsigned`。
- `legacy_server_2012r2_compatibility_test` 保持 `false`。
- 该正式路线使用已配置受控输入的 Windows 自托管 release runner；
  `INTERNAL-UNSIGNED` job 没有完整成功时，不得拿其他测试 job 的产物替代。
- 只接收名称类似
  `mineguard-windows-INTERNAL-UNSIGNED-<commit>` 的 artifact。
- artifact 应同时包含：
  - `MineGuard-Platform-*-INTERNAL-UNSIGNED.exe`；
  - `MineGuard-EnterpriseAgent-*-INTERNAL-UNSIGNED.exe`；
  - `release-manifest.json`；
  - `SHA256SUMS.txt`。
- 文件名包含 `UNSIGNED-TEST-ONLY` 或
  `LEGACY-SERVER-2012R2-UNSIGNED-TEST-ONLY` 时，不得用于正式试运行。

`INTERNAL-UNSIGNED` 没有 Windows “已验证的发布者”。现场必须用电话、纸质交接单或
独立审批系统取得两个 Setup 各自的 SHA-256，不能只相信同一 U 盘里的
`SHA256SUMS.txt`。在 Windows 上核验：

```powershell
Get-ChildItem -Filter '*-INTERNAL-UNSIGNED.exe' |
  Get-FileHash -Algorithm SHA256
```

## 4. 配置 DNSPod

`mineguard.cn` 当前已委托给 DNSPod 权威 DNS。截至 2026-08-13，
`platform.mineguard.cn` 和 `gengyang.mineguard.cn` 尚未建立解析记录。

### 4.1 Platform 公网记录

在 DNSPod 控制台新建：

| 主机记录 | 类型 | 记录值 | TTL |
| --- | --- | --- | --- |
| `platform` | `A` | `<政府端固定公网 IPv4>` | 试运行期 `300` |

只有在政府网络已真正部署 IPv6、防火墙和证书验收后才添加 `AAAA`。
不要为了“看起来完整”填写不可达的 IPv6 地址。

### 4.2 梗阳 Agent 记录

梗阳 Agent 不需向整个公网开放。按实际使用选一种：

1. **推荐：企业内部 DNS**
   将 `gengyang.mineguard.cn` 解析到企业 Agent 主机内网 IP，公网
   DNSPod 不建 `A` 记录；证书通过 DNS-01 验证签发。
2. **仅在 Agent 服务器本机操作**
   在该机受控 hosts 文件中映射
   `127.0.0.1 gengyang.mineguard.cn`，证书仍必须包含
   `gengyang.mineguard.cn` SAN。
3. **确实需要公网访问**
   才在 DNSPod 添加 `gengyang A <企业固定公网 IP>`，并将入站
   443 限制为企业批准网段。

试运行稳定后可将 DNS TTL 调整为 `3600`。DNS 变更后在两台服务器分别检查：

```powershell
Resolve-DnsName platform.mineguard.cn
Resolve-DnsName gengyang.mineguard.cn
```

## 5. 准备 HTTPS 证书和 Platform CA

### 5.1 证书划分

推荐分别签发两张单域名证书：

- Platform 证书：SAN 包含 `platform.mineguard.cn`；
- 梗阳 Agent 证书：SAN 包含 `gengyang.mineguard.cn`。

不建议把同一个 `*.mineguard.cn` 通配证书私钥复制到所有煤矿。任一矿的主机泄露
后，会同时威胁其他子域名。

如 Agent 不对公网开放，应使用 DNS-01 验证签发
`gengyang.mineguard.cn` 证书。DNSPod API Token 只放在受保护的证书管理器中，
不得写入仓库、MineGuard 配置包、页面或日志。

### 5.2 三类文件不得混用

| 材料 | 用途 | 保管位置 |
| --- | --- | --- |
| HTTPS leaf/fullchain | 向浏览器和 Agent 证明当前服务器域名 | 对应服务器反向代理 |
| HTTPS 私钥 | TLS 服务器私钥 | 仅对应服务器的受保护证书目录 |
| `platform-ca.pem` | Agent 验证 Platform HTTPS 证书链 | 作为公共 CA 材料随企业交付目录交付 |

`platform-ca.pem` 应包含验证 Platform 所需的 CA 根证书，必要时可包含中间 CA，
但不得含有任何 `PRIVATE KEY`。Platform 和 Agent 的 HTTPS 私钥都不得放入
`.mgprov`、`.mgreg`、企业交付 ZIP 或 GitHub Action artifact。

企业导入器会锁定 `platform-ca.pem` 的 SHA-256。第一张 Platform 证书应选定稳定
CA 链并确立续期责任人。如未来更换 CA 链，必须走显式 CA 迁移和逐矿更新包，
不得手工覆盖已锁定文件。

## 6. 配置 443 和反向代理

MineGuard 应用进程始终只监听回环端口。反向代理可使用单位批准的
IIS/ARR、Caddy、Nginx 或网关。仓库已提供两份 Nginx 基线模板：

- Platform：`platform/deploy/nginx-mineguard.conf.example`；
- Agent：`agent/deploy/nginx-enterprise-agent.conf.example`。

### 6.1 Platform 代理必须值

```nginx
server {
    listen 443 ssl;
    server_name platform.mineguard.cn;

    ssl_certificate     C:/MineGuard/tls/platform-fullchain.pem;
    ssl_certificate_key C:/MineGuard/tls/platform-private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Connection "";
        proxy_read_timeout 120s;
    }
}
```

### 6.2 梗阳 Agent 代理必须值

复制 Agent 模板后至少替换：

```nginx
server_name gengyang.mineguard.cn;
ssl_certificate     C:/MineGuard/tls/gengyang-fullchain.pem;
ssl_certificate_key C:/MineGuard/tls/gengyang-private.key;

# 必须与 ENTERPRISE_AGENT_PUBLIC_ORIGIN 的 authority 完全一致
proxy_set_header Host gengyang.mineguard.cn;

# 模板中全部 Agent location 均指向该本机上游
proxy_pass http://127.0.0.1:8090;
```

应保留 Agent 模板中的 32 MiB 总请求上限、登录限流、机器接口限流和安全日志格式。

反向代理必须满足：

- 原样保留 path、query 和 body，不重新序列化签名 JSON；
- 不对 Platform 机器接口制造 HTTP 重定向；Agent 不跟随重定向；
- 保留外部 `Host`，设置 `X-Forwarded-Proto: https`；
- 不记录 Cookie、签名头、请求 body、HMAC 或 API Key；
- 设置证书到期和续期失败告警。

## 7. 防火墙和端口验收

| 节点 | 本地应用监听 | 允许的网络端口 | 方向 |
| --- | --- | --- | --- |
| Platform | `127.0.0.1:8080` | `443/tcp` | 矿区 Agent 和批准政府网段入站 |
| 梗阳 Agent | `127.0.0.1:8090` | `443/tcp` | 只允许企业内部浏览器入站 |
| 梗阳 Agent 出站 | 无 | `443/tcp` | 只需访问 `platform.mineguard.cn` 和已批准模型/搜索域名 |

不得对局域网或公网开放 8080/8090。在两台机器检查：

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object LocalPort -In 443,8080,8090

Test-NetConnection platform.mineguard.cn -Port 443
```

预期结果：8080/8090 的 `LocalAddress` 为 `127.0.0.1`；443 由反向代理监听。

## 8. 先验证域名和证书

在**梗阳 Agent 服务器**上执行：

```powershell
Invoke-WebRequest 'https://platform.mineguard.cn/healthz' -UseBasicParsing
Invoke-WebRequest 'https://platform.mineguard.cn/readyz' -UseBasicParsing
```

两个地址都应直接返回 HTTP 200，不应先返回 301/302。还应在 Edge/Chrome 中确认：

- 域名与证书 SAN 一致；
- 证书链完整，无未受信或过期告警；
- `/healthz` 表示进程存活，`/readyz` 表示正式状态就绪；
- Platform 未暴露 8080。

待 Agent 安装完成后，在企业浏览器验证：

```powershell
Invoke-WebRequest 'https://gengyang.mineguard.cn/api/v1/health' -UseBasicParsing
```

## 9. 域名和 CA 通过后，重新生成梗阳矿正式接入包

之前的梗阳联调包使用 `*.mineguard.local`、测试 CA、测试签发机构和联调分组值，
不得通过改文件名或换账号变成正式包。

### 9.1 政府机上首次初始化

1. 用正式 `INTERNAL-UNSIGNED` Platform Setup 安装。
2. 在政府机打开“MineGuard 企业接入包与注册向导”。
3. 新建正式生产 Ed25519 签发密钥，不导入开发机上的 lab issuer。
4. 签发私钥、私钥口令和 Platform 激活码只由政府管理员保管。
5. 将最终 Platform CA 公开 PEM 作为“政府 HTTPS CA PEM”输入。

第一次成功签包后，向导会锁定 Platform 域名、CA 及其 SHA-256、签发机构和
政府身份。因此不得在 DNS 或证书未定稿时“先随便填一个”。

### 9.2 梗阳矿 profile 正式值

| 配置项 | 正式值 |
| --- | --- |
| `profile_version` | 全新正式接入使用 `1` |
| 企业本机实例名 | `gengyang-001` |
| Agent HTTPS origin | `https://gengyang.mineguard.cn` |
| Platform HTTPS origin | `https://platform.mineguard.cn` |
| Platform CA 在 Agent 上的锁定路径 | `C:\ProgramData\MineGuard\EnterpriseAgent\instances\gengyang-001\config\platform-ca.pem` |
| 报表时区 | `Asia/Shanghai` |
| 安装有效窗口 | 通常 `14` 天 |

煤矿、企业、Agent 系统 ID、政府系统/主体/key ID 和五项比较分组均使用第 2 节
已审批值。如联调包已导入过企业机，不要尝试用新生产 issuer 的 `v1` 覆盖原实例；
应按试验环境清理流程创建全新正式实例和状态目录。

### 9.3 四区交付

- 给企业：整个梗阳企业交付目录，包含 `.mgprov`、签发公钥、
  `platform-ca.pem`、交接清单和安装 manifest。
- 另一渠道给企业：Agent `.activation` 文件。
- 独立渠道口头/纸质告知企业：12 位独立核验码。
- 政府留存：`.mgreg`、Platform `.activation`、签发私钥及口令。

HTTPS 私钥、用户密码、LLM API Key 和 DNSPod API Token 不属于任何一个逐矿包。

## 10. 安装与端到端验收

1. 政府端先导入梗阳 `.mgreg` 和 Platform 激活码，生成受管 `clients.json`。
2. Platform 正式配置必须启用 Secure Cookie，只监听 `127.0.0.1:8080`。
3. Platform `/healthz` 和 `/readyz` 均返回 200。
4. 企业机安装正式 Agent Setup，加载完整企业交付目录。
5. 另选 Agent 激活码，输入独立核验码，创建两个不同的具名账号。
6. 正式密码至少 12 位，且在大写、小写、数字和符号中至少包含三类；
   不得使用 `123123123`。
7. 梗阳 Agent 只监听 `127.0.0.1:8090`，浏览器通过
   `https://gengyang.mineguard.cn` 登录。
8. 导入一个已由业务人员确认的月度 CSV，执行：
   “经办保存 → 另一人复核报送 → Platform 入库分析 → Agent 收到报告和回执”。
9. 执行断网恢复、服务重启、证书到期告警、备份与空目录恢复演练。
10. 保存脱敏验收记录，不保存密码、Cookie、HMAC、激活码或证书私钥。

## 11. ICP 和公网合规提示

购买 `mineguard.cn` 不等于已完成 ICP 备案。如使用中国大陆境内服务器通过
公网域名提供互联网信息服务，上线前应通过实际接入商核对 ICP 备案/许可、域名实名和
所在地通信管理要求。根据工业和信息化部现行《非经营性互联网信息服务备案管理办法》，
在中国境内提供非经营性互联网信息服务应依法履行备案手续；具体办理由接入商和属地
主管部门确认：

- [工业和信息化部：非经营性互联网信息服务备案管理办法](https://wap.miit.gov.cn/gyhxxhb/jgsj/cyzcyfgs/bmgz/xxtxl/art/2024/art_84a0cfa0ebd049bbbe751dca9a008e56.html)
- [工业和信息化部 ICP/IP 地址/域名信息备案管理系统](https://beian.miit.gov.cn/)

如属于需办理公安联网备案的互联网站点/系统，还应向属地公安机关确认办理范围和时限。
公安部办事指南载明，相关联网单位应在正式联通后按规定办理备案：

- [公安部“互联网+政务服务”平台：国际联网备案事项](https://ywtb.mps.gov.cn/newhome/portal/fw/ssqd/000709114001)
- [全国互联网安全管理服务平台](https://www.beian.mps.gov.cn/)

如完全使用政府专网、VPN 或不向公众开放的内部系统，适用程序可能不同；不要自行猜测
豁免，由实际互联网接入商、政府信息化部门和属地主管部门出具明确意见。

## 12. 最终上线勾选表

- [ ] 已确认政府固定公网 IP、NAT 和两台服务器 OS。
- [ ] DNSPod 中 `platform.mineguard.cn` 已解析到政府公网 IP。
- [ ] 企业内部可正确解析 `gengyang.mineguard.cn`。
- [ ] 两张 HTTPS 证书 SAN 正确，私钥只在各自服务器。
- [ ] Platform CA PEM 已定稿并记录介质外 SHA-256。
- [ ] 8080/8090 只监听回环，只对批准网段开放 443。
- [ ] Platform `/healthz` 和 `/readyz` 在梗阳网络中均直接返回 200。
- [ ] 下载的 Action artifact 名包含 `INTERNAL-UNSIGNED`，不含 `TEST-ONLY`。
- [ ] 两份 Setup 的介质外 SHA-256 已分别复核。
- [ ] 梗阳矿五项正式比较字段和主体身份已签字确认。
- [ ] 已在政府机生成新的正式 issuer，未复用 lab issuer/测试 CA。
- [ ] 已使用正式域名和 CA 重新生成梗阳矿 `profile_version=1` 接入对。
- [ ] 已完成 CSV、异人复核、HTTPS 报送、政府分析、报告回传的完整链路。
- [ ] 已完成备份恢复、断网重试、时钟和证书到期验收。
- [ ] 已由接入商和责任部门确认 ICP/公安联网备案及其他上线手续。
