# MineGuard Windows 现场部署与网络配置手册

> 当前简化版，适用于 MineGuard 十量 V3、Windows `INTERNAL-UNSIGNED` 安装包。
> 本文取代旧版“双域名、企业端 HTTPS、CA PEM、独立激活码”流程。

本文按真实现场顺序说明政府 Platform、网络、企业接入包和企业 Agent 的安装。
普通部署人员只需使用图形向导；文中的 PowerShell 命令只用于网络检查和排障。

## 1. 先记住最终结构

```text
企业 Agent（每矿一套）
浏览器 -> 本机 Agent（127.0.0.1:8090）
                |
                | 主动出站 HTTPS 443
                v
https://qinyuan-platform.mineguard.cn
                |
        公网或政府内网入口
                |
          Caddy HTTPS 443
                |
        127.0.0.1:8080 Platform
```

只有政府 Platform 需要域名和 HTTPS。企业 Agent：

- 不需要企业域名；
- 不需要企业 HTTPS 证书；
- 不需要在企业路由器开放任何入站端口；
- 只需能主动访问 `https://qinyuan-platform.mineguard.cn:443`；
- 企业人员在安装 Agent 的电脑上打开本机页面。

内网和外网统一使用：

```text
https://qinyuan-platform.mineguard.cn
```

软件配置、企业接入包和证书不区分“内网版”“公网版”。区别仅是 DNS 将同一域名解析到
哪个 IP。

## 2. 部署前准备

### 2.1 两个安装包

从 GitHub Actions 的 `INTERNAL-UNSIGNED` artifact 中取得：

- `MineGuard-Platform-*-INTERNAL-UNSIGNED.exe`；
- `MineGuard-EnterpriseAgent-*-INTERNAL-UNSIGNED.exe`；
- `release-manifest.json`；
- `SHA256SUMS.txt`。

文件名含 `UNSIGNED-TEST-ONLY` 的安装包不能用于现场正式试运行。

在安装前核对 SHA-256：

```powershell
Get-FileHash -Algorithm SHA256 'D:\安装介质\MineGuard-Platform-*-INTERNAL-UNSIGNED.exe'
Get-FileHash -Algorithm SHA256 'D:\安装介质\MineGuard-EnterpriseAgent-*-INTERNAL-UNSIGNED.exe'
```

批准值应从下载介质之外的记录取得，不能只相信同一个 ZIP 中的校验文件。

### 2.2 政府侧需要的信息

| 项目 | 示例/要求 |
| --- | --- |
| Platform 电脑固定内网 IP | 例如 `192.168.10.11`，在路由器做 DHCP 保留 |
| Platform 域名 | `qinyuan-platform.mineguard.cn` |
| 互联网出口公网 IPv4 | 例如 `120.208.96.185` |
| Platform 本机端口 | 默认 `8080`，只监听 `127.0.0.1` |
| HTTPS 入口 | Caddy 监听 TCP `80/443` |
| Windows | Windows 10/11 x64 或 Server 2019/2022 x64 |

### 2.3 每座矿需要的信息

只准备以下业务身份：

- 煤矿正式名称；
- 煤矿稳定 ID，例如 `MINE_GY_001`；
- 经营主体正式名称；
- 经营主体稳定 ID。

技术系统 ID、实例名、包版本和密钥由向导生成。开采方式、班次制度、煤种、产能分组等
不是接入必填项，不要用“待定”或占位值硬填。

## 3. 配置同一个域名的内外网访问

### 3.1 公网 DNS

在域名服务商添加：

| 类型 | 主机记录 | 记录值 |
| --- | --- | --- |
| A | `qinyuan-platform` | 政府互联网出口的真实公网 IPv4 |

例如公网出口是 `120.208.96.185`，记录就是：

```text
qinyuan-platform.mineguard.cn -> 120.208.96.185
```

不要把公网 DNS 写成 Platform 的 `192.168.x.x` 内网地址，也不要添加当前不可达的 AAAA
记录。

检查：

```powershell
Resolve-DnsName qinyuan-platform.mineguard.cn -Type A
```

### 3.2 判断双层路由和运营商 NAT

在靠近 Platform 的路由器管理页面查看 WAN IPv4：

- WAN 是真实公网 IP：只需这一台路由器做端口映射；
- WAN 是 `10.x.x.x`、`172.16-31.x.x`、`192.168.x.x` 或 `100.64-127.x.x`：前面还有
  一层路由/NAT；
- 最外层设备拿到的也不是公网 IP：可能是运营商 CGNAT，需要运营商提供公网 IPv4、专线、
  VPN 或其他单位批准的入口，单靠本地端口映射无法解决。

示例现场结构：

```text
公网 120.208.96.185
  -> 一级路由器
  -> 二级路由器 WAN 192.168.1.5
  -> 二级路由器 LAN 192.168.10.1
  -> Platform 192.168.10.11
```

必须做两次映射：

1. 一级路由器 TCP `80/443` -> `192.168.1.5`；
2. 二级路由器 TCP `80/443` -> `192.168.10.11`。

只在第二台路由器映射不会让公网请求穿过第一台路由器。

### 3.3 Windows 防火墙

Platform 主机只需允许 Caddy 的 TCP `80/443` 入站。不要对局域网或公网开放 `8080`。

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object LocalPort -In 80,443,8080 |
  Select-Object LocalAddress,LocalPort,OwningProcess
```

预期 `80/443` 由 Caddy 监听，`8080` 只监听 `127.0.0.1`，不应出现
`0.0.0.0:8080`。

### 3.4 政府内网也使用同一域名

按现场能力选择一种方式：

1. 路由器支持 NAT 回环：内网继续使用公网 DNS；
2. 推荐长期方案：政府内网 DNS 将同一域名解析到 Platform 私网入口 IP；
3. 仅用于单机测试：在管理员权限下临时修改该电脑 hosts，映射到 Platform 内网 IP。

无论采用哪一种，浏览器和 Agent 中都仍填写域名，不填写 IP。内网 DNS 只改变网络路径，
不会改变 HTTPS 证书名称。

## 4. 配置 Caddy 和 HTTPS

### 4.1 Caddyfile

在 Platform 电脑准备 `C:\MineGuard\Caddy\Caddyfile`：

```caddyfile
qinyuan-platform.mineguard.cn {
    reverse_proxy 127.0.0.1:8080

    log {
        output file C:\MineGuard\Caddy\access.log
        format console
    }
}
```

Caddy 会为该域名自动申请并续期公网可信证书。首次申请必须满足：

- 公网 DNS 已指向真实公网出口；
- 外网 TCP `80/443` 已逐层映射到 Platform 主机；
- 防火墙允许 Caddy；
- 其他程序没有占用 `80/443`。

先在管理员 PowerShell 前台验证：

```powershell
Set-Location 'C:\MineGuard\Caddy'
.\caddy.exe validate --config .\Caddyfile
.\caddy.exe run --config .\Caddyfile
```

窗口保持打开表示 Caddy 正在运行。验证完成后，应通过单位批准的 Windows 服务管理方式将
同一条 `caddy run --config ...` 命令注册为自动启动服务，不要依赖人工长期保持窗口。

### 4.2 不再要求现场选择 HTTPS CA PEM

当前向导中，企业只选择一个 `.mgprov`，不再单独选择 CA PEM、签发公钥、激活码或指纹。
使用 Caddy 公网可信证书时，Windows 操作系统信任链即可验证 HTTPS。

以下三类材料互不替代：

- Caddy HTTPS 证书：证明政府域名，由 Caddy 维护；
- `.mgprov` 内嵌签发信任：证明企业接入配置由政府签发；
- 模型 API Key：只由企业 `api_admin` 配置。

## 5. 安装并配置政府 Platform

### 5.1 安装

1. 运行 `MineGuard-Platform-*-INTERNAL-UNSIGNED.exe`；
2. 安装路径由用户选择，数据放在安装时选择的专用目录；
3. 按安装器要求确认 `INTERNAL-UNSIGNED` 并使用介质外批准值核对；
4. 安装完成后打开 **MineGuard 企业接入包与注册向导**。

不要先建立演示数据再把同一状态目录改成正式目录。演示和正式状态必须分开。

### 5.2 第一次初始化签发机构

在向导第一页：

1. 初始化政府接入包签发密钥；
2. 设置并妥善保存签发密钥口令；
3. Platform HTTPS 地址填写：

```text
https://qinyuan-platform.mineguard.cn
```

第一家企业生成后，后续企业会共用并锁定该 Platform origin。不要填写
`http://IP:8080`、路径、查询参数或业务接口路径。

### 5.3 为第一座矿生成接入包

在“生成企业接入包”页：

1. 填煤矿名称和煤矿 ID；
2. 填经营主体名称和主体 ID；
3. 选择企业交付目录；
4. 点击生成。

企业交付目录最终只需要一个：

```text
<矿井>-v1.mgprov
```

不要再给企业发送 `.mgreg`、CA PEM、激活码、签发私钥或 Platform 管理员密码。

### 5.4 完成政府注册

生成成功后，向导会自动进入“完成监管端配置”：

1. `.mgreg`、Platform 激活材料和签发信任自动带入；
2. 第一次配置时设置 Platform 管理员强密码；
3. 点击导入监管注册包；
4. 等待提示注册与正式配置成功。

`.mgreg` 是政府本机留存材料，不交给企业。Platform 是多矿集中平台，不需要为每座矿安装
一套政府软件。

### 5.5 启动 Platform

1. 打开 **MineGuard Platform 控制中心**；
2. 选择正式配置并点击“启动当前配置”；
3. 本机检查：

```powershell
Invoke-WebRequest 'http://127.0.0.1:8080/healthz' -UseBasicParsing
Invoke-WebRequest 'http://127.0.0.1:8080/readyz' -UseBasicParsing
```

4. 通过最终域名检查：

```powershell
Invoke-WebRequest 'https://qinyuan-platform.mineguard.cn/healthz' -UseBasicParsing
Invoke-WebRequest 'https://qinyuan-platform.mineguard.cn/readyz' -UseBasicParsing
```

四次请求都应返回 HTTP 200。前台验收成功后，再从控制中心安装正式 Windows 服务，使
Platform 开机自动运行。

## 6. 新增第二座及更多煤矿

一个政府 Platform 可以监管多座煤矿。每新增一座矿：

1. 打开政府侧 **MineGuard 企业接入包与注册向导**；
2. 不重新初始化签发机构，不更改 Platform 域名；
3. 填新矿的煤矿与经营主体信息；
4. 生成新矿专属 `.mgprov`；
5. 在最后一页导入该矿政府留存的 `.mgreg`；
6. 将这座矿的 `.mgprov` 单独交给对应企业。

每座矿的 `.mgprov`、系统身份和密钥互不通用。

## 7. 企业侧安装 Agent

### 7.1 安装和接入

1. 运行 `MineGuard-EnterpriseAgent-*-INTERNAL-UNSIGNED.exe`；
2. 打开 **MineGuard 企业接入配置向导**；
3. 选择政府交付的唯一 `.mgprov`；
4. 实例名保持自动值，端口默认 `8090`，仅在被占用时修改；
5. 设置业务管理员账号、姓名和强密码；
6. 为固定账号 `api_admin` 设置另一个强密码；
7. 点击导入并创建实例；
8. 向导自动打开正式服务安装窗口，点击安装并启动；
9. 看到“正式服务已安装、启动并通过绑定当前实例的健康检查”才算完成。

企业不需要填写 Platform API 地址，它已锁定在 `.mgprov` 中。这里的模型 API 是另一件事。

### 7.2 配置模型 API

1. 用固定账号 `api_admin` 登录企业 Agent；
2. 打开“模型 API 配置”；
3. 填 API 地址，例如 `https://api.deepseek.com`；
4. 模型名称可填 `deepseek-chat`；
5. 输入完整 API Key，保存前系统会测试连接；
6. 保存成功后退出，再用业务管理员登录。

业务管理员不能查看或修改 API Key。模型服务不可用时，人工填报、复核、排队和可靠发送
仍可运行；智能映射和生产数据助手会提示模型不可用。

### 7.3 打开企业页面

企业 Agent 默认只在本机开放。使用开始菜单入口，或在 Agent 电脑打开：

```text
http://127.0.0.1:8090
```

不要在企业路由器上把 `8090` 映射到公网。

## 8. 完整端到端验收

按以下顺序做一次真实小批次测试：

1. 企业导入几行已经核对的生产数据；
2. 确认页面显示“生产数据批次”，日期可以不连续、跨月；
3. 保存复核修改；
4. 点击“询问生产数据助手”，确认它绑定当前批次且只能只读解释；
5. 企业人员确认并进入发送队列；
6. 企业页面应变为“政府已接收”或显示明确可重试错误；
7. 政府 Platform 刷新矿井列表和最近接收记录；
8. 确认政府端能看到该矿、实际日期范围和分析结果；
9. 企业拉取政府报告并查看风险说明；
10. 断开企业网络后提交一批测试数据，再恢复网络，确认可靠队列能重试发送。

“政府已接收”只表示报文验签并入队，不等于数据无风险或监管认定正常。

## 9. 网络验收命令

### 9.1 在企业电脑执行

```powershell
Resolve-DnsName qinyuan-platform.mineguard.cn -Type A
Test-NetConnection qinyuan-platform.mineguard.cn -Port 443
Invoke-WebRequest 'https://qinyuan-platform.mineguard.cn/healthz' -UseBasicParsing
Invoke-WebRequest 'https://qinyuan-platform.mineguard.cn/readyz' -UseBasicParsing
```

判断：

- DNS 失败：先修 DNS/代理，不是 MineGuard 账号问题；
- TCP 443 失败：检查逐层 NAT、防火墙和 Caddy；
- 证书失败：检查域名解析、Caddy 证书和电脑时间；
- `healthz=200` 但 `readyz` 失败：Platform 进程已启动，但正式配置、客户端注册或状态库未就绪；
- 返回 502：Caddy 正常，但 `127.0.0.1:8080` 的 Platform 没启动或端口不一致。

### 9.2 排除 Clash/TUN 干扰

只对一个命令绕过代理测试，不必关闭与 GPT 对话所用的 Clash：

```powershell
curl.exe --noproxy '*' -4 -I https://qinyuan-platform.mineguard.cn/readyz
```

如果绕过代理成功、浏览器失败，在 Clash 中为域名、政府公网 IP 和政府内网 IP 设置直连。
不要把虚拟网卡地址写入 DNS 或 `.mgprov`。

## 10. 常见问题快速处理

### 域名能解析，但访问超时

依次检查公网 IP、一级路由映射、二级路由映射、Platform 固定内网 IP、Windows 防火墙和
Caddy。双层 NAT 漏一层是最常见原因。

### Caddy 无法申请证书

确认公网 DNS 已生效，外网 `80/443` 能到达 Caddy，且不存在运营商 CGNAT。不要用
`https://IP` 代替域名，也不要关闭证书验证。

### 政府内网打不开，但企业外网能打开

路由器可能不支持 NAT 回环。给政府内网 DNS 添加同域名私网解析；软件中的 URL 仍保持
`https://qinyuan-platform.mineguard.cn`。

### Agent 服务运行但端口健康检查失败

```powershell
Get-CimInstance Win32_Service -Filter "Name='MineGuardEnterpriseAgent-enterprise'" |
  Select-Object Name,State,StartName
Get-NetTCPConnection -State Listen -LocalPort 8090
```

服务应使用自己的 `NT SERVICE\MineGuardEnterpriseAgent-<实例名>` 虚拟账号。不要通过给
Everyone 写权限来解决 `ProgramData` 拒绝访问。

### 模型 API 保存失败或生产数据助手不可用

确认使用 `api_admin`、API 地址和模型名正确、企业电脑能访问模型服务。模型 API 问题不应
阻止向政府报送；先区分“模型不可用”和“Platform 443 不通”。

## 11. 现场最终勾选表

- [ ] Platform 主机使用固定内网 IP。
- [ ] 公网 DNS 指向真实公网出口。
- [ ] 每一层路由器都完成 TCP 80/443 映射。
- [ ] Platform 防火墙允许 Caddy，8080 未对网络开放。
- [ ] Caddy 已取得有效证书并设置自动启动。
- [ ] 政府内网和企业外网使用同一个域名。
- [ ] `/healthz` 和 `/readyz` 通过最终 HTTPS 域名返回 200。
- [ ] 政府签发机构只初始化一次，后续煤矿复用。
- [ ] 每座矿分别注册，企业只收到自己的 `.mgprov`。
- [ ] 企业 Agent 服务健康，8090 未映射到公网。
- [ ] `api_admin` 已配置模型 API，业务管理员无法查看 API Key。
- [ ] 已完成生产数据批次报送、政府接收、报告回传和断网重试。
- [ ] 已分别备份 Platform 和各矿 Agent 状态目录并完成恢复演练。

## 12. 不要再做的旧操作

- 不要给企业配置第二个公网域名；
- 不要给企业 Agent 配置 HTTPS 证书或开放 8090；
- 不要让企业手工选择 CA PEM、激活码、签发公钥或指纹；
- 不要手工编写 `client.json/clients.json` 代替政府向导；
- 不要给每座矿安装一套政府 Platform；
- 不要用 IP、`http://` 或带路径的 URL 生成 `.mgprov`；
- 不要把开发接入包通过改文件名变成正式包；
- 不要把模型 API Key 交给企业业务管理员；
- 不要用关闭 TLS 验证、开放 8080/8090 或放宽 Everyone ACL 的方式“临时跑通”。

高级运维见：

- [Platform Windows 运维入口](../platform/deploy/windows/README.md)
- [企业 Agent Windows 运维入口](../agent/deploy/windows/README.md)
- [Windows 二进制发行与安装](Windows二进制发行与安装.md)
