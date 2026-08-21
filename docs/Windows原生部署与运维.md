# MineGuard · 矿安智察 Windows 原生部署与运维

需要给非研发目标机交付两个独立离线安装器时，优先按
[《Windows 二进制发行与安装》](./Windows二进制发行与安装.md)构建、签名和验收；本文继续
说明源码/运维层面的 Windows 运行方式。

现场人员应先按
[《Windows 现场部署与网络配置手册》](./mineguard.cn正式上线步骤.md)
完成图形化安装、同域名内外网解析、路由映射、Caddy HTTPS、逐矿 `.mgprov` 和端到端验收；
本文保留源码部署及高级运维细节。

本文是两套独立软件的 Windows 总体部署基线：每座煤矿各自部署一个
`agent/` 企业智能体，政府集中部署一个 `platform/` 监管平台。两端不共享
代码包、数据库、用户、状态目录或密钥，只通过版本化 HTTPS/JSON/HMAC 契约
交换数据。

当前交换合同为十量 V3；字段、CSV 和 V2 只读边界见
[十量 V3 部署与运行](十量V3部署与运行.md)。历史脚本或目录名中出现 `V2` 不代表可用
五量 V2 创建新报送。

企业端和政府端各自的参数、脚本和故障处置见：

- [政府 Platform Windows 说明](../platform/docs/Windows原生部署与运维.md)；
- [企业 Agent Windows 说明](../agent/deploy/windows/README.md)。

## 1. 支持范围

| 场景 | 结论 | 建议 |
|---|---|---|
| Windows 10 1809+/11 本机演示 | 支持 | x64 安装包，Edge/Chrome |
| Windows 10 1809+/11 单矿试点 | 支持 | 使用独立账号、NTFS 权限和定时备份 |
| Windows Server 2019/2022 原生服务 | 支持目标 | WinSW + 反向代理 + 专属虚拟服务账号 |
| WSL2 | 仅开发/联调 | 不作为生产 Windows 服务方案 |
| Windows Server 2016 及更旧版本、ARM64 | 不支持 | 不得绕过安装包系统版本/架构门禁 |

仓库的 Windows CI 使用 Windows Server 2022，并用 PowerShell 5.1 解析部署脚本；
安装包的最低系统门禁是 Windows 10 1809 / Windows Server 2019（build 17763）。
这是技术兼容下限，不等于 2026 年正式生产支持：普通 Windows 10 22H2 必须具有
组织 ESU，或使用仍在产品生命周期内的具体 LTSC 版本；优先 Windows Server 2019/2022
或 Windows 11。
仓库 CI 还会在 Python 3.12 x64 上验证 `Asia/Shanghai` 时区、契约、两端单元测试、
CLI 入口以及带中文和空格状态路径的健康检查。正式上线还必须完成本文第
13 节的现场验收；CI 不能代替现场数据映射、断网和灾备演练。

## 2. 目标拓扑

```text
煤矿 A：Windows Agent A ─┐
煤矿 B：Windows Agent B ─┼── 主动出站 HTTPS 443 ──> 政府 Platform ──> 领导浏览器/大屏
煤矿 C：Linux Agent C   ─┘                    Windows 或 Linux
```

- 一矿一 Agent，一个 Agent 只绑定一个 `mine_id`、一个经营主体和一组
  独立密钥。不得用同一个进程或数据库在页面上切换煤矿。
- Platform 在政府网络集中保存多矿报送、分析、风险、回复和审计链；不与
  任何 Agent 共享 SQLite 文件。
- 政府不主动连入矿区内网。Agent 主动报送、拉取报告并提交人工确认的
  回复。
- Windows 和 Linux 可以混合部署；系统边界由契约和密钥定义，不由操作系统
  定义。

演示时可在同一台 Windows 电脑上同时启动两端。生产环境应将政府端与企业端
放在不同主机或虚拟机和网络区域。各煤矿属于不同经营主体，正式环境应一矿
一主机/虚拟机；不应依赖同一 Windows 主机上多个同身份服务实现所有者隔离。

## 3. 软硬件基线

### 3.1 必需软件

- 64 位 Windows 10 1809+/11 或 Windows Server 2019/2022；安装包会拒绝更旧版本和 ARM64。
- Windows 原生发布固定 64 位 CPython 3.12；两端安装脚本会拒绝其他 Python
  小版本或 32 位解释器。项目元数据中的 `>=3.11` 是源码最低要求，不是 Windows
  发布支持矩阵。
- PowerShell 5.1 或更高。脚本不要通过 `Invoke-Expression` 或 dot-source 加载秘密
  配置。
- NTFS 本机盘。SQLite 数据库、WAL、隔离文件和运行日志不得放在 SMB/NAS、
  OneDrive、网盘或同步目录。
- 现代 Edge 或 Chrome。政府大屏推荐 1920×1080 或更高分辨率。
- 生产需要 WinSW 服务包装器和 HTTPS 反向代理。为避免供应链不可控，
  仓库脚本不自动下载 WinSW，必须由运维提供经审批、校验摘要的可执行文件。

业务运行不需要 GPU、Java、外部求解器、Excel/WPS 或 Node.js。HiGHS 由
Platform 的 SciPy 依赖提供。Node.js 只用于 CI 的 JavaScript 语法检查或额外前端
开发，不是 8080/8090 两个 Python 服务的运行依赖。

### 3.2 建议资源

| 节点 | CPU | 内存 | 本地 SSD | 备注 |
|---|---:|---:|---:|---|
| 双端本机演示 | 4 核 | 8 GB | 20 GB 可用 | 合成数据，不用于监管认定 |
| 单矿 Agent 试点 | 2–4 核 | 8 GB | 50 GB 可用 | 按原件和隔离区保留期扩容 |
| 政府 Platform 试点 | 4–8 核 | 16 GB | 100 GB 可用 | 一个实例集中管理多矿 |
| 政府 Platform 正式起配 | 8 核 | 16–32 GB | 200 GB+ | 按实测并发、保留期和 RPO 调整 |

这些是工程起配，不是未经压测的容量承诺。上线前必须使用现场文件大小、
矿数、保留期和同时用户数做容量测试，并预留至少一份在线数据和一份恢复
演练的额外空间。

## 4. 安装前检查

在管理员 PowerShell 中执行：

```powershell
$PSVersionTable.PSVersion
py -0p
py -3.12 -c "import struct; assert struct.calcsize('P') == 8"
Get-Volume
Get-Service W32Time
w32tm /query /status
```

如脚本来自 Windows 标记为互联网来源的 ZIP，先验证发布包 SHA-256，再对已审批
的解压目录解锁；不要为整台机器永久放开执行策略：

```powershell
Get-FileHash -Algorithm SHA256 .\mineguard-release.zip
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

安装环境无法访问 PyPI 时，在同版本 Windows/Python x64 联网机上准备 wheelhouse，
连同清单和 SHA-256 转入内网。两端安装脚本都支持显式 wheelhouse；不得用
Linux wheel 或在内网机上临时绕过包校验。

## 5. Windows 脚本与安装顺序

### 5.1 政府 Platform

Windows 脚本位于 `platform\deploy\windows\`，按下列顺序使用：

1. `Install-MineGuardPlatform.ps1`：创建独立 runtime 并安装受约束的依赖；
2. `Set-MineGuardPlatformConfiguration.ps1`：写入平台设置、受保护的逐矿客户端注册
   文件和首个管理员口令；
3. `Start-MineGuardPlatform.ps1`：前台启动，用于首次验证；
4. `Test-MineGuardPlatform.ps1`：检查进程、健康和就绪状态；
5. `Install-MineGuardPlatformService.ps1`：显式传入已审批的 WinSW，安装
   Windows Service；
6. `Backup-MineGuardPlatform.ps1` / `Restore-MineGuardPlatform.ps1`：一致性备份、
   验证和恢复到新目录；
7. `Remove-MineGuardPlatformService.ps1`：只卸载服务，保留状态、备份和配置。

先查看脚本实际参数，再执行：

```powershell
Set-Location C:\MineGuard\source\platform
Get-Help .\deploy\windows\Install-MineGuardPlatform.ps1 -Full
Get-Help .\deploy\windows\Set-MineGuardPlatformConfiguration.ps1 -Full
Get-Help .\deploy\windows\Install-MineGuardPlatformService.ps1 -Full

.\deploy\windows\Install-MineGuardPlatform.ps1 `
  -SourceDirectory (Get-Location).Path
```

离线安装在最后一条命令上追加脚本帮助中的 `-Wheelhouse` 参数。配置、前台启动、
健康检查和服务安装的完整复制命令以 Platform Windows 说明为准。

### 5.2 每座煤矿的 Agent

Windows 脚本位于 `agent\deploy\windows\`，每座煤矿独立执行实例初始化和服务安装：

1. `Install-EnterpriseAgent.ps1`：创建独立 runtime，可使用离线 wheelhouse；
2. `New-EnterpriseAgentInstance.ps1`：为一座矿创建独立实例目录、数据库、端口和
   UTF-8 `KEY=VALUE` 配置；
3. `Start-EnterpriseAgent.ps1`：前台启动指定实例；
4. `Test-EnterpriseAgentHealth.ps1`：检查该矿的健康状态；
5. `Install-EnterpriseAgentService.ps1`：使用显式提供的 WinSW 安装该矿独立
   Windows Service；
6. `Backup-EnterpriseAgent.ps1` / `Restore-EnterpriseAgent.ps1`：逐矿停服一致性快照和带
   回滚材料的显式恢复；
7. `Uninstall-EnterpriseAgentService.ps1`：卸载该矿服务，保留配置、数据库、证据
   和备份。

```powershell
Set-Location C:\MineGuard\source\agent
Get-Help .\deploy\windows\Install-EnterpriseAgent.ps1 -Full
Get-Help .\deploy\windows\New-EnterpriseAgentInstance.ps1 -Full
Get-Help .\deploy\windows\Install-EnterpriseAgentService.ps1 -Full

.\deploy\windows\Install-EnterpriseAgent.ps1 `
  -SourceRoot (Get-Location).Path
```

不同煤矿不得共用实例目录、`ENTERPRISE_AGENT_DB`、端口、服务 ID、帐号、
监听目录、outbox/inbox cursor 或任何 HMAC 秘密。同一主机上的多个试点实例
也必须一矿一服务，但正式环境更推荐一矿一主机或虚拟机。

### 5.3 二进制正式运行不依赖虚拟环境

已签名的 Windows 安装包使用两个独立 standalone 入口：
`runtime\MineGuardPlatform.exe` 和 `runtime\MineGuardEnterpriseAgent.exe`。Windows Service
和运维脚本不依赖 `Activate.ps1`，正式服务安装会拒绝 `.venv` 回退。

仅在源码开发/联调时，如手工建立 `.venv`，入口位于：

```powershell
C:\path\to\platform\.venv\Scripts\mineguard.exe
C:\path\to\agent\.venv\Scripts\enterprise-agent.exe
```

源码联调出现 `mineguard: command not found` 或 `enterprise-agent: command not found` 时，
不要复用另一端的虚拟环境；直接调用本产品的绝对路径，或使用：

```powershell
& C:\path\to\platform\.venv\Scripts\python.exe -m mineguard --help
& C:\path\to\agent\.venv\Scripts\python.exe -m enterprise_agent --help
```

`serve` 是常驻服务，启动成功后 PowerShell 不返回不是“卡死”。前台调试时可用
`Ctrl+C` 停止；服务模式必须通过 WinSW/Service Control Manager 停止。

### 5.4 最短的双端演示

下列命令只用于一台 Windows 电脑上体验页面和混合来源演示数据，不创建 Windows
Service，也不完成真实矿井的 HMAC 注册。在 PowerShell A 中：

```powershell
Set-Location C:\MineGuard\source\platform
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install `
  -c .\constraints.txt -e .
& .\.venv\Scripts\python.exe -m pip install tzdata

& .\.venv\Scripts\mineguard.exe seed-v2-demo `
  --state-directory .\.mineguard-v2-demo-windows `
  --through-month 2026-07-31
& .\.venv\Scripts\mineguard.exe serve `
  --host 127.0.0.1 --port 8080 `
  --state-directory .\.mineguard-v2-demo-windows
```

结果包含 8 座程序合成教学矿（各 3 个月）以及太岳矿、梗阳矿两份固定 2026 年 7 月
ET 样表原值。后两者不会补数或平移月份，且未经过企业签名、单位和身份核验；整个状态
目录只用于演示，不得作为正式监管库。

在 PowerShell B 中：

```powershell
Set-Location C:\MineGuard\source\agent
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e . tzdata
$env:ENTERPRISE_AGENT_DB = `
  (Join-Path (Get-Location) 'data\windows-demo.db')
& .\.venv\Scripts\enterprise-agent.exe serve `
  --host 127.0.0.1 --port 8090
```

分别打开 <http://127.0.0.1:8080/> 和 <http://127.0.0.1:8090/>。全新回环演示的账号为
Platform `admin / 123123123`、Agent `demo / 123123123`；两者都不是生产
凭据。Agent 的 demo 账号不能完成真实确认和报送。要验收完整双端交换，
必须改用前述配置脚本，对齐矿井身份、两把密钥、政府注册项和具名企业
账号。

## 6. 配置和秘密

### 6.1 读取时机

Platform 客户端注册表、管理员密码，Agent 的矿井身份、用户、HMAC、Platform
地址、私有 CA 以及可选模型/搜索 API 配置，都在服务进程启动时读取。修改
配置后必须重启对应 Windows Service；已在运行的进程不会自动继承新的
环境变量。

Agent 的 `--env-file` 只解析严格 UTF-8 `KEY=VALUE` 文件，不会把它当 PowerShell
执行；进程中已显式设置的同名环境变量优先。Platform 使用受 ACL 保护的设置
文件和逐矿客户端 JSON，避免把大段 JSON 和秘密塞进 Windows Service XML。

### 6.2 秘密规则

- 演示初始口令 `123123123` 只允许用于回环演示。正式环境必须使用具名用户和
  独立强口令，并禁用或更换演示账号。
- 一座矿使用两把内容不同、至少 32 字节的高熵 HMAC 秘密：应用消息密钥和
  HTTP 运输密钥。不同煤矿不得复用。
- 企业应用签名 key 轮换后，把退役 key 作为单行 JSON 配置在
  `ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON`；它只验证历史 V3 前序，不能签发新消息，
  也不能由政府 `REGULATORY_PREVIOUS_*` 入站验签配置代替。协调换钥时同一双向共享的
  退役 secret 要分别登记，但两个方向仍按各自 key ID 精确选择。
- 模型服务、联网搜索和其他 API Key 只配在需要它的 Agent 服务端。不配置模型时，
  导入、确定性校验、报送、政府算法、报告收件和人工回复仍能工作。
- 不在命令行、WinSW XML、仓库、前端、截图、日志或工单中写口令、Cookie、
  HMAC 或 API Key。
- 已经在对话、终端、截图或 Git 中出现过的 API Key 必须视为已泄露：先在服务商
  后台撤销并生成新 Key，再更新受保护配置并重启 Agent。

Platform 服务基线使用专属虚拟账号 `NT SERVICE\MineGuardPlatform` 和确定性服务 SID，
不使用 `LocalSystem` 或共享的 `LocalService` 身份。配置文件和状态目录只给 `SYSTEM`、
`Administrators` 和对应专属服务 SID 的必需权限。不要依赖 Unix `chmod`；Windows 的
安全边界是 NTFS ACL。产品脚本的 ACL 收敛结果必须在现场通过 `Get-Acl` 复核。
Agent 同样为每个实例使用
`NT SERVICE\MineGuardEnterpriseAgent-<实例名>` 和该名称派生的唯一服务 SID；
不同煤矿实例不得共享数据目录、监听目录或应用/运输 HMAC。

## 7. HTTPS、端口和防火墙

### 7.1 端口基线

| 节点 | 应用监听 | 对网络暴露 | 网络方向 |
|---|---|---|---|
| Platform | `127.0.0.1:8080` | HTTPS 443 反向代理 | 接收各矿 Agent 和政府浏览器 |
| 每矿 Agent | `127.0.0.1:8090` 或该矿独立端口 | 本机浏览器，或 HTTPS 443 代理 | 主动出站访问 Platform |
| LLM/搜索 | 无入站端口 | 无 | Agent 可选受控出站 HTTPS 443 |

8080/8090 只监听 `127.0.0.1`，不对局域网创建入站防火墙放行规则。如果需要
远程浏览，由 IIS/ARR、Caddy、Nginx 或组织网关终止 TLS，只放行 443。
代理必须保留原始 path、query 和 body，不重新序列化已签名 JSON，不跟随或制造
重定向，不记录 Cookie、签名头、请求 body 或模型密钥。

检查端口和连通性：

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object LocalPort -In 443,8080,8090
Test-NetConnection regulatory.example.gov.cn -Port 443
```

政府边界防火墙应尽量只允许已知矿区出口和政府管理网段访问 443。Agent 只需
出站访问经审批的 Platform origin，以及启用后的模型/搜索 allowlist。

### 7.2 Cookie 和 CA

生产 Platform 必须启用 secure cookie；Agent 必须设置完整的 HTTPS public origin 和
secure cookie。Agent 访问政府私有 CA 时，将 CA bundle 配在该矿受保护的实例
配置中，不关闭 TLS 校验。证书的 SAN 必须包含实际使用的主机名。

## 8. 时钟和时区

Windows 默认没有 IANA tzdb，产品安装包必须内含已固定版本的 `tzdata`，否则
`Asia/Shanghai` 可能报 `ZoneInfoNotFoundError`。正式二进制不包含可供运维直接调用的
`runtime\Scripts\python.exe`；安装后用本产品入口验证：

```powershell
& 'C:\ProgramData\MineGuard\Platform\runtime\MineGuardPlatform.exe' self-check
& 'C:\Program Files\MineGuard\EnterpriseAgent\runtime\MineGuardEnterpriseAgent.exe' `
  --env-file 'C:\ProgramData\MineGuard\EnterpriseAgent\instances\<实例>\config\agent.env' `
  config-check --production
```

Platform 和全部 Agent 必须使用可靠时间源。HMAC 重放窗口、报表日期和审计时间都
依赖时钟：

```powershell
Get-Service W32Time
w32tm /query /source
w32tm /query /status
```

如偏差超出组织阈值，先由域管理员修复 Windows Time/GPO/NTP，不通过放大签名
时间窗口来掩盖问题。

## 9. Windows Service 生命周期

正式环境使用经审批的 WinSW，不用登录用户的“启动文件夹”、长期打开的
PowerShell 窗口或任务计划伪装常驻服务。每个服务必须：

- 使用唯一服务 ID 和显示名；
- 显式指向已经发布清单和 Authenticode 校验的本产品 standalone EXE；
- 只在自己的状态、日志和隔离目录可写；
- 配置文件路径可以写入 XML，但密钥和口令本身不得写入 XML；
- 异常退出可受控重启，手动停止不得形成无限重启；
- 日志轮转不得记录秘密或完整企业原始报文。

常用检查：

```powershell
Get-Service | Where-Object Name -Like '*MineGuard*'
Get-CimInstance Win32_Service |
  Where-Object Name -Like '*MineGuard*' |
  Select-Object Name,State,StartName,PathName
```

请使用两端自带的安装/卸载脚本变更服务，不手改 WinSW XML 中的生产密钥。
Agent 服务安装前会执行 `--env-file <绝对路径> config-check --production`，并拒绝
使用 `-SkipAcl` 创建的实例。`-AllowIncompleteDemo` 只用于隔离演示，不得用来绕过
生产身份、账号、HTTPS 或两把 HMAC 配置门槛。

Platform 服务必须从已安装目录的 `service` 子目录安装；脚本会复核产品
`release-metadata`、配置与状态目录身份，只接受无参数指向固定 wrapper 的
`Win32_Service.PathName`、`NT SERVICE\MineGuardPlatform` 专属虚拟账号和 unrestricted
服务 SID 类型。WinSW 必须提供外部批准的
SHA-256；若批准介质同时带 `WinSW.exe.config`，还必须显式传入其独立批准摘要：

```powershell
Set-Location 'C:\ProgramData\MineGuard\Platform\service'
.\Install-MineGuardPlatformService.ps1 `
  -WinSWExecutable 'D:\approved-media\WinSW-x64.exe' `
  -ExpectedSha256 '<批准的 WinSW EXE SHA-256>' `
  -ExpectedConfigSha256 '<仅在存在 .config 时提供其批准 SHA-256>' `
  -Production `
  -ExpectedSignerThumbprint '<介质外审批记录中的40位签名证书指纹>' `
  -StartService
```

服务文件先以同目录随机名完整写入并复核，再无覆盖发布。注册、启动或健康检查任一
失败时，脚本会撤销本次服务注册并删除本次创建的 wrapper 文件；如果同名服务归属
无法证明，则保留现场并报告回滚不完整。移除时每次停止和 `sc.exe delete` 前都会重新
核对完整、无参数的 `PathName`，并等待服务记录真正消失。默认保留 wrapper 以便审计；
需要重装时可在确认服务身份后使用：

```powershell
.\Remove-MineGuardPlatformService.ps1 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -RemoveWrapperFiles
```

以上两种移除方式都不会删除 `runtime/config/state/backups/logs` 中的业务数据。

## 10. 监控和故障处置

最少监控：

- Platform `/healthz` 和 `/readyz`；
- 每矿 Agent `/api/v1/health`，以及登录后 `/api/v2/status`；
- 服务运行时间、退出码、重启次数和日志增长；
- 各矿最近报送时间、outbox/inbox、分析耗时、HMAC 失败和重放拒绝；
- CPU、内存、本机盘可用空间、证书到期、Windows Time、备份成功率和恢复演练。

```powershell
Invoke-RestMethod http://127.0.0.1:8080/healthz
Invoke-RestMethod http://127.0.0.1:8080/readyz
Invoke-RestMethod http://127.0.0.1:8090/api/v1/health
Get-WinEvent -LogName Application -MaxEvents 100
```

| 现象 | 检查 |
|---|---|
| 终端启动后不返回 | 正常常驻状态；用健康端点确认，不重复启动 |
| `command not found` | 正式包直接用本产品 `runtime\MineGuardPlatform.exe` 或 `runtime\MineGuardEnterpriseAgent.exe` 的绝对路径 |
| `Address already in use` | `Get-NetTCPConnection -LocalPort 8080` 或指定 Agent 端口 |
| `/healthz` 成功但 `/readyz` 失败 | 进程存活但逐矿客户端注册/就绪配置不完整 |
| `ZoneInfoNotFoundError` | 核对该 runtime 是否安装 `tzdata` |
| HMAC 或时间超窗 | 核对 key ID、两把秘密的对应关系和 W32Time，不在日志中打印密钥 |
| 配置改了但行为没变 | 重启相应 Windows Service，再查健康和实例身份 |

## 11. 备份和恢复

### 11.1 Platform

Platform 使用产品级一致性备份，不在运行时直接拷贝 `.db/.db-wal/.db-shm`。
Windows 包装脚本为 `Backup-MineGuardPlatform.ps1` 和
`Restore-MineGuardPlatform.ps1`，底层调用 `mineguard backup`、
`verify-backup` 和 `restore-backup`。

- `backup.key` 不包含在业务备份中，必须另存到受控离线介质；
- 每次备份后立即执行验证；
- 恢复只允许指向不存在或空的新状态目录，不覆盖在线状态；
- 备份存储账号与 Platform 服务账号分离，同时保留离线/不可改写副本。

### 11.2 Agent

每矿独立运行 `Backup-EnterpriseAgent.ps1`。备份必须覆盖该矿数据库、outbox/inbox、
cursor、回复、审计和 quarantine，并在一致状态下生成。恢复使用
`Restore-EnterpriseAgent.ps1`：它要求服务已停止、显式 `-ConfirmRestore`，校验实例/矿井
归属、文件集、大小和 SHA-256，并在替换当前数据库和 quarantine 前保留回滚材料。
最稳妥的演练方式是在隔离的 `StateRoot` 先创建同身份测试实例并恢复，而不是直接
操作在线实例。不要在 Agent 运行时用 Explorer/Robocopy 只复制 SQLite 主文件。
业务状态快照故意不包含 `agent.env` 和秘密；它们必须由独立的配置/密钥备份和恢复
流程管理。

每季至少做一次隔离恢复演练，记录实测 RPO/RTO。恢复后先在隔离网络验证审计
链、身份、报告 cursor 和未发 outbox，再恢复外部连接，避免重复报送。

## 12. 升级和回滚

1. 记录当前发布包 SHA-256、Python/产品/契约/算法版本和配置摘要；
2. 确认 Agent outbox 、Platform 分析队列和备份状态，安排变更窗口；
3. 生成并验证一致性备份，把密钥备份与业务备份分开保管；
4. 停止该实例的 Windows Service，将新版安装到新 runtime/发布目录，不覆盖原
   runtime；如同机多个 Agent 共用安装的 runtime，升级期间必须同时停止该主机
   全部 Agent 服务；
5. 使用同一受保护配置和隔离恢复副本执行契约、CLI、健康和业务回归；
6. 切换服务到新 runtime，启动后检查身份、就绪、报送/收件、审计和大屏；
7. 变更失败时先保全新版日志和状态副本。只回切可执行文件不代表数据库可以
   降级；如已发生不可逆迁移，必须从已验证备份恢复到新目录。

不要在在线数据库上反复安装不同版本做“尝试”，也不使用 `pip install -U` 无约束
升级算法依赖。Platform 必须使用发布的 `constraints.txt`。

## 13. 上线验收清单

### 安装与边界

- [ ] Windows 版本、Python 3.12 x64、PowerShell 和发布包 SHA-256 已记录。
- [ ] `ZoneInfo('Asia/Shanghai')` 在 Platform 和每个 Agent runtime 中通过。
- [ ] Platform 与每矿 Agent 有独立 runtime、状态目录、账号和服务 ID。
- [ ] 每个 Agent 只绑定一座矿，矿井/经营主体/sender 与政府注册一致。
- [ ] SQLite 和状态位于本地 NTFS，不位于共享目录或同步盘。
- [ ] PowerShell 5.1 AST 解析、契约、两端测试、CLI 和 Windows health smoke 全部通过。

### 账号与秘密

- [ ] 已更换 `123123123`，生产不启用可提交的演示账号。
- [ ] 所有曾在对话/终端/仓库出现的 API Key 已撤销并换新。
- [ ] 每矿两把不同 HMAC，且各矿不复用；政府注册表与 Agent 配置相互对应。
- [ ] 秘密不在命令行、XML、仓库、前端或日志，NTFS ACL 已按服务账号复核。
- [ ] 配置变更后的服务重启和密钥轮换重叠窗口已演练。

### 网络与运行

- [ ] 8080/8090 只监听回环；只有 HTTPS 443 按最小网段暴露。
- [ ] 反向代理不修改签名 path/query/body，不记录 Cookie、签名或 body。
- [ ] 企业 Agent 只有所需的 Platform/模型/搜索 HTTPS 出站 allowlist。
- [ ] Windows Time 来源、偏差和告警正常；证书主机名、链和到期告警通过。
- [ ] 重启后 Platform 就绪，Agent 身份正确，未发 outbox 继续且不重复分析。

### 数据与灾备

- [ ] Platform 备份及 `verify-backup` 成功，`backup.key` 已分离离线保管。
- [ ] 每矿 Agent 备份包含 DB、outbox/inbox、cursor、回复、审计和 quarantine。
- [ ] 两端都已恢复到新目录并完成隔离验证，RPO/RTO 有实测记录。
- [ ] 断网、进程崩溃、磁盘接近满、证书到期和密钥泄露演练通过。

完成本清单后，再执行 [十量 V3 上线门槛](十量V3部署与运行.md#6-正式上线门槛)的业务、算法、隔离、
幂等、风险回复和修订重算验收。

## 14. WSL2 的定位

WSL2 适合开发、Linux 命令联调和临时演示，但不是本 Windows 生产方案。原因包括
Windows 重启后 WSL 实例和 systemd 生命周期、NAT/防火墙、Windows 与 Linux 路径、监听目录
事件和服务账号边界都与原生 Windows Service 不同。

如开发时使用 WSL2：

- 代码、`.venv` 和 SQLite 都放在 WSL 的 ext4 文件系统，不放在 `/mnt/c`；
- 完全按 Linux 文档安装和启动，不混用 Windows Python 虚拟环境；
- 不把 WSL2 开发成功当作 Windows 原生发布验收；
- 正式上线必须重新执行 Windows CI 和第 13 节现场清单。
