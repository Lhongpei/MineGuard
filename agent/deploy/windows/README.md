# 企业端 Agent：Windows 原生部署

本目录提供企业端 Agent 的 Windows PowerShell 5.1 部署方案。它不会下载 WinSW，
不会把用户密码、模型密钥或两把 HMAC 密钥写入服务 XML/命令行，也不会执行配置文件。
每个实例分别拥有端口、Windows 服务名、配置目录、SQLite 状态库、日志和备份目录。

## 1. 支持基线

- Windows 10/11 x64，或 Windows Server 2019/2022 x64；
- Windows PowerShell 5.1（以管理员身份运行安装和服务命令）；
- 正式二进制发行包不要求目标机安装 Python、编译器、Node.js 或源码；
- 本机固定 NTFS 磁盘；数据库不得放在 UNC、映射网络盘、OneDrive 或同步目录；
- 新版 Edge/Chrome；不需要 GPU、Java、Excel 或外部数据库；
- 如需服务托管，另行从单位批准的软件源取得 WinSW，并取得发布方 SHA-256。

发行目录中的 `runtime\MineGuardEnterpriseAgent.exe` 是基于 CPython 3.12 x64 和固定依赖
构建的 Nuitka standalone 程序，并携带 Windows 所需的 `tzdata`。目标机不能只复制单个
EXE；必须完整保留 `runtime` 目录中的 DLL、时区数据和 `web` 前端资源。

一个实例只能绑定一个煤矿。不同经营主体原则上应使用不同 Windows 主机或虚拟机，
不能依靠同一台机器上的目录区分来代替企业之间的安全边界。若同机部署多个测试实例，
仍必须为每个实例分配不同 `InstanceName`、端口、系统身份、状态库和逐矿密钥。

## 2. 安装二进制发行包

交付介质目录类似：

```text
MineGuardEnterpriseAgent-0.2.1-windows-x64\
  runtime\MineGuardEnterpriseAgent.exe
  runtime\web\...
  deploy\windows\...
  release-manifest.json
  SHA256SUMS.txt
```

该目录不包含企业 Agent 的 Python 源码、测试或 Git 历史。先校验交付方另行提供的
安装器签名/散列，再在管理员 PowerShell 5.1 中执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass

cd D:\approved-media\MineGuardEnterpriseAgent-0.2.1-windows-x64\deploy\windows
.\Install-EnterpriseAgent.ps1
```

默认程序安装到 `C:\Program Files\MineGuard\EnterpriseAgent`，实例状态放到
`C:\ProgramData\MineGuard\EnterpriseAgent\instances`。路径中可以包含中文或空格。
安装器会在实例状态根写入 `.mineguard-enterprise-agent-instances.json` 所有权标记；
后续创建煤矿实例前会复核该标记。首次安装只接管空目录；未带标记的旧目录仅在其中
每个顶层目录都能识别为既有 Agent 实例时才会迁移。`ProgramData`、`Users`、`Windows`、
`Program Files` 等宽泛系统目录不能直接作为状态根，目录树内也不能含链接或重解析点。

脚本会先逐项校验 `release-manifest.json` 中的大小和 SHA-256，拒绝新增/缺失文件、路径
穿越、符号链接和重解析点，再把完整 standalone 运行目录安装到 Program Files。校验清单
用于发现介质损坏，发行真实性仍应依赖单位批准的 Authenticode 签名和可信交付链。
安装完成后，`C:\Program Files\MineGuard\EnterpriseAgent\release-metadata` 会保留版本、
构建信息、发行清单和校验和，供验收、升级比对和事件追溯。

从源码创建 Python 虚拟环境只保留为内部开发兼容路径，不属于交付方案。开发人员才可
在源码目录显式执行：

```powershell
cd C:\src\coral\agent\deploy\windows
.\Install-EnterpriseAgent.ps1 -BuildFromSource
```

正式验收应确认 `runtime\MineGuardEnterpriseAgent.exe` 存在，且运行不依赖 `.venv`、
系统 Python、仓库源码或网络下载。

## 3. 创建逐矿实例

```powershell
cd 'C:\Program Files\MineGuard\EnterpriseAgent\deploy\windows'

.\New-EnterpriseAgentInstance.ps1 `
  -InstanceName qinyuan-001 `
  -MineId MINE-QY-001 `
  -MineName '示例一号煤矿' `
  -OperatorId operator-qy-001 `
  -OperatorName '示例一号煤业有限公司' `
  -SystemId agent-mine-qy-001 `
  -Port 8090
```

`InstanceName` 只允许 1–64 位 ASCII 字母、数字、点、下划线和短横线，并拒绝
`CON/NUL/COM1` 等 Windows 保留设备名；合同中的 `MineId` 不拿来拼 Windows 路径。
脚本会检查端口是否已被其他已创建实例占用，并默认创建本矿收件目录：

```text
C:\ProgramData\MineGuard\EnterpriseAgent\instances\qinyuan-001\
  config\agent.env
  data\enterprise-agent.db
  data\five-quantity-quarantine\
  inbox\
  logs\
  backups\
  service\
  instance.json
```

状态目录 ACL 只给 SYSTEM、Administrators 和 LocalService 必要权限。`-SkipAcl` 仅供
非管理员本机开发；WinSW 正式服务安装会拒绝这种实例。外部设备导出目录需另外给予
LocalService（SID `S-1-5-19`）读取权限，不应给予删除来源原件的权限。
只有显式传入 `-GrantWatchReadAcl` 时，创建脚本才会在经过校验的专用监听目录根设置可继承
只读 ACE；它不会递归改写设备或厂商已有文件的 ACL。UNC、映射盘、链接/重解析点、系统
宽泛目录，以及与 `InstallRoot`/`StateRoot` 重叠的目录都会被拒绝；默认不修改外部目录权限。
实例本身先在 `StateRoot` 内的 GUID 暂存目录完整生成并加固 ACL，校验通过后再同卷原子改名，
失败会清理未发布实例并尽力恢复本次变更的外部监听目录 ACL。
备份目录只允许 SYSTEM 和 Administrators 写入，Agent 服务账号不能修改自身备份。

## 4. 配置账号、政府接口和模型 API

编辑本实例的 `config\agent.env`。它是严格 UTF-8 `KEY=VALUE` 数据文件，不是
PowerShell 脚本，不支持变量展开或命令替换，也不要 dot-source。进程只在启动时读取，
修改后必须重启对应实例。

生成正式账号密码摘要：

```powershell
& 'C:\Program Files\MineGuard\EnterpriseAgent\runtime\MineGuardEnterpriseAgent.exe' hash-password
```

将摘要写入单行 `ENTERPRISE_AGENT_USERS_JSON`；不能写明文密码。演示账号
`demo / 123123123` 只允许回环演示，不能确认或报送。

政府 V2 接口至少配置：

```text
PLATFORM_V2_BASE_URL=https://regulator.example
PLATFORM_V2_SENDER_ID=agent-mine-qy-001
ENTERPRISE_EXCHANGE_KEY_ID=enterprise-key-v2
REGULATORY_EXCHANGE_KEY_ID=regulator-key-v2
ENTERPRISE_EXCHANGE_HMAC_SECRET=<由密钥系统注入的应用消息密钥>
PLATFORM_V2_TRANSPORT_HMAC_SECRET=<不同的运输密钥>
```

两把 HMAC 密钥必须不同且至少 32 字节。模型只影响可选对话/新闻功能：

```text
DEEPSEEK_API_KEY=<由密钥系统注入>
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=<单位批准的模型>
```

多个监听目录在 Windows 使用分号，例如：

```text
ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS=D:\FiveQuantity\Inbox;E:\ApprovedExport
```

## 5. 前台验证

```powershell
cd 'C:\Program Files\MineGuard\EnterpriseAgent\deploy\windows'
.\Start-EnterpriseAgent.ps1 -InstanceName qinyuan-001
```

终端持续占用是 HTTP 服务正常运行，不是卡死。另开一个 PowerShell：

```powershell
.\Test-EnterpriseAgentHealth.ps1 -InstanceName qinyuan-001
```

启动和健康脚本会同时复核状态根所有权标记、实例元数据、配置中的煤矿/系统/端口/数据库
身份、服务包装器实际路径以及对应进程；同一端口上另一个煤矿 Agent 返回通用 200 不会被
当成当前实例健康。运维脚本要求所有程序、状态和快照路径为显式 `X:\...` 本地固定 NTFS
路径，并拒绝 UNC、映射盘、盘符相对路径和任何祖先或受控目录树内的重解析点。

浏览器打开 `http://127.0.0.1:8090/`。正式环境仍只让 Agent 监听回环地址，由单位批准的
IIS/Caddy/Nginx 反向代理统一提供 HTTPS；不要把 8090 直接开放到办公网或公网。

## 6. 安装为 Windows 服务

本项目不下载、不捆绑 WinSW。先从批准渠道准备 WinSW x64 可执行文件并核对其官方
SHA-256，然后执行：

```powershell
$WinSW = 'D:\approved-tools\WinSW-x64.exe'
$ExpectedHash = '<从已批准发布清单抄录的64位SHA-256>'

.\Install-EnterpriseAgentService.ps1 `
  -InstanceName qinyuan-001 `
  -WinSWPath $WinSW `
  -WinSWExpectedSha256 $ExpectedHash `
  -Start
```

生产变更单中应填写预先从可信渠道获得的散列值，不应把对当前未知文件现场计算的值当成
供应链校验。服务名为 `MineGuardEnterpriseAgent-qinyuan-001`，使用 LocalService，
自动延迟启动；stdout/stderr 按 10 MiB 滚动，保留 14 个文件。XML 只包含可执行文件和
ACL 受控环境文件路径，不包含秘密。

服务脚本只接受本机固定 NTFS 磁盘上的 `X:\...` 绝对路径，拒绝 UNC、盘符相对路径、
NTFS ADS、链接、目录联接和挂载点；安装时会严格核对状态根所有权标记及 `instance.json`，
并在复制 WinSW 前后都核对批准的 SHA-256。既有 wrapper 或同名服务不会被覆盖。wrapper
与 XML 先在实例 `service` 目录中完整落盘后原子发布；注册或启动失败会撤销本次服务注册
并清理本次文件，不留下可继续误用的半安装状态。

服务安装默认执行 `config-check --production`：必须有正式账号、HTTPS 浏览器 origin、
Secure Cookie、HTTPS 政府 V2 地址、两把不同 HMAC 密钥、正式 key ID 和完整同类矿分组。
仅离线演示可显式传 `-AllowIncompleteDemo`；该开关不能用于生产验收。

```powershell
Get-Service MineGuardEnterpriseAgent-qinyuan-001
Get-Content 'C:\ProgramData\MineGuard\EnterpriseAgent\instances\qinyuan-001\logs\*.log' -Tail 200
Restart-Service MineGuardEnterpriseAgent-qinyuan-001
```

卸载服务会保留配置、数据库、证据和备份：

```powershell
.\Uninstall-EnterpriseAgentService.ps1 -InstanceName qinyuan-001
```

卸载会从 `Win32_Service` 读取已注册的 `PathName`，只有它精确指向该实例应有的 wrapper
时才停止和删除服务；同名服务若指向别处会被视为劫持并拒绝操作。默认保留 wrapper/XML
供审计或重装；确认不再需要时可显式加 `-RemoveWrapperFiles`，该开关也只删除这两个精确
文件，实例的配置、数据库、原始证据、日志和备份均保留。

## 7. 业务状态备份与恢复

完整业务状态不只有 SQLite，还包含 `five-quantity-quarantine` 中的原始隔离证据。
备份脚本会短暂停止已安装服务，使用 SQLite backup API 生成一致数据库，同时复制隔离
目录并为每个文件记录 SHA-256：

```powershell
New-Item -ItemType Directory 'E:\MineGuardBackups' -Force
icacls.exe 'E:\MineGuardBackups' /inheritance:r
icacls.exe 'E:\MineGuardBackups' /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'

.\Backup-EnterpriseAgent.ps1 `
  -InstanceName qinyuan-001 `
  -DestinationRoot E:\MineGuardBackups
```

配置和业务密钥故意不进入业务状态快照，应由独立密钥/配置备份流程恢复。首次备份会用
Windows CSPRNG 在本实例 `backups\snapshot-auth.key` 创建独立 32 字节快照认证密钥；其
ACL 禁止继承且只允许 SYSTEM/Administrators，Agent 服务账号不能读取。`state-snapshot-v2`
对固定身份字段和按路径排序的完整文件清单做 HMAC-SHA256，并记录非秘密的密钥指纹；
恢复时先核对指纹，再常量时间校验 HMAC，密钥绝不写入快照。

必须把 `snapshot-auth.key` 通过单位密钥托管单独离线备份；只拿到快照而丢失密钥无法恢复，
而把密钥放进同一个快照会完全破坏来源认证。密钥轮换前应按保留期保存旧密钥和对应关系。
灾难恢复或旧密钥轮换时不必覆盖当前默认密钥，可把托管系统恢复出的 32 字节原始密钥放在
预先加固的本地固定 NTFS 目录，并在备份或恢复命令传入
`-SnapshotAuthenticationKeyFile E:\MineGuardKeyEscrow\qinyuan-001-2026.key`。脚本会对显式
路径执行相同的无重解析点检查，并要求该文件关闭 ACL 继承、仅 SYSTEM/Administrators
拥有 FullControl；备份时若显式文件尚不存在，会安全生成，恢复时绝不会自动生成替代密钥。
密钥路径必须位于快照目录之外，恢复脚本拒绝把随快照一起交付的“自带密钥”当成独立信任锚。
显式密钥目录可先由管理员建立并收紧（不要对盘根或共享宽泛目录执行）：

```powershell
New-Item -ItemType Directory 'E:\MineGuardKeyEscrow' -Force
icacls.exe 'E:\MineGuardKeyEscrow' /inheritance:r
icacls.exe 'E:\MineGuardKeyEscrow' /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
```

快照还会把 ACL 收紧为仅 SYSTEM/Administrators 可修改，并限制为最多 10000 个文件、
单文件 32 GiB、总计 256 GiB；备份和恢复仅接受本地固定 NTFS 目录。历史未认证 v1 快照
默认拒绝，仅在批准的遗留恢复流程中显式传 `-AllowUnauthenticatedLegacySnapshot` 才会
继续，且 SHA-256 一致不能表述为来源可信。

恢复会校验快照文件集合、大小和 SHA-256，核对实例与煤矿，拒绝仍在运行的 Windows
服务或前台进程，并在覆盖前保留当前数据库和隔离目录：

```powershell
Stop-Service MineGuardEnterpriseAgent-qinyuan-001

.\Restore-EnterpriseAgent.ps1 `
  -InstanceName qinyuan-001 `
  -SnapshotPath 'E:\MineGuardBackups\qinyuan-001-20260802T120000Z' `
  -SnapshotAuthenticationKeyFile 'E:\MineGuardKeyEscrow\qinyuan-001-2026.key' `
  -ConfirmRestore `
  -StartAfterRestore

.\Test-EnterpriseAgentHealth.ps1 -InstanceName qinyuan-001
```

回滚材料保存在实例的 `backups\restore-rollbacks`。恢复完成后还要登录检查 V2 audit、
outbox、cursor、风险报告回执和隔离记录，不能只看 health 为 200。
恢复的目录创建、复制和替换全部位于 `ShouldProcess` 确认之后；`-WhatIf` 不会写磁盘。
数据库和隔离证据使用 GUID 事务目录切换，失败时保留恢复材料并优先恢复原隔离证据。

## 8. 更新与排障

更新前先做状态快照，停止全部实例服务，从已验签的新二进制发行目录重新运行
`Install-EnterpriseAgent.ps1`，再逐个启动和健康检查。共享运行时更新期间所有实例必须
保持停止，避免一半进程加载旧代码、一半加载新代码。

- `tzdata`/时区错误：确认完整安装了发行包的 `runtime` 目录，没有只复制 EXE；
- `已有企业 Agent 进程运行`：同一状态库已经被前台或服务进程锁定；
- 端口占用：给不同实例设置不同端口，不要共用状态库；
- 配置解析错误：保持绝对路径、UTF-8、一行一个 `KEY=VALUE`，不要复制 PowerShell 语法；
- 服务无法读固定目录：为 LocalService SID `S-1-5-19` 增加只读 ACL；
- API 设置修改后无变化：配置只在进程启动时加载，重启对应服务。

政府 Platform 另有独立的 Windows 原生基线；实际可按单位运维、备份和高可用能力选择
Windows 或 Linux。企业 Agent 与政府 Platform 只通过 V2 HTTP/JSON 合同通信，不共享
代码、数据库或服务账号。

## 9. 内部构建二进制发行目录

本节仅供研发构建机使用，不随用户交付。构建机需要 Windows 10/11 或 Windows Server
x64、CPython 3.12 x64，以及 Visual Studio 2022 Build Tools 的“使用 C++ 的桌面开发”
工作负载。构建脚本固定 Nuitka 版本，生成 standalone 而不是 onefile：

```powershell
cd C:\src\coral\agent
.\packaging\windows\Build-EnterpriseAgentBinary.ps1
```

联网的一次性 CI 首次准备 Nuitka 工具缓存时可显式传
`-AllowNuitkaToolDownloads`；正式隔离构建应从批准介质预置该缓存，传入完整
`-Wheelhouse`，并且不要使用下载开关。

输出位于 `artifacts\MineGuardEnterpriseAgent-<版本>-windows-x64`。构建默认实际启动冻结
程序，检查 `/api/v1/health` 和内嵌前端，并拒绝 runtime 中的 `.py/.pyc/C/C++` 源文件。
隔离构建可传入含构建工具及全部 Python 依赖的 `-Wheelhouse`；脚本不会在该模式回退公网。
