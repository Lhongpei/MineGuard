# 企业端 Agent：Windows 原生部署

本目录提供企业端 Agent 的 Windows PowerShell 5.1 部署方案。它不会下载 WinSW，
不会把用户密码、模型密钥或两把 HMAC 密钥写入服务 XML/命令行，也不会执行配置文件。
每个实例分别拥有端口、Windows 服务名、配置目录、SQLite 状态库、日志和备份目录。

## 1. 支持基线

- Windows 10/11 x64，或 Windows Server 2019/2022 x64；
- Windows PowerShell 5.1（以管理员身份运行安装和服务命令）；
- CPython 3.12 x64，安装时可使用 `py -3.12`；
- 本机固定 NTFS 磁盘；数据库不得放在 UNC、映射网络盘、OneDrive 或同步目录；
- 新版 Edge/Chrome；不需要 GPU、Node.js、Java、Excel 或外部数据库；
- 如需服务托管，另行从单位批准的软件源取得 WinSW，并取得发布方 SHA-256。

Python 包通过 `agent/constraints.txt` 固定到经 Python 3.12 验证的版本。Windows 会安装
`tzdata`，因此 `Asia/Shanghai` 在没有系统 IANA 时区库时仍能工作。

一个实例只能绑定一个煤矿。不同经营主体原则上应使用不同 Windows 主机或虚拟机，
不能依靠同一台机器上的目录区分来代替企业之间的安全边界。若同机部署多个测试实例，
仍必须为每个实例分配不同 `InstanceName`、端口、系统身份、状态库和逐矿密钥。

## 2. 安装运行时

在管理员 PowerShell 5.1 中执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass

cd C:\src\coral\agent\deploy\windows
.\Install-EnterpriseAgent.ps1
```

默认程序安装到 `C:\Program Files\MineGuard\EnterpriseAgent`，实例状态放到
`C:\ProgramData\MineGuard\EnterpriseAgent\instances`。路径中可以包含中文或空格。

隔离网络先在一台联网的 Windows/Python 3.12 机器准备 wheelhouse：

```powershell
cd C:\src\coral\agent
py -3.12 -m pip wheel --constraint .\constraints.txt --wheel-dir D:\agent-wheelhouse .
```

把完整目录送入目标机后离线安装：

```powershell
cd C:\src\coral\agent\deploy\windows
.\Install-EnterpriseAgent.ps1 -Wheelhouse D:\agent-wheelhouse
```

脚本要求 wheelhouse 同时包含 `enterprise_reporting_agent-*.whl` 及全部依赖，不会在
离线模式回退到公网。

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
只有显式传入 `-GrantWatchReadAcl` 时，创建脚本才会为自定义监听目录递归增加该只读
ACE；默认不修改设备或厂商目录的权限。
备份目录只允许 SYSTEM 和 Administrators 写入，Agent 服务账号不能修改自身备份。

## 4. 配置账号、政府接口和模型 API

编辑本实例的 `config\agent.env`。它是严格 UTF-8 `KEY=VALUE` 数据文件，不是
PowerShell 脚本，不支持变量展开或命令替换，也不要 dot-source。进程只在启动时读取，
修改后必须重启对应实例。

生成正式账号密码摘要：

```powershell
& 'C:\Program Files\MineGuard\EnterpriseAgent\runtime\.venv\Scripts\enterprise-agent.exe' hash-password
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

## 7. 业务状态备份与恢复

完整业务状态不只有 SQLite，还包含 `five-quantity-quarantine` 中的原始隔离证据。
备份脚本会短暂停止已安装服务，使用 SQLite backup API 生成一致数据库，同时复制隔离
目录并为每个文件记录 SHA-256：

```powershell
.\Backup-EnterpriseAgent.ps1 `
  -InstanceName qinyuan-001 `
  -DestinationRoot E:\MineGuardBackups
```

配置和密钥故意不进入业务状态快照，应由独立密钥/配置备份流程恢复。快照 SHA-256 只能
发现传输损坏，不能证明来源真实性；应把快照复制到受 ACL、BitLocker 和独立备份系统
保护的介质，并由备份系统提供不可变/HMAC 或签名能力。

恢复会校验快照文件集合、大小和 SHA-256，核对实例与煤矿，拒绝仍在运行的 Windows
服务或前台进程，并在覆盖前保留当前数据库和隔离目录：

```powershell
Stop-Service MineGuardEnterpriseAgent-qinyuan-001

.\Restore-EnterpriseAgent.ps1 `
  -InstanceName qinyuan-001 `
  -SnapshotPath 'E:\MineGuardBackups\qinyuan-001-20260802T120000Z' `
  -ConfirmRestore `
  -StartAfterRestore

.\Test-EnterpriseAgentHealth.ps1 -InstanceName qinyuan-001
```

回滚材料保存在实例的 `backups\restore-rollbacks`。恢复完成后还要登录检查 V2 audit、
outbox、cursor、风险报告回执和隔离记录，不能只看 health 为 200。

## 8. 更新与排障

更新前先做状态快照，停止全部实例服务，使用新代码重新运行
`Install-EnterpriseAgent.ps1`，再逐个启动和健康检查。共享运行时更新期间所有实例必须
保持停止，避免一半进程加载旧代码、一半加载新代码。

- `tzdata`/时区错误：确认使用安装脚本创建的 Python 3.12 venv；
- `已有企业 Agent 进程运行`：同一状态库已经被前台或服务进程锁定；
- 端口占用：给不同实例设置不同端口，不要共用状态库；
- 配置解析错误：保持绝对路径、UTF-8、一行一个 `KEY=VALUE`，不要复制 PowerShell 语法；
- 服务无法读固定目录：为 LocalService SID `S-1-5-19` 增加只读 ACL；
- API 设置修改后无变化：配置只在进程启动时加载，重启对应服务。

政府 Platform 另有独立的 Windows 原生基线；实际可按单位运维、备份和高可用能力选择
Windows 或 Linux。企业 Agent 与政府 Platform 只通过 V2 HTTP/JSON 合同通信，不共享
代码、数据库或服务账号。
