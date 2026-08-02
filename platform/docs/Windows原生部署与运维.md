# MineGuard Platform Windows 原生部署与运维

本文适用于政府侧 `platform/`。企业侧 Agent 有自己的 Windows 安装和状态目录，两个
软件不能共用虚拟环境、配置、密钥或 SQLite 文件。

## 1. 已支持的 Windows 基线

- Windows 10/11 x64（演示、运维终端）或 Windows Server 2019/2022 x64；
- 当前经约束验证的 CPython 3.12 x64；安装脚本会拒绝其他 Python 小版本；
- Windows PowerShell 5.1；脚本不依赖 PowerShell 7，也不需要执行虚拟环境激活脚本；
- 本机 NTFS SSD；状态库不得位于 UNC/SMB、映射网络盘、OneDrive 或其他同步目录；
- 新版 Edge/Chrome；领导大屏建议 1920×1080 或更高分辨率；
- 准确的 Windows 时间同步；报文 HMAC 的可接受时间窗为 5 分钟；
- 不需要 GPU、Java、Node.js、Office/WPS 或单独安装 HiGHS。

Windows 没有系统 IANA 时区库。本发布把 `tzdata` 固定为运行依赖，并把版本写进算法
运行清单，保证 `Asia/Shanghai` 统计窗口和导出时间可以追溯。

推荐目录由安装脚本创建：

```text
C:\ProgramData\MineGuard\Platform\
  runtime\       独立 Python 运行时（LocalService 只读）
  config\        settings.json、clients.json、首启密码文件（只读 ACL）
  state\         mineguard.db、auth.db、backup.key（LocalService 可写）
  backups\       在线一致性备份（LocalService 可写）
  logs\          WinSW 滚动日志（LocalService 可写）
  service\       PowerShell 包装和 WinSW XML（LocalService 只读）
```

安装脚本用 SID 设置 ACL，避免中文 Windows 上内置账号名称本地化造成权限错误。默认
服务身份是低权限 `LocalService`（SID `S-1-5-19`），不是 `LocalSystem`。

## 2. 在线安装

在“以管理员身份运行”的 **Windows PowerShell 5.1** 中进入解压后的 `platform`
目录：

```powershell
# 先按独立发布清单核验整个交付包；确认可信后只为当前进程放行脚本。
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

& .\deploy\windows\Install-MineGuardPlatform.ps1 `
  -SourceDirectory $PWD.Path `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform'
```

脚本创建隔离运行时、按照 `constraints.txt` 安装依赖、验证 NumPy/SciPy/HiGHS 和上海
时区，并设置最小 NTFS 权限。它不会激活虚拟环境，不会创建服务，也不会下载 WinSW。

## 3. 无互联网内网安装

先在相同 Python 3.12 x64/Windows 架构的联网交付机准备经审批的 wheelhouse。它至少
要包含 `constraints.txt` 中所有包、`setuptools>=68` 及其 Windows `win_amd64` wheel。
将源码、wheelhouse、文件清单和 SHA-256 一并通过正式介质转入内网，然后运行：

```powershell
& .\deploy\windows\Install-MineGuardPlatform.ps1 `
  -SourceDirectory $PWD.Path `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -Wheelhouse 'D:\ApprovedWheelhouse'
```

指定 `-Wheelhouse` 后脚本强制使用 `--no-index`，不会回退到互联网。缺少任何兼容
wheel 都会中止安装。

## 4. 配置多矿注册表和首次管理员

复制 [clients.json.example](../deploy/windows/clients.json.example) 到受控临时目录，
为每座矿配置一个独立 Agent 身份。消息 HMAC 与 HTTP 运输 HMAC 必须是两把不同的
随机秘密，各至少 32 字节。不要使用示例占位符，不要通过聊天、命令行参数或工单正文
传递秘密。示例中的 `REPLACE` 被故意设计成不能通过校验；配置、服务安装和每次启动
还会再次拒绝常见 `REPLACE`、`CHANGE_ME`、`DEMO_ONLY` 等占位秘密。

政府端支持两种兼容入口：

- `MINEGUARD_V2_CLIENTS_FILE`：Windows 正式推荐；文件最大 4 MiB，支持 UTF-8/BOM；
- `MINEGUARD_V2_CLIENTS_JSON`：保留兼容，不适合多矿 Windows 环境块。

两者同时设置会拒绝启动。文件必须是绝对路径、普通文件，且路径中不能有符号链接、
junction 或其他 reparse point。

使用安全提示输入管理员密码，然后配置：

```powershell
$adminPassword = Read-Host '首次管理员密码' -AsSecureString

& 'C:\ProgramData\MineGuard\Platform\service\Set-MineGuardPlatformConfiguration.ps1' `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -ClientsFile 'D:\SecureDelivery\clients.json' `
  -PlatformSystemId 'mineguard-qinyuan' `
  -PlatformPartyId 'regulator-qinyuan' `
  -PlatformKeyId 'regulator-key-v2' `
  -AdminPassword $adminPassword

Remove-Variable adminPassword
```

配置脚本先用产品本身完整校验注册表，再原样复制到受 ACL 保护的
`config\clients.json`。密码不会进入 WinSW XML、命令行、日志或 `settings.json`；
首启文件仅用于建立 `auth.db` 中的 scrypt 密码摘要。

正式配置默认启用 Secure Cookie，浏览器必须通过 HTTPS 反向代理访问。只在隔离本机
演示时显式添加 `-HttpOnlyDemo`。只看合成数据且不接 Agent 时，可以显式使用：

```powershell
$demoPassword = Read-Host '演示管理员密码' -AsSecureString
& 'C:\ProgramData\MineGuard\Platform\service\Set-MineGuardPlatformConfiguration.ps1' `
  -DemoWithoutClientRegistry -HttpOnlyDemo -AdminPassword $demoPassword
```

`-AllowDemoDefaultPassword` 只允许与 `-DemoWithoutClientRegistry` 同用，且安装服务时会
给出醒目警告；正式环境绝对不能使用。

## 5. 前台启动和检查

先以前台方式完成首启验证：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Start-MineGuardPlatform.ps1'
```

终端保持占用代表服务正在运行，不是卡死。另开窗口执行：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Test-MineGuardPlatform.ps1'
```

`/healthz` 表示进程可响应；`/readyz` 还要求至少配置一座矿。合成演示无客户端注册表
时使用 `-HealthOnly`。验证首启已经创建管理员后，删除明文首启文件：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Set-MineGuardPlatformConfiguration.ps1' `
  -ClearBootstrapPassword
```

该命令会先只读确认当前 `auth.db` 至少有一个用户；没有账号时拒绝删除，避免锁死。

## 6. 安装为 Windows 服务（WinSW）

仓库只提供 WinSW XML 和安装校验脚本，**不会下载或夹带第三方二进制**。通过本单位
软件供应链取得批准的 WinSW x64，核对来源并记录其 SHA-256。然后执行：

```powershell
$ApprovedWinSWSha256 = '<从独立批准清单粘贴64位SHA-256>'

& 'C:\ProgramData\MineGuard\Platform\service\Install-MineGuardPlatformService.ps1' `
  -WinSWExecutable 'D:\Approved\WinSW-x64.exe' `
  -ExpectedSha256 $ApprovedWinSWSha256 `
  -StartService
```

`-ExpectedSha256` 必须来自独立签名/批准清单，不能从待校验文件现场计算后原样传回。
安装脚本核对 SHA-256、XML 服务身份、回环监听和首启密码条件；现有同名服务不会
被隐式覆盖。WinSW 以 `LocalService` 运行 PowerShell 包装，包装再用固定
`runtime\Scripts\python.exe -m mineguard` 启动，日志滚动写入 `logs\`。

服务操作：

```powershell
Get-Service MineGuardPlatform
Start-Service MineGuardPlatform
Stop-Service MineGuardPlatform
Restart-Service MineGuardPlatform
```

只卸载服务注册、完整保留运行时、配置、状态、备份和日志：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Remove-MineGuardPlatformService.ps1'
```

该脚本核对同名服务确实指向当前安装目录，随后通过 Windows 服务管理器停止并删除固定
服务注册；它不会运行未知包装程序，也不会删除任何数据。需要无人值守执行时，变更单
已经明确批准后才使用 `-Confirm:$false`。

## 7. HTTPS 和防火墙

应用始终监听 `127.0.0.1:8080`。由 IIS/Caddy/Nginx 或单位网关在同机终止 HTTPS，
只向授权办公网开放 443；Windows 防火墙不得向局域网开放 8080。代理需保留 Host、
设置 `X-Forwarded-Proto: https`，并把代理访问日志纳入审计留存。

## 8. 在线备份、核验和恢复演练

不要在服务运行时直接复制 `.db`、`-wal`、`-shm` 文件。产品备份命令使用 SQLite
在线备份 API，并在完成后检查数据库完整性、文件 SHA-256 和 HMAC 清单：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Backup-MineGuardPlatform.ps1'
```

脚本每次都从受保护的 `config\settings.json` 读取当前 `stateDirectory`，因此切换到恢复
目录后不会误备份旧的默认目录；默认 `backup.key` 也跟随当前状态目录。

`state\backup.key` 不包含在备份里，必须另行加密、离线保管。备份目录也必须有容量
和新鲜度监控，并定期复制到批准的备份系统；应用工作状态仍不能直接运行在网络盘。

恢复脚本只允许恢复到一个不存在或空的新目录，绝不覆盖当前状态：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Restore-MineGuardPlatform.ps1' `
  -BackupId '20260802T120000Z-1234' `
  -TargetStateDirectory 'D:\MineGuardRestore\state-20260802' `
  -KeyFile 'E:\OfflineKeys\mineguard-backup.key'
```

先用另一个端口隔离验收恢复副本。确认后，在维护窗口停止服务，并通过配置脚本的
`-StateDirectory` 指向恢复目录，再重启；不要手工覆盖旧目录：

```powershell
Stop-Service MineGuardPlatform
$adminPassword = $null  # 已有 auth.db，无需再次提供首启密码
& 'C:\ProgramData\MineGuard\Platform\service\Set-MineGuardPlatformConfiguration.ps1' `
  -ClientsFile 'C:\ProgramData\MineGuard\Platform\config\clients.json' `
  -StateDirectory 'D:\MineGuardRestore\state-20260802'
Start-Service MineGuardPlatform
```

## 9. 升级、杀毒和已知边界

- 升级前做一次已核验备份；停止服务后，从新发布目录重新运行安装脚本，再启动验收；
- 依赖约束、Python、tzdata、NumPy 或 SciPy 变化时必须做完整算法和恢复回归；
- Defender/杀毒可能短暂锁定 SQLite。只对确有冲突的 `state`/`backups` 目录设置最小
  例外，不要排除整个磁盘或源码目录；
- 单个状态目录只能由一个 Platform 进程使用；当前 SQLite 单节点版不是多实例集群；
- WinSW 停止时向控制台进程发送 Ctrl+C 并等待，异常断电仍要在下次启动后检查
  `/readyz`，必要时从已核验备份恢复；
- Windows 服务托管不代替 HTTPS、证书、反向代理、时间同步、磁盘监控和异地备份。

上线验收至少包括：服务以 LocalService 运行、8080 仅回环监听、HTTPS 登录、每矿
Agent 报送与回执、领导只读范围、服务重启、断网恢复、在线备份、空目录恢复、备份
密钥丢失演练、日志中文无乱码，以及注册表/首启密码对普通用户不可读。
