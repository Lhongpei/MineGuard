# MineGuard Platform Windows 原生部署与运维

本文适用于政府侧 `platform/`。企业侧 Agent 有自己的 Windows 安装和状态目录，两个
软件不能共用虚拟环境、配置、密钥或 SQLite 文件。

当前正式业务入口是十量 V3；11 个原子字段、CSV、开票非负口径和五量 V2 只读边界见
[十量 V3 部署与运行](../../docs/十量V3部署与运行.md)。本文中的
`MINEGUARD_V2_CLIENTS_FILE/JSON` 是程序为兼容现有安装保留的客户端注册变量名，
同一注册表会验证 V3 客户和双 HMAC，不表示提交路径仍是 V2。

## 普通使用者先看：控制中心

安装完成后，不需要打开 `ProgramData`，也不需要输入长命令。从 Windows 桌面或开始菜单点击
**MineGuard Platform 控制中心**；出现管理员权限确认时选择“是”。

### 本机展示

1. 选择“本机展示（推荐先看）”；
2. 勾选红色确认项，明确这是本机 HTTP 演示；
3. 点击“一键准备并启动展示”；
4. 等待健康检查通过，控制中心会优先用 Edge 或 Chrome 打开领导端。

登录账号是 `admin`，密码是 `123123123`。这个账号只用于本机展示，不能用于生产、企业
报送或监管认定。Internet Explorer 不支持现代前端；如果机器没有 Edge/Chrome，控制中心
会显示地址和提示，不会退回 IE 打开空白页。

### 正式内网首次配置

切换到“正式内网配置”，选择单位批准的 `clients.json`、用途单一的本机 NTFS 状态目录和
端口并填写管理员账号。点击配置按钮后，独立短生命周期 helper 才弹出小密码窗并要求输入
两遍；主控制中心既不读取密码，也不接收 `SecureString`。helper 要求正式密码至少 12 位，
并在大写字母、小写字母、数字、符号四类中至少包含三类，并禁止 `123123123`。单位 HTTPS 反向代理已经就绪时，再填写供领导访问的完整 HTTPS
根地址；地址必须以 `https://` 开头，不能含账号口令、子路径、查询参数或 `#` 片段。点击“打开
安全密码窗并配置”后等待 helper 退出和健康检查通过。控制中心打开前还会核验 HTTPS 根地址的 `/readyz`；
验证成功的地址会保存在受保护配置中，但控制中心不会配置 DNS、证书或反向代理。

密码仅在 helper 进程中以安全对象交给受保护配置事务，不进入主控制中心、命令行或日志；
配置完成或取消后 helper 立即退出。非敏感的运行记录写入 ACL 受控的
`logs\control-center-*.log`；现场报错时可以拍照窗口底部“运行状态”栏。已有正式配置或
已有状态数据时，控制中心会禁止一键覆盖，只允许启动现有配置和打开页面。
所有配置写入都持有机器级 `Global\MineGuardPlatform.Configuration` Mutex，直到提交或
回滚完全结束。启动脚本会等待同一把机器级 Mutex，并从检查事务残留、读取配置开始，
一直持有到 Platform 长运行子进程完全退出；运行期间配置脚本获取不到该锁就会闭锁拒绝修改，避免前台
运行时切换 config/state/ACL。正常退出、控制中心停止或异常终止都会通过 `finally`/操作系统句柄回收
释放 Mutex；30 秒内未取得锁则闭锁拒绝启动。事务开始时会写入固定阻断标记
`config\.mineguard-configuration-blocked.json`；只有完整提交或完整回滚并清除事务目录后
才删除。异常断电或回滚不完整时，后续配置和启动都会拒绝继续。管理员须停服，按标记中的
唯一 `transactionDirectory` 核验并清理该精确目录，再删除固定阻断标记并重新配置。
即使磁盘或 ACL 故障导致标记未能更新，启动和配置也会有界扫描 `config` 的直系子目录；
任何精确匹配 `.configuration-transaction.<32位十六进制>` 的残留目录都会独立触发阻断。
首次写入前会检查端口占用；如果演示数据准备中断，可在同一页点击【补齐数据并启动展示】继续，
不要手工删除受保护的状态目录。

控制中心运行的是前台验收进程：窗口保持打开才会继续运行，关闭窗口会先询问并停止本次
启动。正式长期常驻可切换到“正式服务安装”页，选择本单位批准的 WinSW，并手工填写介质外
审批记录中的 WinSW SHA-256、可选 `.config` SHA-256 和 Platform 签名证书指纹；也可按
第 6 节使用同样参数执行命令。控制中心不会下载 WinSW、不会从 build metadata 自动取信，
也不会代替服务变更审批。

## 1. 已支持的 Windows 基线

- Windows 10/11 x64（演示、运维终端）或 Windows Server 2019/2022 x64；
- Windows 10 1809+ 仅表示技术兼容下限；2026 年正式上线的普通 Windows 10 22H2
  必须具有组织 ESU，或使用仍在产品生命周期内的具体 LTSC 版本；优先
  Windows Server 2019/2022 或 Windows 11；
- 客户机不需要安装 Python；正式包自带经验证的 Nuitka standalone 运行时；
- 只有可信构建机需要 CPython 3.12 x64 和 Visual Studio 2022 C++ Build Tools；
- Windows PowerShell 5.1；安装、配置、启动、健康检查、备份、恢复和服务移除脚本都会
  显式检查该门槛，不依赖 PowerShell 7，也不需要执行虚拟环境激活脚本；
- 安装根、状态、备份、备份密钥暂存和恢复目标都必须写成 `X:\...` 盘符绝对路径，位于
  已就绪的本机固定 NTFS 磁盘；不得使用 UNC/SMB、盘符相对路径、映射/移动盘、OneDrive
  或其他同步目录，路径自身和每一级现有祖先均不得是 symlink、junction、挂载点或其他
  reparse point；
- 新版 Edge/Chrome；领导大屏建议 1920×1080 或更高分辨率；
- 准确的 Windows 时间同步；报文 HMAC 的可接受时间窗为 5 分钟；
- 不需要 GPU、Java、Node.js、Office/WPS 或单独安装 HiGHS。

Windows 没有系统 IANA 时区库。本发布把 `tzdata` 固定为运行依赖，并把版本写进算法
运行清单，保证 `Asia/Shanghai` 统计窗口和导出时间可以追溯。

推荐目录由安装脚本创建：

```text
C:\ProgramData\MineGuard\Platform\
  runtime\       MineGuardPlatform.exe 与受控 DLL/PYD/资源（专属服务 SID 只读）
  config\        settings.json、clients.json、首启密码文件（只读 ACL）
  state\         mineguard.db、auth.db、backup.key（专属服务 SID 可写）
                 .mineguard-platform-state.json（专用状态根所有权标记）
  backups\       在线一致性备份（专属服务 SID 可写）
  logs\          WinSW 滚动日志（专属服务 SID 可写）
  service\       PowerShell 包装和 WinSW XML（专属服务 SID 只读）
  release-metadata\ 版本、构建、文件摘要与签名状态（专属服务 SID 只读）
```

安装脚本用固定服务 SID 设置 ACL，避免本地化账号名以及多个 LocalService 服务共享权限。
服务身份是专属虚拟账号 `NT SERVICE\MineGuardPlatform`，其确定性 SID 为
`S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346`；安装时还会执行并
复核 `sc.exe sidtype MineGuardPlatform unrestricted`。它不是 `LocalSystem`，也不再与
其他 `LocalService` 服务共享文件访问身份。

状态目录必须是用途单一的状态根。位于安装根内时只允许使用 `Platform\state` 或其专用
子目录，不能指向 `runtime/config/service` 等程序树；位于外部磁盘时必须为空或带上述
MineGuard 所有权标记。状态目录也不能等于安装根或成为安装根的宽泛祖先。
从早期无所有权标记版本升级时，先停止服务，再用当前注册表和当前 `-StateDirectory`
重新运行 `Set-MineGuardPlatformConfiguration.ps1`；它只会接纳可识别的既有 MineGuard
状态根并补写标记。启动、备份和恢复脚本在标记补齐前会安全拒绝，不能手工伪造标记绕过。

## 2. 正式二进制安装

对外交付两类互斥的正式 Setup：经 Authenticode 签名的版本，或明确带
`INTERNAL-UNSIGNED` 标识的无证书受控内网版本；同时交付 SHA-256 和使用手册，不交付
Python 源码、测试、Git 历史或开发虚拟环境。安装器会把临时展开的发布目录交给同一套
受保护安装逻辑；客户机不访问 PyPI，也不需要 Python。正式安装的信任入口是 Setup 介质
本身：signed Setup 必须核对介质外 SHA-256、有效且带时间戳的 Authenticode 状态及签名者
指纹；`INTERNAL-UNSIGNED` Setup 必须在安装器页面输入介质外独立批准的本文件 SHA-256，
且安装正式服务时再次输入介质外批准的 Platform 子发行清单 SHA-256。默认
`UNSIGNED-TEST-ONLY` 不能作为正式介质。

仅在受控构建、故障注入或兼容性测试中，需要直接核验尚未封装为 Setup.exe 的二进制
staging 时，才可在“以管理员身份
运行”的 **Windows PowerShell 5.1** 中进入
`MineGuardPlatform-<version>-windows-x64`：

```powershell
# 先按独立发布清单核验整个交付包；确认可信后只为当前进程放行脚本。
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

& .\deploy\windows\Install-MineGuardPlatform.ps1 `
  -SourceDirectory $PWD.Path `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform'
```

脚本逐项核验 `release-manifest.json` 和 `SHA256SUMS.txt`，拒绝未列入文件和 reparse
point，再校验前端资源、NumPy/SciPy/HiGHS、上海时区及 Authenticode 状态。运行时、
运维脚本和发布元数据作为同一事务切换；失败会恢复旧版本。配置、状态、备份和日志不
参与覆盖。这些自检只是纵深防御：它们不能认证正在执行的管理员脚本自身，因此直接
staging/PS1 不得作为正式交付、正式安装或信任根。

## 3. 可信 Windows 构建与离线介质

二进制必须在可信 Windows Server 2022 x64 构建机生成。构建入口和精确 staging 契约
见 `platform/packaging/windows/README.md`。联网内部测试构建示例：

```powershell
& .\platform\packaging\windows\Build-MineGuardPlatform.ps1 `
  -OutputDirectory 'C:\MineGuardBuild\Platform' `
  -AllowNuitkaToolDownloads
```

正式构建必须传入签名工具、代码签名证书 thumbprint、HTTPS 时间戳 URL 和
`-RequireSignedBinary`。离线构建通过 `-Wheelhouse` 使用审批后的 Windows wheels，
并预置 Nuitka 工具缓存；脚本强制 `--no-index`，不会回退互联网。源码和 wheelhouse
只留在构建区，绝不进入 staging 或最终 Setup.exe。

## 4. 配置多矿注册表和首次管理员（高级命令）

普通首次配置优先使用本文开头的控制中心。需要自动化或排障时，复制
[clients.json.example](../deploy/windows/clients.json.example) 到受控临时目录，
为每座矿配置一个独立 Agent 身份。`sender_id`、`party_id`、`mine_id`、`mine_name`
和五个 `comparison_context` 维度必须使用已治理的正式值。消息 HMAC 与 HTTP 运输 HMAC
必须是两把不同的随机秘密，各至少 32 字节。正式门禁会检查当前和轮换密钥，
拒绝演示/占位身份与 key ID、低多样性或短片段重复密钥、密钥复用和未分类/待替换的
同类矿分组值。不要使用示例占位符，不要通过聊天、命令行参数或工单正文
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
首启文件仅用于建立 `auth.db` 中的 scrypt 密码摘要。正式密码至少 12 个字符，并包含
大小写字母、数字、符号中的至少三类；`123123123`、常见弱口令、示例和占位文本均会被
配置、服务安装和每次启动重复拒绝。

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

控制中心已经把下面的启动和健康等待过程合并为按钮；本节命令供高级管理员排障或自动化
验收使用。

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

该命令会先只读确认当前 `auth.db` 至少有一个已完成改密的正式管理员；演示/默认口令或
待换密管理员不满足条件，避免删除首启秘密后锁死。

正式状态目录与演示状态目录永久分离，演示数据不能原地转正式。即使人工删除演示标记，配置、前台启动和服务安装
仍会核验数据库中的演示交换类型、演示 Agent 绑定和演示煤矿命名空间，拒绝把合成/样表
数据原地“转正式”。应新建空的专用状态目录，再由企业 Agent 通过签名 HTTP 报送真实数据。

## 6. 安装为 Windows 服务（WinSW）

仓库只提供 WinSW XML 和安装校验脚本，**不会下载或夹带第三方二进制**。通过本单位
软件供应链取得批准的 WinSW x64，核对来源并记录其 SHA-256。然后执行：

```powershell
$ApprovedWinSWSha256 = '<从独立批准清单粘贴64位SHA-256>'
$ApprovedPlatformSigner = '<从独立审批记录粘贴40位代码签名证书指纹>'
# 只有批准介质存在 WinSW-x64.exe.config 时才设置这一项：
$ApprovedWinSWConfigSha256 = '<该 .config 的独立批准 SHA-256>'

& 'C:\ProgramData\MineGuard\Platform\service\Install-MineGuardPlatformService.ps1' `
  -WinSWExecutable 'D:\Approved\WinSW-x64.exe' `
  -ExpectedSha256 $ApprovedWinSWSha256 `
  -ExpectedConfigSha256 $ApprovedWinSWConfigSha256 `
  -Production `
  -ExpectedSignerThumbprint $ApprovedPlatformSigner `
  -StartService
```

`-ExpectedSha256` 必须来自独立签名/批准清单，不能从待校验文件现场计算后原样传回。
如果 WinSW 没有 companion `.config`，应同时删掉上例变量和参数；如果存在，则
`ExpectedConfigSha256` 同样必须来自外部批准清单。正式配置必须显式传 `-Production`，
且 `ExpectedSignerThumbprint` 必须来自待安装介质之外的审批记录。安装脚本会要求发布
分类为 `signed-production-candidate`、`codeSigned=true`，并直接验证主程序 Authenticode
状态、时间戳和实际签名者指纹；介质内自报的证书指纹不能单独成为信任锚。脚本还会核对产品 release
manifest、配置/状态身份、XML 服务身份、回环监听和首启密码条件；现有同名服务不会
被隐式覆盖。文件以随机临时名完整写入和复核后才发布，注册、启动或健康检查失败会
撤销本次服务并删除本次文件；归属无法证明时停止清理并报告回滚不完整。注册成功后
还会从 `Win32_Service.PathName` 核对无参数精确 wrapper、专属虚拟账号和 unrestricted
服务 SID 类型。
WinSW 包装使用固定 `runtime\MineGuardPlatform.exe`，日志滚动写入 `logs\`。

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

该脚本在每次停止和最终 `sc.exe delete` 前重新核对同名服务确实以无参数 PathName
指向当前 wrapper，并等待服务记录真正消失；它不会运行未知包装程序，也不会删除业务
数据。需要重新安装服务文件时可显式增加 `-RemoveWrapperFiles`，该开关也只删除经过
完整性记录核验的 wrapper、可选 `.config` 和记录本身，仍保留
`runtime/config/state/backups/logs`。需要无人值守执行时，变更单已经明确批准后才使用
`-Confirm:$false`。

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
执行脚本时，自定义 `-BackupDirectory` 和 `-KeyFile` 必须先放到受 ACL 保护的本机固定
NTFS 专用路径，脚本会逐级拒绝 reparse point。权威密钥仍应离线保管；需要恢复时只把
受控副本暂存到该本机路径，操作完成后按单位密钥制度清理暂存副本。

恢复脚本只允许恢复到一个不存在或空的新目录，绝不覆盖当前状态：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Restore-MineGuardPlatform.ps1' `
  -BackupId '20260802T120000Z-1234' `
  -TargetStateDirectory 'D:\MineGuardRestore\state-20260802' `
  -KeyFile 'D:\MineGuardSecureKeys\mineguard-backup.key'
```

恢复目标必须不存在或为空、不能与当前状态或备份目录重叠，并满足同一固定 NTFS/逐级
无 reparse/状态边界要求。恢复成功后脚本会在新目录创建并核验同一份
`.mineguard-platform-state.json` 所有权标记，再设置专属服务 SID ACL；返回结果的
`nextStep` 也只会引导使用配置事务。

先用另一个端口隔离验收恢复副本。确认后，在维护窗口停止服务，并通过配置脚本的
`-StateDirectory` 原子切换到恢复目录，再重启；禁止手工编辑 `settings.json` 或覆盖旧
目录：

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

上线验收至少包括：服务以 `NT SERVICE\MineGuardPlatform` 运行且 ServiceSidType=1、8080 仅回环监听、HTTPS 登录、每矿
Agent 报送与回执、领导只读范围、服务重启、断网恢复、在线备份、空目录恢复、备份
密钥丢失演练、日志中文无乱码，以及注册表/首启密码对普通用户不可读。
