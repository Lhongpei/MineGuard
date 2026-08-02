# MineGuard Windows 二进制发行与安装

这套发行链生成两个完全独立的离线安装包，而不是把政府平台和企业智能体塞进同一个进程：

- `MineGuard-Platform-<版本>-windows-x64...exe`：政府监管 Platform；
- `MineGuard-EnterpriseAgent-<版本>-windows-x64...exe`：单矿企业侧 Agent。

两个安装包各自携带 Nuitka standalone 运行时、浏览器前端、产品自己的 Windows 运维
PowerShell、版本信息、逐文件清单和 SHA-256。目标机不需要 Python、Node.js、编译器、
Java、Excel、GPU 或源码，离线安装也不需要访问互联网。业务联网、HTTPS 证书、DNS、
准确系统时间和模型/新闻接口仍按实际部署需要配置。

## 1. 支持边界

目标机基线为原生 x64 的 Windows 10 1809+、Windows 11 x64、Windows Server 2019/2022
x64，使用 Windows PowerShell 5.1 完成管理操作。安装器明确阻止 ARM64；Windows on ARM
x64 仿真尚未验证，不能作为当前验收环境。程序和 SQLite 状态必须位于本机固定 NTFS
磁盘，不能放在 UNC、映射网络盘、OneDrive 或同步目录。

每个状态位置必须是用途单一的固定目录，例如 Platform 的专用 `state` 叶目录或 Agent 的
专用 `instances` 根；不得把状态参数指向源码/程序/runtime/service 目录、整个安装根、整个
`C:\ProgramData`、磁盘根或其他宽泛目录。路径本身及其受控父链不得是 symlink、junction
或其他 reparse point。备份和恢复目标也使用另外的专用空目录，不能靠目录覆盖完成回滚。

浏览器使用单位仍在安全支持期内的 Edge/Chrome。容量取决于矿数、日报频率、留痕和备份
策略；小规模试运行建议至少 4 核、8 GiB 内存并为程序和状态预留 10 GiB，正式 sizing
应使用拟交付数据做压测，不能把建议值当成无条件保证。

构建机使用原生 Windows x64、CPython 3.12 x64、MSVC 构建工具、Windows PowerShell
5.1，以及预先安装并经单位批准的 Inno Setup 6.7.1 或更高 6.x。Nuitka 固定为
`4.1.3`，其构建依赖也在两个子项目中精确锁定。建议构建机至少 8 核、16 GiB 内存和
20 GiB 临时磁盘空间。

## 2. 一次构建两份未签名验收包

在仓库根目录的 Windows PowerShell 5.1 中执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass

.\scripts\Build-WindowsBinaryRelease.ps1 `
  -OutputDirectory "$pwd\release\windows" `
  -InnoCompiler 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' `
  -AllowNuitkaToolDownloads `
  -TestInstallerFailurePropagation `
  -TestInstallerLifecycle
```

`-AllowNuitkaToolDownloads` 只表示允许 Nuitka 获取它明确需要的构建辅助组件；根脚本绝不
临时下载 Inno Setup，找不到 `ISCC.exe` 会直接失败。成功输出只有四个文件：两份安装器、
`release-manifest.json` 和 `SHA256SUMS.txt`。所有构建和真实安装/健康/卸载验收通过前，
文件只存在临时 artifact stage，不会在交付目录留下半成品。`OutputDirectory` 在构建开始
时必须不存在；最终四个文件先复制到输出目录旁边的随机 staging 目录并完成全量复核，
最后才在同一 NTFS 卷上原子改名为目标目录。已有空目录也不会被接管或覆盖。

未签名文件名一定包含大写 `UNSIGNED-TEST-ONLY`，清单分类为
`unsigned-test-artifacts`。这种文件只供隔离功能验收，不是正式可信介质。

如果仓库托管在 GitHub，提交并推送这批经过复核的文件后，可在 **Actions → Windows
binary installer release → Run workflow** 手工触发。`sign_artifacts=false` 会在托管的
Windows Server 2022 runner 上执行同一构建、故障注入、真实静默安装、健康检查和卸载，
完成后从该次运行的 Artifacts 下载
`mineguard-windows-UNSIGNED-TEST-ONLY-<commit>`。这一步产出的才是可拿到 Windows 机器
双击的两份 EXE；Linux 工作区中的脚本本身不是 Windows 安装包。

## 3. 离线构建

目标机安装本来就是离线的；如果构建机也必须离线，应先在同架构、同 CPython 版本的受控
联网机建立完整 wheelhouse，并把 Nuitka/MSVC 所需缓存按单位流程预热后转运。例如先用
两个子项目的 constraints、pyproject 和构建 requirements 生成并复核 wheel：

```powershell
py -3.12 -m pip download --dest D:\wheelhouse `
  -r platform\packaging\windows\requirements-build.txt `
  -r agent\packaging\windows\build-requirements.txt

py -3.12 -m pip wheel --wheel-dir D:\wheelhouse `
  --constraint platform\constraints.txt .\platform
py -3.12 -m pip wheel --wheel-dir D:\wheelhouse `
  --constraint agent\constraints.txt .\agent
```

把 wheelhouse 当供应链介质管理，记录散列并用无网络构建机验证其完整性。离线构建时不要
传 `-AllowNuitkaToolDownloads`。清单必须放在 wheelhouse 外，避免自引用散列：

```powershell
.\scripts\New-WindowsWheelhouseManifest.ps1 `
  -Wheelhouse D:\approved-wheelhouse `
  -OutputPath D:\approved-evidence\windows-wheelhouse-manifest.json

$ManifestSha256 = (Get-FileHash `
  D:\approved-evidence\windows-wheelhouse-manifest.json `
  -Algorithm SHA256).Hash
```

清单生成器同样只接受本机固定 NTFS 的盘符绝对路径，拒绝 UNC、映射网络盘和任一祖先
reparse point；它先把完整 JSON 刷盘到同目录随机临时文件，再用同卷原子改名发布，且绝不
覆盖已有证据文件。

根构建会递归拒绝 reparse point、非 wheel 文件、清单外额外文件和缺失文件，并逐项核对
大小/SHA-256。清单散列必须通过独立受控渠道审批和保存，不能只把 wheel、清单和散列放在
同一可写目录后称为可信；根构建会在解析 JSON 之前先核对这个外部预期散列。未签名调试可
省略清单/外部锚点但会明确警告；正式候选两者都强制要求。下面同一会话变量只用于说明参数
传递，生产 CI 应从受保护 environment variable 读取已审批值：

```powershell
.\scripts\Build-WindowsBinaryRelease.ps1 `
  -OutputDirectory D:\release\windows `
  -Wheelhouse D:\approved-wheelhouse `
  -WheelhouseManifest D:\approved-evidence\windows-wheelhouse-manifest.json `
  -ExpectedWheelhouseManifestSha256 $ManifestSha256 `
  -InnoCompiler 'D:\approved-tools\Inno Setup 6\ISCC.exe' `
  -TestInstallerFailurePropagation `
  -TestInstallerLifecycle
```

## 4. 可选 Authenticode 正式候选签名

签名证书必须预装在执行账号的 `CurrentUser\My` 或本机 `LocalMachine\My` 证书库，两个
库合计必须只命中一张指定 thumbprint。根脚本会识别证书库；机器证书自动让 SignTool
使用 `/sm`。接口不接收 PFX 路径或证书密码，避免把秘密放进参数、日志和 CI 配置。

```powershell
.\scripts\Build-WindowsBinaryRelease.ps1 `
  -OutputDirectory D:\release\windows-signed `
  -Wheelhouse D:\approved-wheelhouse `
  -WheelhouseManifest D:\approved-evidence\windows-wheelhouse-manifest.json `
  -ExpectedWheelhouseManifestSha256 '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF' `
  -PythonExecutable 'D:\approved-tools\Python312\python.exe' `
  -ExpectedPythonPatchVersion '3.12.10' `
  -ExpectedPythonExecutableSha256 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' `
  -InnoCompiler 'D:\approved-tools\Inno Setup 6\ISCC.exe' `
  -ExpectedInnoCompilerSha256 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe' `
  -ExpectedSignToolSha256 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC' `
  -SigningCertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -TimestampUrl 'https://timestamp.example-approved.invalid' `
  -RequireSigned `
  -TestInstallerFailurePropagation `
  -TestInstallerLifecycle
```

上面的时间戳地址及所有示例 SHA-256 均为格式占位符，不能原样使用。产品 EXE 在子项目
生成 manifest 之前签名；Inno 再签 Setup 和 uninstaller，随后统一复核签名状态、签名证书
和时间戳。只有此路径才去掉文件名中的 `UNSIGNED-TEST-ONLY`，清单分类为
`signed-production-candidate`。签名表示来源和完整性，不等于自动批准上线。
正式签名模式还会强制拒绝 `-AllowNuitkaToolDownloads`；Nuitka 所需辅助缓存必须提前从
审批介质预置，不能在签名构建时临时联网取得。正式自托管 runner 也不运行
`actions/setup-python`：必须由受保护变量指定预装的 `python.exe`、精确 3.12 patch 及其
批准 SHA-256。根构建在使用前实际核对 Python、ISCC 和 SignTool，并把同一个已解析的
`python.exe` 显式传给 Platform 与 Agent 子构建；任何实际散列、Python patch 或子清单
记录不一致都会失败。Output、wheelhouse 和 wheelhouse manifest 之间也不得相等或互相
包含，避免构建输出污染受审批输入。

## 5. 交付核验与安装

先从独立可信渠道取得预期散列/签名者信息，再检查介质：

```powershell
Get-AuthenticodeSignature .\MineGuard-Platform-*-windows-x64.exe |
  Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
Get-FileHash .\MineGuard-Platform-*-windows-x64.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

不要把与安装器放在同一可写目录里的散列文件单独当成真实性证明。图形安装可双击；静默
安装示例。Setup 同时内置简体中文和英文安装界面，并按 Windows 界面语言自动选择：

```powershell
& .\MineGuard-Platform-0.5.0-windows-x64.exe `
  /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-

& .\MineGuard-EnterpriseAgent-0.2.1-windows-x64.exe `
  /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
```

Setup 先把子项目 release staging 展开到临时目录，再调用包内产品安装脚本。产品脚本逐项
复核 release manifest 和 SHA-256，做自检、原子切换 runtime、设置 ACL，并把版本清单
落到 `release-metadata`。子脚本任何非零退出码都会中止 Setup，其 stdout/stderr 写入
Inno Setup 日志；不会再出现“产品安装失败但 Setup 显示成功”。

升级前先停止服务。当前二进制版已注册且为 `Stopped` 的 Platform/Agent 服务会被保留；
任何相关服务仍在运行时，安装器和产品脚本都会拒绝升级。同版本允许修复安装，也允许升级
到更高版本；默认拒绝覆盖安装更低版本，不能把“安装旧 EXE”当成回滚方案。涉及数据库或
配置 schema 跨版本变化时，仍须在现场副本完成备份、恢复和业务验收后再升级，版本号检查
不能替代数据兼容性验证。

从旧版 Python/source/venv Agent 迁移时是一个例外：即使旧服务已停止，也必须先对每个矿
执行 `Uninstall-EnterpriseAgentService.ps1` 移除旧服务注册，再安装企业二进制包，最后用
`Install-EnterpriseAgentService.ps1` 按原实例逐一重新注册服务。该流程只替换程序与服务
指向，不删除 ProgramData 中的实例配置、数据库、证据、备份和日志；迁移前仍须完成备份和
恢复演练。

## 6. 安装后初始化

安装器不会编造煤矿身份、客户端密钥、管理员密码或模型 API，也不会把默认
`123123123` 注入正式配置。它只安装经过审计的不可变程序和运维入口。

政府 Platform 默认在 `C:\ProgramData\MineGuard\Platform`。从开始菜单打开 Platform
operations console，准备正式 `clients.json`，再通过安全交互输入首次管理员密码：

```powershell
Set-Location 'C:\ProgramData\MineGuard\Platform\service'
.\Set-MineGuardPlatformConfiguration.ps1 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -ClientsFile 'D:\approved-media\clients.json'
```

企业 Agent 程序默认在 `C:\Program Files\MineGuard\EnterpriseAgent`，实例状态在
`C:\ProgramData\MineGuard\EnterpriseAgent\instances`。一矿一智能体，从开始菜单选择
“Create an enterprise mine instance”，或执行：

```powershell
Set-Location 'C:\Program Files\MineGuard\EnterpriseAgent\deploy\windows'
.\New-EnterpriseAgentInstance.ps1 `
  -InstanceName qinyuan-001 -MineId MINE-QY-001 `
  -MineName '本矿名称' -OperatorId OP-QY-001 `
  -OperatorName '本企业名称' -SystemId agent-qy-001 -Port 8090
```

然后在实例的 ACL 受控配置文件中设置账号摘要、政府接口、两把不同的交换密钥以及可选的
模型 API。演示登录只限回环隔离测试，不能用于确认、报送或生产服务。

安装器不下载也不捆绑 WinSW。需要 Windows 服务时，继续使用两个产品随包提供的服务
安装脚本，并从单位批准的软件源单独取得 WinSW、核验预先批准的 SHA-256。

## 7. 卸载与数据保留

卸载前先用产品脚本移除服务注册：Platform 使用
`Remove-MineGuardPlatformService.ps1`；每个企业实例分别使用
`Uninstall-EnterpriseAgentService.ps1`。只要 `MineGuardPlatform` 或任一
`MineGuardEnterpriseAgent-*` 服务仍注册，uninstaller 就会安全拒绝，避免删掉仍被服务
引用的 runtime。

卸载器只定向移除 `runtime`、运维脚本和 `release-metadata`。政府侧
`config/state/backups/logs` 以及企业侧 ProgramData 实例不会被删除；卸载前仍应做完整备份
和恢复演练，卸载后按单位数据保留制度人工处置。CI 的发布门禁会静默安装两个产品、真实
启动健康端点、卸载并检查这些目录中的 sentinel 仍存在。

## 8. 内容披露、可追溯性与第三方合规

交付介质的准确口径是：**no MineGuard backend Python source**、无 Python bytecode、测试、
Git 历史或真实秘密。浏览器 frontend 的 HTML、JavaScript、CSS 和 operations PowerShell
必须保留为可读文本，便于浏览器执行和管理员审计。核心后端由 Nuitka 编译，但 EXE 不是
绝对防分析机制，仍可能被 inspect 或 reverse engineer。

`release-manifest.json` 记录产品版本、提交 revision、dirty 状态、Python/Nuitka/Inno
版本、依赖、wheelhouse manifest 实际/外部预期散列及锚点核验状态、证书库位置、签名/
时间戳状态、安装器大小与散列；子 manifest 记录安装器内的逐文件散列。这是 constrained,
traceable and repeatable build，不承诺不同机器产物 byte-for-byte identical。

交付单位在再分发前必须自行审查并留档：Nuitka builder/runtime exception、Inno Setup
commercial-use terms、全部打包依赖许可证，以及本单位采购、密码和供应链制度。版本记录是
审计证据，不替代法律/采购审查，也不能笼统声称所有工具都可无条件免费商用。

GitHub Actions 的 [windows-release.yml](../.github/workflows/windows-release.yml) 有两条互不
混淆的路径：`windows-2022` 只产出明确标记的 unsigned test artifacts；正式签名仅能在带
`windows/x64/signing` 标签、预装证书/SignTool/Inno/离线 wheelhouse 的受控自托管 runner
上显式触发，并且必须先等同一 workflow 的 unsigned 构建、完整 Windows PowerShell 5.1
解析和生命周期测试成功。该 runner 必须是隔离构建机，不能同时承载真实 MineGuard 服务；生命周期门禁
会创建并精确清理临时服务，且遇到同名既有服务会拒绝运行。流水线只上传工件，不自动创建
公开 Release。受保护环境还必须提供
`WINDOWS_RELEASE_WHEELHOUSE_MANIFEST_SHA256`，其值来自清单之外的审批记录。
此外必须配置 `WINDOWS_RELEASE_PYTHON_EXECUTABLE`、
`WINDOWS_RELEASE_PYTHON_PATCH_VERSION`、`WINDOWS_RELEASE_PYTHON_EXECUTABLE_SHA256`、
`WINDOWS_INNO_COMPILER_SHA256` 和 `WINDOWS_SIGNTOOL_SHA256`；这些值应来自受保护审批记录，
不能在 job 中对现场文件即时计算后再反向当作预期值。发布清单只记录版本、实际/预期散列
和外部锚核验结果，不记录构建机上的受控工具绝对路径。
