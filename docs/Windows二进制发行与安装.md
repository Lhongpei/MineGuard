# MineGuard Windows 二进制发行与安装

> 企业现场配置以当前 [Agent Windows 部署说明](../agent/deploy/windows/README.md)
> 为准：单个 `.mgprov`、单业务管理员、固定 `api_admin`，不再使用旧 CA/激活码/
> 公钥/指纹或 `.mgllm` 现场向导。本文后续保留的相关内容仅作历史发行设计参考。

本发行链当前交付十量 V3。现场字段与配置以
[十量 V3 部署与运行](十量V3部署与运行.md)为准；五量 V2 只用于历史只读审计。

这套发行链生成两个完全独立的离线安装包，而不是把政府平台和企业智能体塞进同一个进程：

- `MineGuard-Platform-<版本>-windows-x64...exe`：政府监管 Platform；
- `MineGuard-EnterpriseAgent-<版本>-windows-x64...exe`：单矿企业侧 Agent。

两个安装包各自携带 Nuitka standalone 运行时、浏览器前端、产品自己的 Windows 运维
PowerShell、版本信息、逐文件清单和 SHA-256。目标机不需要 Python、Node.js、编译器、
Java、Excel、GPU 或源码，离线安装也不需要访问互联网。业务联网、HTTPS 证书、DNS、
准确系统时间和模型/新闻接口仍按实际部署需要配置。

## 安装后怎么打开（普通使用者先看）

政府侧 Platform 安装完成后，不需要寻找 `ProgramData`，也不需要抄写 PowerShell 命令：

1. 从 Windows 桌面或开始菜单点击 **MineGuard Platform 控制中心**；出现管理员权限确认时
   选择“是”。
2. 临时看效果时，选择“本机展示（推荐先看）”，勾选红色确认项，再点击
   “一键准备并启动展示”。
3. 控制中心显示服务正常后，会优先用 Edge 或 Chrome 打开领导端。登录账号为 `admin`，
   密码为 `123123123`。

这个默认账号只用于本机 HTTP 展示，不能用于正式运行、企业报送或监管认定。Internet
Explorer 不支持；没有 Edge/Chrome 时应先离线安装现代浏览器，不能用 IE 打开，否则可能
只看到空白页。控制中心运行的是前台验收进程，窗口保持打开才会继续运行；关闭窗口会提示
并停止本次启动。正式长期运行仍须由管理员按本手册后文使用单位批准的 WinSW 安装服务。

正式首次配置也在同一控制中心内完成：切换到“正式内网配置”，选择经批准的
`clients.json`、专用状态数据目录和端口，只在主界面填写管理员账号；点击配置后，
独立的短生命周期 helper 进程才会弹出密码窗并要求输入、确认密码。主控制中心不读取密码，
也不接收 `SecureString`。单位 HTTPS 反向代理已经就绪时，再填写领导端 HTTPS 地址。
地址必须以 `https://` 开头，且不能包含账号口令、
子路径、查询参数或 `#` 片段，例如 `https://mineguard.example.gov.cn/`。控制中心
会同时核验本机和该 HTTPS 地址的 `/healthz`；验证成功后将地址保存在受保护的本机
配置中，下次无需重新输入。它不负责配置 DNS、证书或反向代理。正式密码不能使用
`123123123`，密码不会写入命令行或控制中心日志；
非敏感运行记录写入受保护的 `logs\control-center-*.log`。已有正式配置或已有状态数据时，
控制中心会防止一键覆盖，只允许安全启动和打开页面。

控制中心会在写入首次配置前检查端口是否被占用；如果演示数据准备中断，再次打开后可直接
点击【补齐数据并启动展示】，不需要手工删除 `ProgramData` 下的文件。

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

`INTERNAL-UNSIGNED` 的正式 GitHub 发行在临时的 `windows-2022` GitHub-hosted
runner 上构建，不再要求部署单位维护一台 `mineguard-release` 自托管构建机。
工作流先用独立的 `qualify-formal-inputs` 运行锁定 CPython、Inno、wheel 集合和
Nuitka 依赖缓存，经独立复核后才由受保护 Environment 放行正式构建。
Nuitka 固定为 `4.1.3`，所有被采信的工具或文件集都按精确版本和 SHA-256
失败关闭。带 Authenticode 的 `signed` 路径仍使用预装证书、SignTool、Python、
Inno 和离线介质的隔离自托管 Windows x64 runner。本地构建命令只用于开发、
故障注入或离线复现，不会自动获得 GitHub artifact attestation。

### 1.1 Windows Server 2012 R2 legacy 兼容测试

标准发布不支持 Windows Server 2012 R2。手工触发发布工作流时可显式选择
`legacy_server_2012r2_compatibility_test`，它只在 runner 的临时工作区生成名称含
`LEGACY-SERVER-2012R2-UNSIGNED-TEST-ONLY` 的未签名试验介质并执行兼容性验证，
不上传可下载的安装包或发行 artifact。该模式不能与生产签名同时开启，
也不表示已完成目标系统认证。

目标机至少必须满足：

- x64 Windows Server 2012 R2，已安装适用的安全更新；
- 已安装 Windows Management Framework 5.1，`$PSVersionTable.PSVersion` 显示 5.1；
- CPU/虚拟 CPU 暴露完整 x86-64-v2 指令集，并具备 Universal C Runtime 和 Microsoft Visual C++ x64 运行库；
- 程序和 SQLite 状态位于本机固定 NTFS；
- 领导端从受支持的办公终端现代浏览器经 HTTPS 访问，不依赖服务器本机旧浏览器。

必须在真实 2012 R2 目标机完成 standalone self-check/HiGHS、安装回滚、前台与服务
健康、SQLite 备份/校验/恢复、升级和卸载验收。在此之前只能用于隔离兼容测试。

Server 2012 R2 系统自带 PowerShell 4.0 时，从
[Microsoft Windows Management Framework 5.1 官方下载页](https://www.microsoft.com/en-us/download/details.aspx?id=54616)
只选择 `Win8.1AndW2K12R2-KB3191564-x64.msu`。安装前由 Windows 运维人员核对
.NET Framework、KB2919355、现有 WMF 依赖以及 Hyper-V HNV/RRAS 集群网关影响，安排
维护窗口和系统备份；安装后重启，再确认 `$PSVersionTable.PSVersion` 为 5.1。

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

如果仓库托管在 GitHub，可在 **Actions → Windows binary installer release →
Run workflow** 手工触发。工作流默认选择 `release_mode=internal-unsigned`，
只有正式 `internal-unsigned` 和 `signed` 路径会上传可下载的 Windows 安装包。
首次建立或任何依赖/托管镜像变化后，先显式选择
`release_mode=qualify-formal-inputs`；它只生成待复核清单并锁定缓存，不生成或
上传 EXE。完成第 4 节的独立复核和 Environment 配置后，才能运行默认的
`internal-unsigned`。
显式选择 `release_mode=unsigned-test` 时，托管的 Windows Server 2022 runner 仍会执行
构建、故障注入、真实静默安装、健康检查和卸载，但只保留运行日志和
内部构建缓存，不上传 EXE、`release-manifest.json` 或 `SHA256SUMS.txt`，因而不存在
可从 Actions 下载的 `UNSIGNED-TEST-ONLY` 介质。Linux 工作区中的脚本本身也不是
Windows 安装包。

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

## 4. 无代码签名证书的内网正式版（当前部署可选）

不购买、不安装 Authenticode 代码签名证书时，使用独立的
`INTERNAL-UNSIGNED` 正式发行路径。它不是 `UNSIGNED-TEST-ONLY` 的改名版：仍强制要求
干净且可追溯的 Git 提交、独立审批的 wheel 文件集清单和 Nuitka 依赖缓存清单、
固定的 Python/Inno 版本和摘要、生产模型签发信任库，以及两套安装器的真实安装、
健康检查、升级和卸载测试。区别只在于 Windows 无法显示已验证的发布者身份；
GitHub artifact attestation 证明产物来自指定仓库、workflow 和提交，现场执行信任仍由
介质外独立交付的每份 Setup SHA-256 建立。两者必须都通过，不可互相替代。

这里的 `ModelTrust` 是 Agent 用来验证每矿 `.mgllm` 模型授权包的 Ed25519 **公钥**
JSON，不是 Windows 证书，也不包含 LLM API Key；对应签发私钥仍只保留在交付方的离线
签发环境。首次生成生产信任库时，按[企业模型凭据签发与轮换](企业模型凭据签发与轮换.md)
的 issuer-init 和 trust-check 步骤执行。仓库自带的
`model-credential-trust.TEST-ONLY.json` 会被严格构建拒绝。

### 4.1 第一阶段：锁定正式输入

先冻结 `main` 的待发布 commit；从输入资格运行开始到正式产物上传前，不要合并
会改变代码、requirements、constraints 或 Windows 打包脚本的提交。在
**Actions → Windows binary installer release → Run workflow** 中设置：

- branch：`main`；
- `release_mode`：`qualify-formal-inputs`；
- `legacy_server_2012r2_compatibility_test`：`false`；
- `qualification_python_patch`：待批准的精确 CPython `3.12.x`，不允许 `3.12` 这类漂移值。

该 job 在 `windows-2022` 上完成以下事情：生成仅含锁定 wheel 的
`wheelhouse-manifest.json`；用固定 Nuitka 编译最小探针，预热它明确需要的
MSVC/依赖分析文件；生成 `nuitka-downloads-manifest.json`；最后用该清单摘要作为
Actions cache key 保存文件集。它只在日志中给出待审批的摘要和 Base64
清单，**不生成 EXE，不上传正式 artifact**。这一步成功只表示“候选输入可
复核”，不表示已批准发布。

由未执行该次资格运行的发布复核人核对 run URL、commit SHA、精确 Python patch、
Python/Inno SHA-256、两份清单的文件集和 SHA-256、requirements/constraints 差异，
并独立复核生产 `model-credential-trust.json`。模型信任库只含 Ed25519 公钥；
issuer 私钥、LLM API Key、HTTPS 私钥和任何 HMAC 都不得进入工作流、日志、
cache 或 Environment。公开仓库的 Actions 日志必须按公开信息处理。

复核通过后，把以下值写入受保护的
`windows-internal-unsigned-release` Environment：

| 类型 | 名称 | 来源 |
| --- | --- | --- |
| Variable | `WINDOWS_RELEASE_PYTHON_PATCH_VERSION` | 审批的精确 `3.12.x` |
| Variable | `WINDOWS_RELEASE_PYTHON_EXECUTABLE_SHA256` | 资格日志中的 `python.exe` SHA-256 |
| Variable | `WINDOWS_INNO_COMPILER_SHA256` | 资格日志中的 `ISCC.exe` SHA-256 |
| Variable | `WINDOWS_RELEASE_WHEELHOUSE_MANIFEST_SHA256` | 已复核 wheelhouse 清单 SHA-256 |
| Variable | `WINDOWS_NUITKA_DOWNLOADS_MANIFEST_SHA256` | 已复核 Nuitka 缓存清单 SHA-256 |
| Variable | `WINDOWS_MODEL_ISSUER_TRUST_STORE_SHA256` | 独立批准的生产公钥信任库 SHA-256 |
| Secret | `WINDOWS_RELEASE_WHEELHOUSE_MANIFEST_B64` | 已复核 wheelhouse 清单的 Base64 |
| Secret | `WINDOWS_NUITKA_DOWNLOADS_MANIFEST_B64` | 已复核 Nuitka 缓存清单的 Base64 |
| Secret | `WINDOWS_MODEL_ISSUER_TRUST_STORE_B64` | 已复核生产公钥信任库的 Base64 |

Environment 必须只允许 `main`，并配置发布审批人。Base64 字段使用 Secret 是为了
受保护地物化精确文件，不代表公钥清单本身是私密钥。任何清单、工具摘要、
Python patch、生产信任库或冻结 commit 变化，都必须重新运行资格阶段并重新审批，
不能只改某个摘要让构建“通过”。

### 4.2 第二阶段：审批并构建 `INTERNAL-UNSIGNED`

再次手工运行同一 workflow，branch 仍选 `main`，设置
`release_mode=internal-unsigned` 且保持 legacy 选项为 `false`。前置 Windows PowerShell
5.1/安装事务门禁成功后，正式 job 会在
`windows-internal-unsigned-release` Environment 等待获授权的发布复核人批准。
未批准前不会分配正式 runner，也不会取得 Environment 中的值。

批准后，新的 `windows-2022` runner 必须：

1. 取得精确 CPython patch，并核对 `python.exe` 和预装 Inno 的外部批准 SHA-256；
2. 从受保护值物化两份清单和生产模型信任库，在解析前先核对各自 SHA-256；
3. 按已批准清单摘要精确恢复 wheelhouse，并由根构建器逐文件核对文件集、大小和
   SHA-256；
4. 按清单摘要精确恢复 Nuitka 依赖缓存，cache miss、额外/缺失文件、大小或
   SHA-256 不一致都立即失败；
5. 在不放宽正式门禁的情况下构建两份 Setup，完成故障注入、真实安装、健康、
   升级/卸载和发行文件复核；
6. 对最终两份 Setup、`release-manifest.json` 和 `SHA256SUMS.txt` 生成 GitHub
   artifact attestation；证明生成失败则不上传正式 artifact；
7. 只上传 `mineguard-windows-INTERNAL-UNSIGNED-<commit>`，保留期以 workflow 中的
   `retention-days` 为准。

缓存被 GitHub 清理、托管镜像中 Python/Inno 变化或任何清单核对失败时，正式 job
必须失败关闭。正确恢复方法是在当前 `windows-2022` 镜像重跑
`qualify-formal-inputs`、独立复核并更新 Environment，不是关掉清单或允许构建期临时
下载未批准组件。

成功 artifact 必须恰好包含两份名称以 `INTERNAL-UNSIGNED.exe` 结尾的 Setup、
`release-manifest.json` 和 `SHA256SUMS.txt`。根清单分类为
`unsigned-internal-release`，`production_approved=true`，两份 Setup 的 Authenticode 状态必须是
`NotSigned`。`installers[].child_release_manifest_sha256` 分别覆盖对应产品完整
runtime、部署脚本和发行元数据文件集合。

### 4.3 下载后验证 provenance 和介质外摘要

只从上述 `internal-unsigned` 正式 job 的 **Artifacts** 下载，解压后先对四个单独文件
验证 attestation，而不是验证 GitHub 生成的外层 ZIP。联网验收终端安装 GitHub CLI 并
登录后，在解压目录执行：

```powershell
$Repo = 'Lhongpei/MineGuard'
$Targets = @()
$Targets += @(Get-ChildItem -File -Filter 'MineGuard-Platform-*-INTERNAL-UNSIGNED.exe')
$Targets += @(Get-ChildItem -File -Filter 'MineGuard-EnterpriseAgent-*-INTERNAL-UNSIGNED.exe')
$Targets += @(Get-Item -LiteralPath '.\release-manifest.json')
$Targets += @(Get-Item -LiteralPath '.\SHA256SUMS.txt')
if ($Targets.Count -ne 4) { throw '正式 artifact 必须恰好找到四个待验证文件。' }
foreach ($Target in $Targets) {
  gh attestation verify $Target.FullName -R $Repo
  if ($LASTEXITCODE -ne 0) { throw "Artifact attestation 验证失败: $($Target.Name)" }
}
```

验收记录应保留 workflow run URL/ID、冻结 commit SHA、artifact 名、四份验证结果和两份
Setup SHA-256。Attestation 只证明“该摘要的文件由该 GitHub 仓库/workflow/commit
生成”，不是 Authenticode 发布者签名，不单独证明程序无恶意或现场已批准上线。
无法联网的现场，由发布人在联网验收机先完成 attestation 验证并把上述记录与
摘要通过受控渠道交付；现场仍必须用本机 `Get-FileHash` 比对介质外摘要。

发布负责人应把两份 Setup 各自的 SHA-256 以及各自的
`child_release_manifest_sha256` 写入审批单，通过电话、纸质交接单或独立审批
系统交给现场人员。不要只把 Setup、`SHA256SUMS.txt` 和摘要放在同一个 U 盘里。
静默安装必须显式提供同样的外部摘要，例如：

```powershell
$ExpectedSetupSha256 = '<从介质外审批记录取得的 64 位 SHA-256>'
& '.\MineGuard-Platform-0.6.1-windows-x64-INTERNAL-UNSIGNED.exe' `
  /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- `
  /ALLOWUNSIGNEDINTERNALRELEASE=1 `
  /EXPECTEDINSTALLERSHA256=$ExpectedSetupSha256
```

Platform 和 Agent 是两份不同文件，必须分别使用各自的外部摘要。安装后的正式服务向导还会
分别要求介质外批准的 Platform/Agent 子发行清单 SHA-256 和 WinSW SHA-256，不能从本机待安装
文件自动计算后当作预期值。Windows 可能显示“未知发布者”，这是无 Authenticode 证书路径
的预期现象；attestation 或摘要不匹配时均不得继续。

这里免除的是 **Windows 程序代码签名证书**。跨机器正式访问仍应通过单位 HTTPS 反向代理
使用其 TLS 证书；企业接入包和模型授权包使用的 Ed25519 签发密钥也是另一套业务信任机制，
不能一并删除。

### 4.4 可选 Authenticode 正式候选签名（仍使用自托管 runner）

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
  -ModelIssuerTrustStore 'D:\approved-trust\model-credential-trust.json' `
  -ExpectedModelIssuerTrustStoreSha256 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' `
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
和时间戳。此路径的文件名不带未签名后缀，清单分类为
`signed-production-candidate`；无证书正式路径则明确带 `INTERNAL-UNSIGNED` 后缀。签名表示
来源和完整性，不等于自动批准上线。
通过 GitHub Actions 构建时，必须显式选择 `release_mode=signed`；签名成功后上传的
artifact 名为 `mineguard-windows-signed-candidate-<commit>`。签名路径不以额外的布尔开关作为
发布授权，避免选项冲突或误将测试构建当成正式介质。
正式签名模式还会强制拒绝 `-AllowNuitkaToolDownloads`；Nuitka 所需辅助缓存必须提前从
审批介质预置，不能在签名构建时临时联网取得。正式自托管 runner 也不运行
`actions/setup-python`：必须由受保护变量指定预装的 `python.exe`、精确 3.12 patch 及其
批准 SHA-256。正式 Agent 安装器还必须嵌入由独立审批输入提供的生产模型签发信任库，
并在构建前核对其外部 SHA-256；仓库中的 `TEST-ONLY` 信任库即使改名也会被拒绝。
根构建在使用前实际核对 Python、ISCC、SignTool 和模型信任库，并把同一个已解析的
`python.exe` 显式传给 Platform 与 Agent 子构建；任何实际散列、Python patch 或子清单
记录不一致都会失败。Output、wheelhouse 和 wheelhouse manifest 之间也不得相等或互相
包含，避免构建输出污染受审批输入。

## 5. 交付核验与安装

正式安装的信任入口有两种互斥方式：带时间戳的 signed Setup，或明确标记为
`INTERNAL-UNSIGNED`、先通过 GitHub artifact attestation 来源验证，再通过介质外
SHA-256 核验的 Setup。前者需取得预期 SHA-256 和 signer thumbprint；后者的
attestation 验证方法见 4.3，现场执行仍只接受每份 Setup 独立的外部 SHA-256，
不接受包内清单自证。执行前检查介质：

```powershell
Get-AuthenticodeSignature .\MineGuard-Platform-*-windows-x64.exe |
  Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
Get-FileHash .\MineGuard-Platform-*-windows-x64.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

不要把与安装器放在同一可写目录里的散列文件单独当成真实性证明。无签名 Setup 内置的
摘要输入页会再次核对自身，但它不能替代“执行前、用目标机已受信任系统工具”的核验；
被针对性篡改的未签名程序本身不能充当自己的信任根。先对每份无签名 Setup 做显式比较：

```powershell
$Setup = '.\MineGuard-Platform-0.6.1-windows-x64-INTERNAL-UNSIGNED.exe'
$ApprovedSha256 = Read-Host '输入介质外批准的 Platform Setup SHA-256'
$ActualSha256 = (Get-FileHash -LiteralPath $Setup -Algorithm SHA256).Hash
if (-not $ActualSha256.Equals(
    $ApprovedSha256, [StringComparison]::OrdinalIgnoreCase)) {
  throw '安装包 SHA-256 不一致，禁止执行。'
}
& $Setup
```

Platform 和 Agent 分别执行一次，且必须使用各自摘要。核验一致后图形安装可双击；Setup
同时内置简体中文和英文安装界面，并按 Windows 界面语言自动选择。下面是签名版静默安装
示例；`INTERNAL-UNSIGNED` 静默参数见上一节：

```powershell
$PlatformVersion = '<platform-version>' # 必须与 Platform release-manifest.json 一致
$AgentVersion = '<agent-version>'       # 必须与 Agent release-manifest.json 一致

& ".\MineGuard-Platform-$PlatformVersion-windows-x64.exe" `
  /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-

& ".\MineGuard-EnterpriseAgent-$AgentVersion-windows-x64.exe" `
  /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
```

Setup 先把子项目 release staging 展开到临时目录，再调用包内产品安装脚本。产品脚本逐项
复核 release manifest 和 SHA-256，做自检、原子切换 runtime、设置 ACL，并把版本清单
落到 `release-metadata`。子脚本任何非零退出码都会中止 Setup，其 stdout/stderr 写入
Inno Setup 日志；不会再出现“产品安装失败但 Setup 显示成功”。
包内脚本的 manifest、SHA-256 和 Authenticode 复核是建立信任后的纵深防御，不能认证正在
执行的脚本自身。直接展开 release staging 或以管理员运行其中 PS1，只允许用于受控构建、
故障注入或兼容性测试，不得称为正式交付或正式安装，也不是信任根。

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

### 6.1 政府 Platform 图形配置（推荐）

政府 Platform 默认在 `C:\ProgramData\MineGuard\Platform`。从开始菜单打开
**MineGuard Platform 控制中心**：

- 展示验收：在“本机展示”页确认演示边界后一键准备并启动，无需 `clients.json`；
- 正式内网：在“正式内网配置”页选择 `clients.json` 和专用状态目录，填写端口、管理员
  账号及可选的单位 HTTPS 地址，再点击“打开安全密码窗并配置”；独立 helper 进程会在小窗口中
  要求输入和确认密码，完成或取消后立即退出；HTTPS 地址不得
  包含账号口令、查询参数或 `#` 片段，且只用于本次打开浏览器，不会持久保存；
- 再次打开：点击“启动当前配置”或“打开领导端页面”，控制中心不会重写已有配置；
- 浏览器：只支持仍在安全支持期内的 Edge/Chrome，不支持 Internet Explorer；
- 运行方式：这是前台启动，关闭控制中心会停止由它启动的 Platform。正式常驻服务继续按
  6.3 节使用经批准的 WinSW。

演示账号 `admin / 123123123` 只在本机展示模式启用。正式模式启用 Secure Cookie，应用只
监听 `127.0.0.1`；应先配置单位批准的 HTTPS 反向代理，再让领导端通过 HTTPS 地址访问。
控制中心的非敏感运行记录写在受保护的 `logs\control-center-*.log`，密码不会进入
主控制中心、命令行或日志。

### 6.2 政府 Platform 高级命令入口

需要脚本化运维时，仍可从管理员 PowerShell 准备正式 `clients.json`，再通过安全交互输入
首次管理员密码：

```powershell
Set-Location 'C:\ProgramData\MineGuard\Platform\service'
.\Set-MineGuardPlatformConfiguration.ps1 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -ClientsFile 'D:\approved-media\clients.json'
```

### 6.3 企业 Agent 与正式 Windows 服务

企业 Agent 程序默认在 `C:\Program Files\MineGuard\EnterpriseAgent`，实例状态在
`C:\ProgramData\MineGuard\EnterpriseAgent\instances`。一矿一智能体。正式新部署从开始
菜单打开 **MineGuard 企业接入配置向导**，加载监管端交付的企业目录，另行选择激活码，
核对独立审批摘要，再建立经办/复核两个具名账号。向导验签、解密并原子发布实例配置，
现场人员不手写矿井身份、政府地址或两把 HMAC。下面的手工命令仅是高级兼容入口：

```powershell
Set-Location 'C:\Program Files\MineGuard\EnterpriseAgent\deploy\windows'
.\New-EnterpriseAgentInstance.ps1 `
  -InstanceName qinyuan-001 -MineId MINE-QY-001 `
  -MineName '本矿名称' -OperatorId OP-QY-001 `
  -OperatorName '本企业名称' -SystemId agent-qy-001 -Port 8090
```

演示登录只限回环隔离测试，不能用于确认、报送或生产服务。模型能力必须在企业接入实例
完成后，从开始菜单打开 **MineGuard 模型授权导入向导**，分别选择本矿 `.mgllm` 和经另一
渠道交付的激活码。正式实例禁止在 `agent.env` 中写入 API Key、模型地址或可替换的信任库；
密钥由向导转换为本机 DPAPI 保护的秘密库，政府 Platform 不接收这些内容。未导入模型授权
不影响 CSV 导入、确定性校验、报送和监管算法。

安装器不下载也不捆绑 WinSW。Platform 或 Agent 需要长期常驻 Windows 服务时，继续使用
两个产品随包提供的服务安装脚本，并从单位批准的软件源单独取得 WinSW、核验预先批准的
SHA-256。图形控制中心不能替代这一正式服务安装和审批流程。

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

GitHub Actions 的 [windows-release.yml](../.github/workflows/windows-release.yml) 有四条互不
混淆的手工路径：

- `qualify-formal-inputs`：在 `windows-2022` 上生成候选清单和按清单摘要命名的
  Nuitka 依赖缓存；不构建 EXE，不发布 artifact；
- `unsigned-test`：在 `windows-2022` 上执行构建和安装生命周期验证；不上传任何可安装
  EXE 或发行 artifact；
- `internal-unsigned`：仅在 `main` 上运行，通过
  `windows-internal-unsigned-release` Environment 审批后，在新的 `windows-2022`
  GitHub-hosted runner 上重建并核对已批准输入、执行完整生命周期测试、为精确
  四文件生成 artifact attestation，然后上传无证书内网正式版；
- `signed`：仍只能在同时带 `self-hosted`、`windows`、`x64`、`signing`
  标签、预装证书/SignTool/Python/Inno 和已批准离线介质的隔离自托管 runner 上生成。

托管的无证书正式路径不读取 SignTool、代码签名证书或时间戳值；它使用 4.1
列出的摘要与 Base64 清单物化精确输入，不使用自托管机器绝对路径。签名路径的
`windows-production-signing` Environment 仍需要自托管 runner 上的
`WINDOWS_RELEASE_PYTHON_EXECUTABLE`、`WINDOWS_RELEASE_WHEELHOUSE`、
`WINDOWS_MODEL_ISSUER_TRUST_STORE`、`WINDOWS_INNO_COMPILER`、`WINDOWS_SIGNTOOL_PATH`、
它们的已批准 SHA-256，以及证书 thumbprint 和时间戳 URL。

只有 `internal-unsigned` 和 `signed` 两条正式路径会上传 artifact，且都不自动创建
公开 Release。推送 `main` 或 tag 本身不会绕过手工发布选择和 Environment 保护。
发布清单记录版本、实际/预期散列和外部锚核验结果；attestation 另行关联仓库、
workflow、run 和 commit，不被包内文件当作自证材料。
