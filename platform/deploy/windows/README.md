# MineGuard Platform Windows 运维入口

本目录由 MineGuard Platform Windows 安装包部署。普通使用者不需要进入这个目录，也不
需要输入 PowerShell 命令；本页前两节先说明图形控制中心，后面的命令只供管理员高级运维。

首次现场部署请先阅读
[Windows 现场部署与网络配置手册](../../../docs/mineguard.cn正式上线步骤.md)。该手册说明
单一 Platform 域名、内外网 DNS、双层路由、Caddy HTTPS、政府多矿注册及企业接入顺序。

正式安装的信任入口是 Setup 介质本身。有证书模式在执行前核对 Setup
SHA-256 和签名者指纹，使用 signed Setup；显式的 `INTERNAL-UNSIGNED` 受控内网模式
不核验签名者，必须从安装介质之外的独立批准记录核对 Setup SHA-256，并在
安装正式服务时再输入该产品的子发行清单 SHA-256。直接展开 staging 不能认证其中脚本
自身，不是信任根。默认 `unsigned-test-artifacts` 仍只能用于兼容性测试，
不能安装正式服务。

## 1. 一键打开本机展示

1. 从 Windows 桌面或开始菜单点击 **MineGuard Platform 控制中心**；出现管理员权限确认时选择
   “是”。
2. 选择“本机展示（推荐先看）”。
3. 勾选红色确认项，再点击“一键准备并启动展示”。
4. 等待右下角显示服务正常；控制中心会优先用 Edge 或 Chrome 打开领导端。

演示登录账号是 `admin`，密码是 `123123123`。它只监听本机，只用于功能展示，不得用于
正式运行、企业报送或监管认定。Internet Explorer 不受支持；没有 Edge/Chrome 时，控制
中心会显示可拍照反馈的提示，请先离线安装现代浏览器，不要用 IE 打开。

控制中心启动的是前台进程。窗口保持打开才会继续运行；关闭窗口时会先询问，确认后停止
本次启动。这不是“卡死”。需要长期常驻运行时，完成前台验收后再按第 4 节安装正式服务。

## 2. 配置正式环境（内网和公网）

新部署优先从开始菜单打开 **MineGuard 企业接入包与注册向导**。它按三个页面完成：

企业 Agent 只需知道一个稳定的政府 Platform HTTPS 地址。如同时有内网和公网，
推荐两边共用同一个 FQDN：公网 DNS 指向公网入口/NAT，内网 DNS 把同一域名解析到
私网入口。企业 Agent 本身只在企业电脑的 `127.0.0.1` 上打开，不需企业域名或入站 HTTPS。

1. 初始化口令加密的签发密钥；
2. 填写煤矿、企业和政府 Platform HTTPS 地址；技术 ID、实例名、版本号以及政府侧
   保管目录由当前版本自动生成。开采方式、班次、煤种、产能分组等资料不是接入必填项。
   界面只要求选择一个企业交付根目录；企业交付目录必须且只能包含一个 `.mgprov`；
   激活材料和签发公钥已嵌入该文件，企业无需另行输入 CA、激活码、公钥或指纹；
3. 生成成功后向导自动切到“完成监管端配置”，并带入本机保管的配对 `.mgreg`、Platform
   激活码和签发信任；监管人员只需设置首次管理员密码并提交。向导验签后事务写入
   `clients.json`、Platform 身份及签发信任锚。若正式服务
   正在运行，界面会明确提示短暂停服；只有操作员确认后才停止，并在成功或失败后自动恢复。

首次成功生成后，向导会在管理员签发目录保存不含秘密的 `authority-policy.json`，后续煤矿
自动复用并锁定 issuer、Platform 身份和 Platform URL 等监管固定项，避免多矿误填成
互不兼容的注册表。每次继续签发前会重新计算固定公钥 SHA-256 并与策略文件比较；
文件被替换时闭锁。签发私钥永远不进入企业交付目录。监管注册、激活码和签发机构目录使用安装根下带所有权标记的
固定 NTFS 专用目录；向导不会对用户任意选择的宽泛目录递归改 ACL。

第一次生成前，向导会创建
`provisioning-authority\authority-policy.pending.json`；四区材料和固定策略全部成功后，
才原子发布 `authority-policy.json` 并删除 pending 标记。策略保存、ACL 或发布任一步失败时
不会显示“生成成功”，pending 标记会保留并闭锁后续签发。此时不得直接删除标记或继续交付
已经生成的材料；应先核对四区输出和审计记录，再按单位批准的恢复流程处理。

当前图形流程只生成和导入 `profile_version=1` 的全新配置，不显示旧版升级、手工
`clients.json` 注册或固定策略迁移入口。正式模式始终只监听 `127.0.0.1` 并启用 Secure
Cookie；领导端应通过单位批准的 HTTPS 反向代理访问。控制中心的非敏感运行记录写入受保护的
`logs\control-center-*.log`，现场报错时可直接拍照窗口底部“运行状态”栏。
配置与启动共用机器级 `Global\MineGuardPlatform.Configuration` Mutex：启动会在同一锁内
检查阻断标记和残留事务、读取配置，并持有到长运行子进程完全退出。因此前台或服务
运行期间配置脚本会闭锁拒绝修改 config/state/ACL；正常退出、向导停止和异常终止都会在
`finally` 或操作系统关闭进程句柄时释放 Mutex。30 秒超时则闭锁拒绝启动/配置。

## 3. 高级命令：配置并前台验收

以下命令都应在“以管理员身份运行”的 **Windows PowerShell 5.1** 中执行。不要从邮件、
临时目录或源码副本运行同名脚本；服务安装和移除脚本会验证自己确实属于当前已安装版本。

准备单位批准的逐矿 `clients.json`，然后通过安全交互设置首次管理员密码：

```powershell
Set-Location 'C:\ProgramData\MineGuard\Platform\service'
Set-ExecutionPolicy -Scope Process Bypass

.\Set-MineGuardPlatformConfiguration.ps1 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -ClientsFile 'D:\approved-media\clients.json'

.\Start-MineGuardPlatform.ps1 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform'
```

另开一个管理员 PowerShell 窗口运行健康检查：

```powershell
& 'C:\ProgramData\MineGuard\Platform\service\Test-MineGuardPlatform.ps1' `
  -BaseUri 'http://127.0.0.1:8080'
```

确认后停止前台进程，再安装 Windows 服务。

## 4. 安装 Windows 服务

安装包不下载或捆绑 WinSW。请从单位批准的软件供应链取得 WinSW x64，并从独立批准记录
取得 SHA-256；不要把现场文件即时计算出的散列反过来当作批准值。

```powershell
$ApprovedWinSWSha256 = '<从独立批准记录取得的64位SHA-256>'
$ApprovedPlatformSigner = '<从独立审批记录取得的40位代码签名证书指纹>'

.\Install-MineGuardPlatformService.ps1 `
  -WinSWExecutable 'D:\approved-tools\WinSW-x64.exe' `
  -ExpectedSha256 $ApprovedWinSWSha256 `
  -Production `
  -ExpectedSignerThumbprint $ApprovedPlatformSigner `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -StartService
```

如果批准介质同时包含 `WinSW-x64.exe.config`，还必须从独立批准记录取得该文件的散列，
并增加：

```powershell
-ExpectedConfigSha256 '<该 .config 的独立批准 SHA-256>'
```

没有 companion `.config` 时不要传这个参数。正式配置还必须显式使用 `-Production`，
并从待安装介质之外的审批记录传入 `-ExpectedSignerThumbprint`；脚本会核验正式发布分类、
有效且带时间戳的 Authenticode 签名和实际签名者。安装脚本会验证 Platform 发布清单、配置和
状态目录身份，重复核对 WinSW 散列，并在注册、启动或健康检查失败时回滚本次服务安装。
正式配置、每次启动和服务安装都会重复核验账号库及状态用途：仍启用的演示/默认凭据、
没有完成改密的正式管理员、或包含演示/合成记录的状态库都会被拒绝；演示数据不能原地
转换为正式数据。

如果已安装明确标记为 `INTERNAL-UNSIGNED` 的内网候选版，不填写签名者指纹，
改为从介质外独立批准记录取得 Platform 的 `child_release_manifest_sha256`。该值位于
根发行 `release-manifest.json` 对应 Platform 项中，交付前必须连同 Setup SHA-256 一起
抄入介质外审批记录：

```powershell
$ApprovedPlatformReleaseManifestSha256 = '<介质外独立批准的64位子发行清单SHA-256>'

.\Install-MineGuardPlatformService.ps1 `
  -WinSWExecutable 'D:\approved-tools\WinSW-x64.exe' `
  -ExpectedSha256 $ApprovedWinSWSha256 `
  -Production `
  -AllowUnsignedInternalRelease `
  -ExpectedReleaseManifestSha256 $ApprovedPlatformReleaseManifestSha256 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -StartService
```

该通道只接受 `unsigned-internal-release`；签名候选版、默认未签名测试版或
分类与构建元数据不一致的介质都会被拒绝。这只替换 Authenticode 发布者验证，
不会关闭 `-Production`、Secure Cookie、HTTPS 反向代理、正式账号、状态用途、客户端
注册表、受管签发信任或健康检查等门禁。

配置脚本使用机器级命名 Mutex 串行化全部配置事务。若异常中断或回滚不完整，固定的
`config\.mineguard-configuration-blocked.json` 会阻止再次配置和启动；请按标记中的精确
`transactionDirectory` 停服核验、清理后，再删除该固定标记并重新配置。
标记不是唯一依据：两条入口还会有界扫描 config 直系子目录，任何精确的
`.configuration-transaction.<32位十六进制>` 残留都会独立阻断。

图形控制中心的“正式服务安装”页会识别发布分类：签名候选版要求签名者
指纹，`INTERNAL-UNSIGNED` 要求子发行清单 SHA-256 并弹出无发布者身份的风险确认，
默认未签名测试版直接禁用正式服务按钮。所有信任锚都必须由操作员从介质外
批准记录手工填写，界面不会从 `build-metadata.json` 自动填入。

## 5. 健康检查、备份与恢复

```powershell
.\Test-MineGuardPlatform.ps1 -BaseUri 'http://127.0.0.1:8080'
.\Backup-MineGuardPlatform.ps1 -InstallRoot 'C:\ProgramData\MineGuard\Platform'
```

恢复必须指向本机固定 NTFS 上不存在或为空的新专用目录，不能覆盖在线状态。先阅读脚本
帮助并在隔离端口验收恢复副本，再通过配置事务切换状态目录。

## 6. 移除服务和卸载

```powershell
.\Remove-MineGuardPlatformService.ps1 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform'
```

需要同时移除三个经完整性校验的 WinSW 服务文件时，显式增加
`-RemoveWrapperFiles`。这两个操作都不会删除 `runtime/config/state/backups/logs` 中的
业务数据。服务注册移除后，才可从 Windows“已安装的应用”卸载 Platform 程序。

正式接入时应只监听 `127.0.0.1`，由单位批准的 HTTPS 反向代理对外提供访问；不要启用
演示默认密码。完整的构建、签名、升级、备份和恢复口径见交付介质中的
“MineGuard Platform deployment guide”。
