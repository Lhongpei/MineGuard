# MineGuard Platform Windows 运维入口

本目录由 MineGuard Platform Windows 安装包部署。普通使用者不需要进入这个目录，也不
需要输入 PowerShell 命令；本页前两节先说明图形控制中心，后面的命令只供管理员高级运维。

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

## 2. 用控制中心配置正式内网

首次正式配置前，管理员先准备单位批准的逐矿 `clients.json` 和用途单一的本机 NTFS 状态
目录。打开控制中心并切换到“正式内网配置”，依次：

1. 选择 `clients.json` 和状态数据目录，确认本机端口；
2. 填写管理员用户名和两遍正式密码。图形向导要求至少 12 位、同时包含字母和数字，且
   禁止使用演示密码 `123123123`；
3. 单位 HTTPS 反向代理已经就绪时，填写领导端 HTTPS 地址。必须是完整的 `https://`
   地址，不能包含账号口令、查询参数或 `#` 片段；该栏只用于本次打开浏览器，不会配置
   反向代理，也不会持久保存；
4. 点击“保存正式配置并启动”，等待健康检查通过后再打开领导端。

密码通过内存中的安全对象交给受保护配置脚本，不出现在命令行和控制中心日志中。正式模式
始终只监听 `127.0.0.1` 并启用 Secure Cookie；领导端应通过单位批准的 HTTPS 反向代理
访问。控制中心的非敏感运行记录写入受保护的 `logs\control-center-*.log`，现场报错时也可
直接拍照窗口底部“运行状态”栏。已有配置或已有状态数据时，控制中心会禁止一键覆盖，只
提供启动和打开页面入口。

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

.\Install-MineGuardPlatformService.ps1 `
  -WinSWExecutable 'D:\approved-tools\WinSW-x64.exe' `
  -ExpectedSha256 $ApprovedWinSWSha256 `
  -InstallRoot 'C:\ProgramData\MineGuard\Platform' `
  -StartService
```

如果批准介质同时包含 `WinSW-x64.exe.config`，还必须从独立批准记录取得该文件的散列，
并增加：

```powershell
-ExpectedConfigSha256 '<该 .config 的独立批准 SHA-256>'
```

没有 companion `.config` 时不要传这个参数。安装脚本会验证 Platform 发布清单、配置和
状态目录身份，重复核对 WinSW 散列，并在注册、启动或健康检查失败时回滚本次服务安装。

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
