# MineGuard Platform Windows 运维入口

本目录由 MineGuard Platform Windows 安装包部署。下面的命令都应在“以管理员身份运行”的
**Windows PowerShell 5.1** 中执行。不要从邮件、临时目录或源码副本运行同名脚本；服务
安装和移除脚本会验证自己确实属于当前已安装版本。

## 1. 先配置并前台验收

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

## 2. 安装 Windows 服务

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

## 3. 健康检查、备份与恢复

```powershell
.\Test-MineGuardPlatform.ps1 -BaseUri 'http://127.0.0.1:8080'
.\Backup-MineGuardPlatform.ps1 -InstallRoot 'C:\ProgramData\MineGuard\Platform'
```

恢复必须指向本机固定 NTFS 上不存在或为空的新专用目录，不能覆盖在线状态。先阅读脚本
帮助并在隔离端口验收恢复副本，再通过配置事务切换状态目录。

## 4. 移除服务和卸载

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
