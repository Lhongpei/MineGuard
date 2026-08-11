# MineGuard Platform Windows 二进制构建

该目录只用于可信 Windows 构建机，不进入最终客户安装目录。构建结果是 Nuitka
`standalone` 目录，不是临时解压运行的 onefile 程序：

```text
<OutputDirectory>/MineGuardPlatform-<version>-windows-x64/
  runtime/
    MineGuardPlatform.exe
    ...受控 DLL、PYD、时区和前端资源...
  deploy/windows/
  VERSION.txt
  build-metadata.json
  release-manifest.json
  SHA256SUMS.txt
```

在安装了 CPython 3.12 x64、Visual Studio 2022 Build Tools（Desktop
development with C++）的 Windows Server 2022 构建机上运行：

```powershell
& .\platform\packaging\windows\Build-MineGuardPlatform.ps1 `
  -OutputDirectory 'C:\MineGuardBuild\Platform' `
  -AllowNuitkaToolDownloads
```

若选择 Authenticode 签名正式交付路径，应追加 `-SignToolPath`、`-SigningCertificateThumbprint`、
`-TimestampUrl` 和 `-RequireSignedBinary`，使主程序在生成发布清单之前完成
Authenticode 签名。证书私钥只存在于可信构建机的证书存储，不进入参数或仓库。
脚本默认拒绝有未提交改动的工作树；只有不对外交付的本地调试才可显式使用
`-AllowDirtySource`，并且该开关不能绕过 `-RequireSignedBinary` 的干净 revision 要求。
正式签名模式还强制要求 `-Wheelhouse`，并拒绝 `-AllowNuitkaToolDownloads`；根发行构建器
会进一步用外部审批散列认证 wheelhouse 清单，只有根链路才能把最终安装器标成正式候选。

不使用代码签名证书的受控内网，可以显式生成
`unsigned-internal-release`：

```powershell
& .\platform\packaging\windows\Build-MineGuardPlatform.ps1 `
  -OutputDirectory 'C:\MineGuardBuild\Platform' `
  -PythonExecutable 'C:\ApprovedPython\python.exe' `
  -ExpectedPythonPatchVersion '<approved-3.12.x>' `
  -ExpectedPythonExecutableSha256 '<approved-python-sha256>' `
  -Wheelhouse 'C:\MineGuardBuild\wheelhouse' `
  -InternalUnsignedRelease
```

该模式与签名候选版一样要求干净且可识别的 Git revision、固定 Python patch
及可执行文件 SHA-256、已审批的离线 wheelhouse，并禁止构建期下载 Nuitka
工具。它不是默认未签名测试版，也不能与 `-RequireSignedBinary` 或任何签名
参数同时使用。最终 Setup 必须明确标识 `INTERNAL-UNSIGNED`，在执行前按介质外记录
核对 Setup SHA-256；安装正式服务时还要单独核对整个子发行清单 SHA-256。Windows 不会
显示可验证的发布者，因此只适用于受控交付和受控内网。该子构建命令只产生 standalone
暂存树；正式 Setup 必须统一由仓库根目录的
`scripts\Build-WindowsBinaryRelease.ps1 -InternalUnsignedRelease` 生成，根构建器会把子发行
清单摘要固化进已核验的 Setup，并写入最终根发行清单。

构建脚本要求 Windows PowerShell 5.1 或更高版本；源码、工具、wheelhouse、临时目录和
发布目录都必须在本机固定 NTFS 上，并拒绝 UNC、盘符相对路径以及位于符号链接、junction
或挂载点下的路径。正式离线构建应准备包含
`requirements-build.txt`、`constraints.txt` 及 Platform
全部依赖的 wheelhouse，并预置 Nuitka 工具缓存；然后传入 `-Wheelhouse`，不要使用
`-AllowNuitkaToolDownloads`。脚本先在最终版本目录的同级随机暂存目录中组装产物，
执行版本、两套前端资源、Asia/Shanghai 时区、SciPy/HiGHS 求解器、发布清单和
SHA-256 完整覆盖自检，再以同盘目录改名一次发布。默认拒绝覆盖已存在的同版本交付目录；
只有明确需要替换内部构建时才可显式传 `-Force`。此时旧目录会先改名为事务备份，新目录
发布失败则自动恢复旧目标，因此最终版本目录不会暴露半成品。

最终安装器应把 staging 的 `runtime` 内容安装到 `{app}\runtime`，所以安装后的
固定入口是：

```text
{app}\runtime\MineGuardPlatform.exe
```

`platform/deploy/windows` 中的启动、配置、服务、备份和恢复脚本会优先调用该
EXE；源码/venv 开发安装才回退到 `runtime\Scripts\python.exe -m mineguard`。
安装脚本把四个发布元数据文件保留在 `{app}\release-metadata`；无签名正式版还事务生成
`release-trust-anchor.json`，供每次正式启动复核整棵 standalone 树，便于运维核验，
且不会在升级或卸载运行时的过程中触碰 `config`、`state`、`backups` 和 `logs`。
