# Bundled WinSW service wrapper

- Upstream: https://github.com/winsw/winsw
- Release: `v2.12.0`
- Asset: `WinSW-x64.exe`
- SHA-256: `05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da`
- License: MIT; see `LICENSE.txt`.

`Build-EnterpriseAgentBinary.ps1` rejects the asset unless its digest matches
this pinned release policy. The verified file and license are copied under
`deploy/windows/service-host/` and included in the Agent child release
manifest. Target machines never download WinSW.
