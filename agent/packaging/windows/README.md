# Enterprise Agent Windows binary build

This directory is the internal, native-Windows build boundary for the enterprise
Agent. It is not copied into end-user media.

## Build

Required on the build worker:

- Windows x64;
- CPython 3.12 x64 (`py -3.12` by default);
- Visual Studio 2022 Build Tools with the Desktop development with C++ workload;
- PowerShell 5.1 or newer.

All source, tool, wheelhouse, work and artifact paths must be fully qualified
drive-letter paths on a local fixed NTFS volume. The builder rejects UNC/mapped
network paths, ambiguous components, alternate data streams, and any existing
symlink, junction, mount point or other reparse-point ancestor.

Run from the `agent` directory:

```powershell
.\packaging\windows\Build-EnterpriseAgentBinary.ps1
```

On a disposable connected CI worker, pass `-AllowNuitkaToolDownloads` so a
missing approved Nuitka compiler/dependency-analysis cache can be populated
non-interactively. Without that explicit switch the build never adds Nuitka's
`--assume-yes-for-downloads` option.

For a formal offline build, do not pass `-AllowNuitkaToolDownloads`; pre-populate
the Nuitka tool cache from approved media, and make the worker's network policy
deny outbound access. `-Wheelhouse` must contain all packages referenced by
`build-requirements.txt`, `constraints.txt`, the Agent wheel/build dependencies,
and their transitive dependencies. Pip uses `--no-index` and never falls back to
the package network when that option is present; a missing Nuitka tool cache must
fail the isolated build rather than enabling the download switch.

An unsigned build is explicitly marked as internal test media. A formal worker
must keep the private key in the Windows certificate store and sign before the
manifest is generated:

```powershell
.\packaging\windows\Build-EnterpriseAgentBinary.ps1 `
  -Wheelhouse 'D:\approved-wheelhouse' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' `
  -SigningCertificateThumbprint '<40-hex-character-thumbprint>' `
  -TimestampUrl 'https://<approved-rfc3161-service>' `
  -RequireSignedBinary
```

The thumbprint is an identifier, not a private key. The build script never
accepts a PFX password or exports key material. Before the executable enters the
manifest it calls the repository's non-dot-sourced signing helper, which requires
exactly one valid Code Signing certificate, signs and runs `signtool verify /pa`,
then verifies the signer thumbprint and RFC 3161 timestamp with
`Get-AuthenticodeSignature`. `-RequireSignedBinary` also requires a clean Git
revision; the revision and dirty status are recorded without recording the source
checkout path.
Signed mode rejects online pip resolution and Nuitka tool downloads: the approved
offline wheelhouse and pre-staged Nuitka cache are mandatory. The root release
builder additionally authenticates that wheelhouse against its externally
approved manifest hash before it can classify an installer as a production candidate.

The compiler is deliberately configured for Nuitka `standalone`, not `onefile`.
The runtime must remain a directory because the executable loads its compiled
dependencies, Windows timezone data, and frontend assets from that directory.

## Output contract

The output consumed by the root installer build is:

```text
artifacts\MineGuardEnterpriseAgent-<version>-windows-x64\
  runtime\MineGuardEnterpriseAgent.exe
  runtime\web\...
  runtime\<compiled dependencies>
  deploy\windows\...
  VERSION.txt
  build-metadata.json
  release-manifest.json
  SHA256SUMS.txt
```

`release-manifest.json` is the machine-readable installation integrity contract.
It contains relative paths, sizes, and SHA-256 values but no source checkout
path. The deployed installer preserves all four metadata files under
`InstallRoot\release-metadata` for incident response and version tracing.
The builder assembles a random sibling staging directory and publishes it by a
same-volume directory rename. It refuses an existing version by default;
`-Force` is an explicit internal rebuild operation and restores the old release
if the replacement rename fails.

The build fails if Python/C/C++ source or compiler intermediates remain under
`runtime`. Its default smoke test executes the compiled program, requests
`/api/v1/health`, and loads the bundled frontend. `-SkipSmokeTest` is only for
local compiler diagnosis and must not be used by a release pipeline.

The manifest hashes detect accidental corruption; they do not authenticate the
publisher. Release automation must Authenticode-sign the executable and final
installer using credentials supplied by the controlled Windows signing worker.
No signing private key belongs in this repository or in build arguments logged
by CI.
