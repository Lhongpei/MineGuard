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

An unsigned build is marked as internal test media by default. A signed formal
worker keeps the private key in the Windows certificate store and signs before
the manifest is generated:

```powershell
.\packaging\windows\Build-EnterpriseAgentBinary.ps1 `
  -Wheelhouse 'D:\approved-wheelhouse' `
  -ModelIssuerTrustStore 'D:\approved-model-trust\model-issuers.json' `
  -ExpectedModelIssuerTrustStoreSha256 '<64-hex-offline-approved-sha256>' `
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
It also requires a separately approved model-issuer trust store and its
independently delivered SHA-256. The frozen Agent validates the strict
`mineguard-model-issuer-trust-store-v1` schema before the public trust store is
bound into the release. The repository contains a public-key-only `TEST-ONLY`
trust store for unsigned CI; all formal candidates reject it, and no corresponding
private key is retained.

For a controlled intranet that has no Authenticode certificate, the distinct
`-InternalUnsignedRelease` mode is available. It is not an alias for the
default unsigned test build: it applies the same clean-Git, exact CPython,
approved offline wheelhouse, pre-staged Nuitka cache and externally pinned
model-trust-store gates as a signed candidate, but deliberately requires the
resulting executable to remain `NotSigned`:

```powershell
.\packaging\windows\Build-EnterpriseAgentBinary.ps1 `
  -PythonExecutable 'C:\ApprovedPython312\python.exe' `
  -ExpectedPythonPatchVersion '3.12.<approved-patch>' `
  -ExpectedPythonExecutableSha256 '<64-hex-approved-python-sha256>' `
  -Wheelhouse 'D:\approved-wheelhouse' `
  -ModelIssuerTrustStore 'D:\approved-model-trust\model-issuers.json' `
  -ExpectedModelIssuerTrustStoreSha256 '<64-hex-approved-trust-sha256>' `
  -InternalUnsignedRelease
```

This writes `release_classification: unsigned-internal-release` to both
metadata documents. This child command only creates the standalone staging tree;
the official formal Setup must be produced by the repository root
`scripts\Build-WindowsBinaryRelease.ps1 -InternalUnsignedRelease` path. The root
builder binds the child `release-manifest.json` SHA-256 into the verified Setup
and records it as `installers[].child_release_manifest_sha256` for the separate
approval record. A hash read only from the same untrusted media is not an external
trust anchor. This mode provides full-tree integrity against the independently
delivered digest; it does not establish a Windows publisher identity.

For the repository's signed GitHub workflow, the protected
`windows-production-signing` environment must define
`WINDOWS_MODEL_ISSUER_TRUST_STORE` as the absolute local-NTFS path of that
approved public trust-store JSON on the controlled runner, and
`WINDOWS_MODEL_ISSUER_TRUST_STORE_SHA256` as its independently approved hash.
The file contains issuer public keys only; model API credentials and issuer
private keys must never be placed in workflow variables, the checkout, or the
release artifact.

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
  model-credential-trust.json
  VERSION.txt
  build-metadata.json
  release-manifest.json
  SHA256SUMS.txt
```

`release-manifest.json` is the machine-readable installation integrity contract.
It contains relative paths, sizes, and SHA-256 values but no source checkout
path. The deployed installer preserves all five metadata files, including the
fixed `model-credential-trust.json`, under `InstallRoot\release-metadata` for
incident response and version tracing.
The builder assembles a random sibling staging directory and publishes it by a
same-volume directory rename. It refuses an existing version by default;
`-Force` is an explicit internal rebuild operation and restores the old release
if the replacement rename fails.

The build fails if Python/C/C++ source or compiler intermediates remain under
`runtime`. Its default smoke test executes the compiled program, requests
`/api/v1/health`, and loads the bundled frontend. `-SkipSmokeTest` is only for
local compiler diagnosis; the script rejects it for signed and
`-InternalUnsignedRelease` formal candidates.

The manifest hashes detect corruption but authenticate a formal release only when
their expected digest is delivered through an independent approval channel. The
optional signed path additionally uses Authenticode; the
`INTERNAL-UNSIGNED` path deliberately has no signing private key or Windows
publisher identity.
