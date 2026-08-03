# Pinned Inno Setup language input

`ChineseSimplified.isl` is the byte-for-byte Simplified Chinese translation
shipped in the official Inno Setup source repository at tag `is-6_7_1`:

- source: `Files/Languages/Unofficial/ChineseSimplified.isl`
- upstream Git blob: `d6a11c4490de07dad443ade668289fc954dfa1ed`
- SHA-256: `7d544b9bb1d142cfa11f2e5d3cc8abe2e55f8e066c5124e3772675aa236e1278`

It is vendored because a standard Windows runner may install the compiler
without optional user-contributed translations. Release builds are offline
with respect to packaging tools and must not fetch a language file on demand.
Both the cross-platform packaging checks and the native root builder verify
the pinned SHA-256 before any long Nuitka compilation begins.

The corresponding upstream Inno Setup license is preserved in
`INNO-SETUP-LICENSE.txt`. If the translation is intentionally upgraded, update
the source tag, blob identity, byte hash and the two verification gates in the
same reviewed change.
