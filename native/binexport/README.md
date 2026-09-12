# Personal BinExport helper

This optional shared library exports an existing BinaryView inside the BN GUI. Its
`processor.cpp` is based on the MIT-licensed processor from the pinned Binary Ninja
SDK and links its pinned open-source BinExport dependencies. It registers no
commands, similarity providers, or resolvers. The Python boundary loads it lazily
and rejects a different core ABI before passing any view to the exporter. The exact
upstream license is retained in `BINARYNINJA_LICENSE.txt`.

Pinned inputs:

- Binary Ninja SDK `2ddf304b3275aa184e95570404539cbc4beb64c6` (6.0.10601, ABI 187).
- SDK BinExport submodule `c29b5f7767a66ddefefde03e4530cad0cd6b8639`.
- SDK fmt submodule `40626af88bd7df9a5fb80be7b25ac85b122d6c21`.
- Abseil and Protobuf archives and hashes are pinned by that BinExport revision.

Build on Apple Silicon macOS with Xcode command-line tools, CMake 3.25 or newer, and
BN6 installed:

```console
python3 tools/build_binexport.py --package
```

The first configure fetches sources. `--sdk` accepts an existing checkout at the
pinned revision with `vendor/fmt` and `vendor/binexport` initialized. `--bn-install`
selects a nonstandard application location. Build artifacts stay in `build/`; the
installed helper and dependency licenses go into `binja_windbg_mcp/native/`.
`--package` creates `dist/binexport-bn6-abi187-macos-arm64.zip`, ready to extract into
a companion checkout. Generated binaries are not committed. Restart BN after
replacing an already loaded helper. BinDiff itself remains user-installed.

The C ABI consists of `BNMCPExportABI`, `BNMCPCoreABI`, `BNMCPExportView`, and
`BNMCPFree`. Export ABI 1 takes a borrowed `BNBinaryView*`, UTF-8 destination and
application-defined export ID, and a `bool(void)` continuation callback. The caller
retains the view and callback until return. The exporter takes an additional view
reference and serializes calls. The returned allocated UTF-8 JSON contains either
`ok: false` and an error, or export ID, architecture, and exported flow-graph entry
addresses. Release every response using `BNMCPFree`.

The helper replaces the upstream processor's placeholder executable ID with a
unique per-input identifier. The `.BinDiff` file table must echo it for the correct
primary/secondary slot. This ID is **not an original-file hash**. Python separately
hashes export bytes and captures the existing PE identity/original hash. Functions
without exported flow graphs are reported as omitted. Cancellation is checked
between functions and at processor progress callbacks; ownership lasts until return.

The pinned BN6 AArch64 decoder does not recognize CLRBHB (`HINT #22`). The local
processor recognizes only its exact aligned four-byte encoding after BN rejects it,
then exports a four-byte fallthrough instruction named `clrbhb`. Other decode
failures retain the upstream omission behavior. This recovers flow-graph evidence;
it does not add instructions or IL to Binary Ninja's function analysis.

The install step includes SDK, BinExport, fmt, Abseil, Protobuf, utf8_range and Boost
license texts.
No Binary Ninja core library is copied or distributed with the helper.
