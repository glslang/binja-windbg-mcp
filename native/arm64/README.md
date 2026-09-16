# Native ARM64 CLRBHB support

This companion-maintained replacement fixes instruction `D50322DF` (`clrbhb`) in
Binary Ninja **6.0.10601, SDK ABI 187, Apple Silicon macOS 13+**. It handles the
zero-operand decode case and emits the `SystemHintOp_CLRBHB` LLIL intrinsic,
allowing analysis to continue into the following instruction. Other versions
require a separately pinned build and validation.

## Build

Requires Xcode command-line tools, CMake, Python 3.13 and the installed Binary
Ninja application. From the companion repository:

```sh
python3 tools/build_arm64.py
```

The builder downloads hash-checked source archives pinned in the script, applies
`clrbhb.patch`, and produces `dist/arm64-clrbhb-bn6-abi187-macos-arm64.zip` and an
unpacked directory. `--sdk-archive` and `--fmt-archive` accept previously downloaded
archives for an offline build. Only verified archives are reused: each invocation
extracts fresh SDK/fmt sources, reapplies the patch and compiles in a fresh temporary
build directory with `CMAKE_OSX_ARCHITECTURES=arm64`. The built library must pass
`lipo -verify_arch arm64` before packaging. SDK and fmt licenses accompany the library.
The build never installs anything or changes the application bundle.

## Install and remove

Run with native arm64 Python on Apple Silicon macOS 13.0 or newer. Installation
rejects Intel Macs, x86_64 Python under Rosetta, other operating systems and macOS
versions below 13.0 (or an unreadable version) before changing a profile. The
selected Binary Ninja executable must contain an arm64 slice, checked with
macOS `lipo`. Binary Ninja must also run natively, without Rosetta.

Close Binary Ninja first. Choose an explicit user profile, preferably a disposable
one for initial validation:

```sh
python3 tools/build_arm64.py \
  --install dist/arm64-clrbhb-bn6-abi187-macos-arm64 --profile /tmp/bn-clrbhb-profile
BN_USER_DIRECTORY=/tmp/bn-clrbhb-profile \
  '/Applications/Binary Ninja.app/Contents/MacOS/binaryninja' --new-instance
```

The installer verifies the installed SDK revision, the package hash, and all
recorded build inputs against this checkout: patch digest, fmt revision, both
source archive hashes and the minimum macOS version. Stale or incomplete manifests
are rejected before profile changes. The package library must also pass the
arm64 slice check before installation. It copies the
library to a temporary file, verifies its hash, then disables
`corePlugins.architectures.aarch64` before atomically publishing the library in
that profile's `plugins`. It refuses an existing replacement. Removal checks
ownership, removes the replacement, then restores the previous setting while
preserving unrelated settings. Both operations retain the receipt until finished
so an interrupted operation can be recovered with `--uninstall`:

```sh
python3 tools/build_arm64.py --uninstall --profile /tmp/bn-clrbhb-profile
```

Use fresh analysis or reanalyze affected databases. The added intrinsic extends
the normal intrinsic list; the compiled NEON intrinsic IDs follow that list.
Do not reuse serialized IL across stock and replacement architectures.

## Acceptance capture

`tools/capture_arm64.py` installs the package into a new disposable profile,
verifies the loaded native image, checks CLRBHB text and LLIL, analyzes all sixteen
recorded Secure Kernel endpoints, and runs a complete external BinDiff comparison
with all eight endpoint diffs and unchanged-input checks. Each diff must contain
the three expected reference/target instruction RVAs with complete text. The
launcher saves and hashes the companion Python modules and native BinExport helper
next to the probe so delayed imports use those copies. Third-party dependencies
remain supplied through `--python-path`. It requires the exact
ARM64 pair identified by hashes in `tools/clrbhb_gui_probe.py`:

```sh
python3 tools/capture_arm64.py \
  --package dist/arm64-clrbhb-bn6-abi187-macos-arm64 \
  --binaryninja '/Applications/Binary Ninja.app/Contents/MacOS/binaryninja' \
  --license-file '/path/to/license.dat' --output /tmp/clrbhb-acceptance \
  --python-path "$PWD" --python-path /path/to/mcp-dependencies \
  --reference /path/to/reference/securekernel.exe \
  --target /path/to/target/securekernel.exe --bindiff /path/to/bindiff
```

The license travels only through the child environment. Reports omit it. The
launcher waits for the actual GUI exit and records forced exits or crash reports
as failures. No Ultimate license is needed for this external comparison.

## Upstream

`clrbhb.patch` includes native decoder, LLIL and disassembly regression changes
against the pinned stable SDK. Rebase the small patch onto Vector35's current
development branch before opening an upstream PR. Once an upstream release
passes the same acceptance capture, remove this replacement and re-enable the
bundled architecture. The exporter's existing fallback remains useful on stock
installations.
