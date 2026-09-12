# Prepare a Personal release

This procedure builds and checks a release candidate without publishing a release,
creating a tag, or replacing a helper loaded by Binary Ninja. Personal acceptance
includes real GUI comparison, lifecycle cleanup, and guarded ARM64 WinDbg handoff.
Native Ultimate validation is deferred because of cost and does not gate this release.

## Build from a clean checkout

Use an isolated checkout of the intended commit on Apple Silicon macOS, with Xcode
command-line tools, Python 3.13, CMake 3.25 or newer, and Binary Ninja 6.0.10601 installed.
Keep `plugin.json` and `pyproject.toml` versions consistent. BinDiff is installed
separately by the user; neither its executable nor Binary Ninja core belongs in the archive.

```console
python3 tools/build_binexport.py --package
cmake --build build/binexport --target binja_binexport_clrbhb_test
ctest --test-dir build/binexport -R binja_binexport_clrbhb --output-on-failure
```

`--sdk /path/to/binaryninja-api` can reuse a checkout of the exact SDK revision
documented in [the helper README](../native/binexport/README.md), with the pinned
submodules initialized. Build dependencies still need network access on the first
configure. The install step writes only into this checkout.

The helper archive is `dist/binexport-bn6-abi187-macos-arm64.zip`. Extract it into
an empty staging directory and check that it contains the helper under
`binja_windbg_mcp/native/`, the companion's MIT license, and all seven dependency
license texts. It must contain
no private profiles, credentials, analysis inputs, Binary Ninja core library,
BinDiff executable, build tree, or test output. Check the dylib architecture and
dynamic dependencies with `file` and `otool -L`; it must not depend on libraries
in the build checkout. Confirm export ABI 1 and core ABI 187, and retain a SHA-256
of the archive and extracted dylib with the source commit and tool versions.
`otool -l` must show the intended minimum OS (13.0 by default). Loading the helper
requires Binary Ninja core to be loaded by the host; a plain `ctypes.CDLL` call in
an unrelated Python process without that dependency is not a valid load test.

## Check the companion

```console
uv run --python 3.13 --with pytest --with ruff --with-requirements requirements.txt python -m pytest -q
uv run --python 3.13 --with ruff ruff check .
uv run --python 3.13 --with ruff ruff format --check .
npx markdownlint-cli2@0.23.2 README.md "docs/**/*.md" "native/**/*.md"
```

Review [validation scope](binja-windbg-mcp-validation.md) alongside these results.
Unit tests and an archive inspection do not replace the recorded Personal GUI and
debugger acceptance. A new runtime change requires relevant acceptance to be repeated;
documentation-only changes do not imply another live capture.

The plugin source can be distributed from a tagged commit. The optional helper
archive is a separate asset extracted into that checkout; restart Binary Ninja
before replacing a loaded helper. Choose a release tag and publish assets only
when publication is explicitly requested. Preparing these files does not publish them.

## 2026-09-12 readiness check

The native source baseline is merged commit `ce3a5db4ee430b4e2563f7905851abe4f29ba76a`
(plugin version 0.2.0). This pass prepares the helper and verifies delivery artifacts;
it leaves the optional CVE investigation tracked and creates no release or tag.

The [readiness manifest](release-readiness-20260912.json) records the checked archive
and dylib hashes, contents, dependencies, and tool versions. The isolated build
passed all 187 Python tests and the native CLRBHB regression. Ruff and documentation
checks passed. The archive contains the arm64 dylib, the companion MIT license,
and seven dependency licenses, with export ABI 1, core ABI 187, and minimum macOS
13.0. The initial build inherited macOS 26.0; the build script now sets the target
explicitly. The dependency list contains Binary Ninja core and system libraries,
with no checkout-specific library paths.

Validation ran on macOS 26.6.2 with CMake 4.4.3. The extracted helper loaded with
Binary Ninja core preloaded and returned the expected ABI values. This was an ABI
check, not a new GUI export capture, and macOS 13 runtime behavior was not tested.
The existing Personal captures remain the live behavior evidence. No release or
tag was created.
