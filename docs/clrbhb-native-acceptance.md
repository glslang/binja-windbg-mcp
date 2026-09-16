# CLRBHB native acceptance — 2026-09-15

The companion now maintains a pinned replacement ARM64 architecture plugin for
Binary Ninja 6.0.10601 Personal on Apple Silicon. It closes windbg-mcp follow-up 63
locally; upstream submission is the next step.

## Delivered

- [Native patch and runbook](../native/arm64/README.md): decode `D50322DF` as
  `clrbhb` and emit the `SystemHintOp_CLRBHB` intrinsic.
- [Builder and installer](../tools/build_arm64.py): exact SDK revision and archive
  hashes, packaged licenses, explicit profile selection, ownership-checked removal
  and restoration of the previous bundled-plugin setting.
- [GUI capture](../tools/capture_arm64.py): disposable profile, native loaded-image
  verification, function/IL checks, complete external comparison and real child-exit
  evidence. The normal profile and app bundle were unchanged.

The generated package is `dist/arm64-clrbhb-bn6-abi187-macos-arm64.zip`, built from
SDK revision `2ddf304b3275aa184e95570404539cbc4beb64c6`, ABI 187. Its native library
SHA-256 is `fe26ff7a60a2d6da8c9e569c64c28a8759c673be90bff59c72db328ba2c684be`.
Generated binaries stay out of source control.

## Measured result

The [summary](samples/clrbhb-native-acceptance-20260915.json) includes all sixteen
endpoints and eight complete function diffs. The [compressed full capture](samples/clrbhb-native-acceptance-20260915.json.gz)
also retains every match and unmatched row. Only temporary directory prefixes are
redacted; input and source hashes remain intact.

| Check | Result |
|---|---|
| Native plugin | Only the user-profile ARM64 library loaded; bundled architecture disabled |
| Synthetic `CLRBHB; ADD; RET` | Three instructions, 12-byte function, named CLRBHB intrinsic |
| Secure Kernel endpoints | 16/16 decode; each function has three instructions and a 12-byte block |
| External comparison | Completed; 3,101 matches; 3 reference and 26 target unmatched |
| Coverage | 3,104 reference / 3,127 target functions; zero omitted or unresolved results |
| Affected diffs | All eight retained with three rows each; no instruction-text truncation |
| Preservation | Input hashes, mapped bytes, function/type/comment hashes and generations unchanged |
| Process exit | Exit 0; no forced termination or new crash reports |
| Companion tests | 197 passed, including ten new package tests |
| Stable native C regression | CLRBHB, NOP and CSDB passed |

The full Python suite needs localhost sockets for its transport tests. The initial
restricted run passed 191 tests and hit six socket-permission failures; rerunning
with localhost access passed all 197.

## Scope and upstream handoff

The supported replacement is pinned to this SDK and macOS ARM64. It provides native
text and IL without changing the companion API or removing the older-build export
fallback. Use fresh or reanalyzed databases when switching architecture providers.
Ultimate is unnecessary for this external acceptance.

The [upstream PR draft](../native/arm64/UPSTREAM_PR.md) describes the fix and test
evidence. The patch includes upstream-format disassembly and LLIL cases. Those
cases match the GUI observations; the entire upstream architecture suite was not
run against this package. Earlier standalone development-source testing found
42,639 corpus entries unchanged and the same pre-existing MSR formatting failure
in both baseline and patched trees; that is not a green upstream-suite claim.

This acceptance does not settle CVE attribution, require Ultimate access, or fix
Vector35's FirstSetupDialog crash.

## Installer and rebuild review checks

The PR review follow-up adds host/process architecture rejection before profile
changes and publishes a verified temporary library with an atomic rename. Tests
exercise partial copies, copy corruption, and failures before publication and
while saving settings; recovery never requires removing an unverified plugin.

Builds now revalidate the source archives and extract fresh SDK/fmt sources and
CMake outputs on every invocation. Tests verify that an altered legacy source
tree and matching marker are ignored, repeated builds use fresh directories, and
a tampered cached archive is rejected before compilation.

After these changes, **207 tests passed**, including twenty package tests. Ruff,
formatting and documentation lint passed. A fresh native build from the pinned
archives succeeded, and the rebuilt package installed and uninstalled in a
temporary profile with the original settings restored byte for byte. The earlier
GUI/native-analysis capture above remains the evidence for the unchanged decoder
patch; this follow-up changes its build and installation tooling.

## Endpoint pairing and probe snapshot review checks

Acceptance now requires each target endpoint to match its corresponding reference
RVA exactly once. Unrelated reference functions, swapped pairs, missing endpoints
and duplicates fail before diff acceptance. The delayed GUI import uses the saved
`sources` directory, and the recorded hashes are calculated from the same bytes
written there. Regression tests edit or remove the live checkout before executing
the generated bootstrap and confirm the retained probe still runs.

All **215 tests passed**, including eight capture regressions; Ruff, formatting
and documentation lint passed. A fresh disposable GUI run passed all eight exact
endpoint pairs and complete diffs with unchanged input and analysis state, followed
by normal GUI exit. Its capture and hashed source snapshots remain local. The
previously retained capture also passes the stricter pair check.

## macOS minimum and complete endpoint checks — 2026-09-16

After rebasing onto main's MCP 2.2.0 dependency pins, installation and building
reject macOS releases below 13.0 or an unreadable version. The host check, CMake
deployment target and package manifest share the same minimum-version constant.
Tests verify refusal leaves absent and existing profiles unchanged, and that 13.0
and newer releases can install and remove the package.

Endpoint acceptance now requires exactly three four-byte instructions at the
entry, entry + 4 and entry + 8, with one block covering exactly twelve bytes and
the CLRBHB intrinsic present. Missing final branches, malformed instruction
lengths/addresses, extra instructions/blocks and shortened bounds are rejected.
All sixteen endpoints in the retained capture pass the stricter check.

The full suite passed **239 tests** with the current pinned requirements. Ruff,
formatting, requirement/lock consistency and the complete documentation lint
passed. The native decoder patch is unchanged; no new capture was published.

## Executable, companion snapshot and diff-row checks — 2026-09-16

Compatibility now uses macOS `lipo -verify_arch arm64` on the selected app's
executable before changing a profile. The capture saves and hashes the companion
Python modules and native BinExport helper alongside the probe. Delayed-import
regressions use the real companion modules after editing or removing the copied
checkout, and verify the saved helper and all recorded source hashes.

Each endpoint diff must have three complete rows pairing the expected reference
and target instruction RVAs. Missing sides, wrong or duplicated RVAs, blank or
truncated text, and truncated function output fail acceptance. The retained
capture satisfies this stricter check.

A new local GUI run passed with all fifteen companion file hashes verified and
all eight three-row diffs complete, then exited normally. Its disposable plugin
was removed. The capture remains local. The full suite passed **252 tests**;
an initial concurrent run had one external-process fixture timeout and cleanup
failure, and the suite passed on rerun after GUI exit. Ruff, formatting and
changed-documentation lint passed.
