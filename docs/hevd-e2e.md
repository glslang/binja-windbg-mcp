# HEVD bridge end-to-end test

The real Binary Ninja GUI and the Windows WinDbg MCP service passed a live HEVD bridge
run on 2026-09-06. The trigger opened and closed the device with desired access zero.
It sent **no IOCTLs**. This verifies bridge operation and a narrow runtime access
observation; it does not establish complete driver analysis or access for ordinary users.

## Identified build and environment

| Item | Value |
|---|---|
| Binary Ninja | 6.0.10601 Personal, Apple Silicon, bundled Python 3.13.14 |
| MCP Python SDK | Official `mcp==2.1.1`, server and clients |
| Debugger host | Windows ARM64 Parallels VM; existing WinDbg MCP service updated with the guarded-coordinate release build |
| Debuggee | Windows build 26100.1 ARM64, existing serial kernel-debug profile |
| HEVD SHA-256 | `8cd7546a42fe11308e512e54282c0d8b60f8c8774ec8823c5550ba5e53ac706e` |
| PE identity | Timestamp `1734099220`, `SizeOfImage` `585728` |
| PDB identity | GUID `A75E3B9A77BD44C4A5C5E8F7F563A002`, age `1` |
| PDB SHA-256 | `6966ad0a8d01ee95a959de5ba6f05fcc7e3bb9006c4035334bc4e473dbb90961` |
| Static / runtime base | `0x0000000140000000` / `0xfffff800843e0000` |

The original driver and PDB came from the installed debuggee build. The debugger read
the PDB through an existing Parallels shared folder. Both clients used the same WinDbg
bearer credential over an SSH loopback tunnel. Credentials stayed outside test reports,
source control and Binary Ninja metadata. A separate Binary Ninja GUI instance loaded
the installed companion checkout; this was not a headless emulation.

## Observed results

| Check | Result |
|---|---|
| Pairing | Matching HEVD identity accepted; all three guarded focused actions enabled |
| Wrong identity | Memory, breakpoint and run-to calls refused the changed timestamp; breakpoint list unchanged |
| Byte comparison | All 32 bytes at RVA `0x87078` equal, complete reads, unmodified current BinaryView, no overlapping relocations |
| Breakpoint | Companion installed a breakpoint at runtime `HEVD+0x87078`; the benign open hit it |
| Following | Debugger stop navigated Binary Ninja to static `HEVD+0x87078` |
| Manual navigation | Cursor moved to `0x870a4`; identical polls preserved it after 1.5 seconds |
| Run-to | Companion resumed to the actual selected IL instruction at `0x87098`; debugger location matched |
| Cleanup | Temporary breakpoint removed, original breakpoint list restored, pairing closed, session released and device open/close completed successfully |

The UI request for `0x8709c` selected an IL line mapped to `0x87098`. The test reads the
actual cursor before invoking `run_to_here`; focused actions operate on that cursor.
Initial debugger reads of the driver code were unavailable before the benign open made
the routine resident. Subsequent comparison was complete. Running-target refusals were
also observed while an asynchronous run was active.

The live test exposed a macOS UI issue: `UIContext.activeContext()` can be absent when
Binary Ninja is in the background. The companion now uses the selected tab of the sole
UI window in that case. Multiple inactive windows remain ambiguous and are refused.
A regression test covers both cases; the fixed code passed the live run.

Selected structured outcomes are preserved in [hevd-e2e-results.json](hevd-e2e-results.json).
The full local runner report also records each request, response and elapsed time.

## Static analysis and IOCTL recovery

The real adapter capture contains 108 functions. It recovered WDM major functions
`0` and `2` at `0x87078`, and `14` at `0x870a8`, five sink imports, device characteristics
`0x100`, and bounded dispatch-to-sink paths. The default traversal visited 57 functions
and reported its depth boundary explicitly.

The initial IOCTL recovery returned no proven cases and an unresolved switch at `0x87654`.
Binary Ninja rendered the input through `Parameters.Create` and an unnamed offset,
so the adapter could not establish the required `DeviceIoControl.IoControlCode` input.
The [real partial capture](../tests/fixtures/hevd-arm64-bn6-partial.json) and offline replay
assert that limitation alongside the successful independent sections. An empty map is
not evidence that this driver has no IOCTLs. The fix below resolves this build's case mapping;
the earlier partial capture remains immutable as a historical regression fixture.

The device opened successfully as the Parallels guest-exec account, SYSTEM, with desired
access zero. That observation does not establish an unprivileged user's effective rights.
No complete security-descriptor comparison, module unload/replacement, reconnect race,
rebase, evidence undo, or mountmgr workflow was exercised in this run.

## IOCTL recovery fix

A subsequent read-only Binary Ninja run recovered **29 cases**, `0x00222003` through
`0x00222073` in steps of four. The ordinary `ioctl_map` returned `success` with no
unresolved cases, through both the adapter and the authenticated MCP server. All case
addresses matched a separate check of the ARM64 comparison branches and their equality
edges, including comparisons reconstructed by BN as a switch. The reference uses this
binary's disassembly, not a published HEVD table or adapter-generated expectations.

The input is a four-byte read at `_IO_STACK_LOCATION + 0x18` in this build. Its database
layout places `Parameters` at `0x8` and `DeviceIoControl.IoControlCode` another `0x10`
bytes inside it. The adapter now checks those actual offsets and widths against the
read's base type. No hardcoded structure offset, rendered variable name or IOCTL constant
is used to establish input identity. No type is imported or applied automatically.

Union reinterpretation is restricted to callbacks registered exclusively for
`IRP_MJ_DEVICE_CONTROL` or `IRP_MJ_INTERNAL_DEVICE_CONTROL`. Callbacks also registered for
other major functions remain conservative until their paths can be distinguished.
Ambiguous unions, missing/malformed layouts, wrong widths/base types and reassigned input
aliases remain refused. Known member indices are respected instead of selecting the
first overlapping union field.

The [successful capture](../tests/fixtures/hevd-arm64-bn6-ioctls.json) pins the same
original-file hash, architecture, PE/PDB identity and BN analysis version, with independent
branch evidence for each expected code/case pair. A separate
[typed-input capture](../tests/fixtures/inputs/hevd-ioctl-input.json) exercises the adapter's
layout resolver offline. The original unresolved capture is retained. The suite has
**70 passing tests**, including both captures, real input replay, pointer-width differences,
missing layouts, mixed-major-function callbacks and ambiguous union selection.

[Structured MCP results](hevd-ioctl-recovery-results.json) preserve the recovered map.
All input/output sizes remain `null`, since no exact size was proved. The composite
`driver_surface` still reports its intentional traversal depth boundary. Driver bytes and
database types were unchanged. These are static mappings; no IOCTLs were executed, and
the fix does not establish runtime coverage or general recovery for every driver/build.

## Repeat the live check

This is an explicitly invoked macOS/Parallels test. Ordinary `pytest` only replays the
immutable capture and mocks; it never attaches a debugger or runs the guest trigger.

1. Install the companion and its pinned dependencies. Open this exact HEVD build in
   Binary Ninja with its matching PDB, allow analysis to finish and select the PE view.
   Configure a named WinDbg profile in the companion and connect through loopback HTTP
   or verified HTTPS. Use the same WinDbg credential for the host and companion.
2. Create a **disposable** kernel session through `attach_kernel(profile=...)`. Refresh
   the module inventory once, then load HEVD's symbols from a debugger-accessible path.
   Confirm matching PE identity and a complete 32-byte read at `HEVD+0x87078`.
   If the code is not resident, run `hevd_open.ps1` once while the target is running, then
   stop it through the execution handle. Inspect the create/close routine before doing so.
3. Pair the companion with that session and explicit binary ID using `pair_windbg`.
   Save each listener's connection as private local JSON containing `url` and `token`.
   These files are host configuration, not tool arguments or committed fixtures.
4. Run the harness below with those handles. **It removes its breakpoint, unpairs, and
   ends the supplied debugger session on exit**, including assertion failure. It never
   retries an uncertain mutation. Avoid using a session shared with another investigation.

```sh
python tools/hevd_e2e.py \
  --bn-connection /private/path/bn.json \
  --windbg-connection /private/path/windbg.json \
  --session-id '<disposable session ID>' \
  --binary-id '<companion binary ID>' \
  --debuggee-vm '<Parallels debuggee name>' \
  --output /tmp/hevd-e2e-results
```

Use Python 3.13 with the pinned requirements; do not pass `-O`, which disables assertions.
The runner checks the fixture hash and identity before installing a breakpoint.
[hevd_open.ps1](../tools/hevd_open.ps1) uses `CreateFileW` and `CloseHandle` only, with no
`DeviceIoControl`, buffer writes or exploitation. The runtime trigger is intentionally
narrow; extending it requires reviewing the actual build's dispatch first.
