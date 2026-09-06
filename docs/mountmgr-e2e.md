# Mountmgr static and live acceptance

Verified on 2026-09-06 with Binary Ninja **6.0.10601 Personal**, its bundled Python
**3.13.14**, the official `mcp==2.1.1` SDK, and the Windows ARM64 WinDbg MCP service.
The complete fixture covers this identified build. The older WinDbg walkthrough is
an abbreviated analysis of a different build; its addresses are not this fixture.

## Build and prerequisites

| Property | Value |
|---|---|
| File version | `10.0.26100.1 (WinBuild.160101.0800)` |
| Architecture | ARM64 / `aarch64` |
| Original file size | 117,120 bytes |
| Original SHA-256 | `734b4a45381ca6850d827f895e86e50ad03a882689483510402d96757fe15497` |
| PE timestamp | `2826447139` |
| PE SizeOfImage | `135168` (`0x21000`) |
| PDB GUID / age | `93E8BD6D2EF58D8BB5E56FEC14491E6A` / `1` |
| PDB SHA-256 | `3c920ba1ba4285aada5b524f543812b37d8dd3def1c27ca30c22f3636849eceb` |
| Static image base | `0x0000000140000000` |
| Observed runtime base | `0xfffff800822a0000` |

The original file came from the test guest and the matching PDB from Microsoft's public
symbol server. Neither binary nor PDB is distributed here. The public PDB supplied
function names but lacked the required NT structures. Available ARM64 NT types from the
identified HEVD PDB were explicitly imported into this test database; required offsets
were checked against the live kernel's types. Native MCP applied the entry/dispatch
prototypes and the current IRP-stack pointer type. The fixture records that provider,
architecture, layouts and explicit setup. Analysis tools do not apply these edits.

The original file was hashed independently. After saving a BNDB, this adapter cannot
reliably recover original bytes and correctly returns `file_sha256: null`; the fixture
keeps both facts. A current-view runtime byte comparison still works on that BNDB.

## Complete dispatch fixture

The real adapter capture contains 184 functions. The live driver object independently
confirmed major functions 0 and 2 at RVA `0x188a0`, device control (14) at `0x18910`,
shutdown (16) at `0x10ad0`, and cleanup (18) at `0x1030`.

The ordinary IOCTL map succeeds with **93 code/site records and no unresolved entries**:
48 host/silo routes for **24 recognized codes**, plus **45 explicit table slots leading
to default rejection**. Those default slots are not supported IOCTLs. Multiple sites
for one code remain separate. All recognized codes use `METHOD_BUFFERED`; access bits
are decoded from each numeric code. Input and output exact sizes remain `null`.

The independent routing interpreter enumerated all 65,536 values in the `0x006d`
device-type domain for both host and silo paths. It uses original instructions and raw
table bytes, independently of the adapter's IL case recovery. The fixture retains three
jump tables: two signed 32-bit tables and one signed 8-bit table. Every expected
`(code, dispatch_rva, case_rva)` record matches both offline analysis and authenticated MCP.
This establishes dispatch selection for this input domain, not arbitrary runtime coverage.

| Code | Host case name | Required access | Case RVA |
|---|---|---|---|
| `0x006d0008` | QUERY_POINTS | any | `0x18ab0` |
| `0x006d0030` | QUERY_DOS_VOLUME_PATH | any | `0x18b80` |
| `0x006d0034` | QUERY_DOS_VOLUME_PATHS | any | `0x18ba8` |
| `0x006d003c` | QUERY_AUTO_MOUNT | any | `0x18eb4` |
| `0x006d4008` | QUERY_POINTS_ADMIN | read | `0x18f04` |
| `0x006d4020` | CHANGE_NOTIFY | read | `0x18eec` |
| `0x006d4028` | CHECK_UNPROCESSED_VOLUMES | read | `0x189b0` |
| `0x006d402c` | VOLUME_ARRIVAL_NOTIFICATION | read | `0x18f10` |
| `0x006d4048` | TRACELOG_CACHE | read | `0x18f9c` |
| `0x006d4058` | VOLUME_REMOVAL_NOTIFICATION | read | `0x18f6c` |
| `0x006dc000` | CREATE_POINT | read + write | `0x18fb0` |
| `0x006dc004` | DELETE_POINTS | read + write | `0x19000` |
| `0x006dc00c` | DELETE_POINTS_DBONLY | read + write | `0x18fe8` |
| `0x006dc010` | NEXT_DRIVE_LETTER | read + write | `0x19018` |
| `0x006dc014` | AUTO_DL_ASSIGNMENTS | read + write | `0x190a4` |
| `0x006dc018` | VOLUME_MOUNT_POINT_CREATED | read + write | `0x19078` |
| `0x006dc01c` | VOLUME_MOUNT_POINT_DELETED | read + write | `0x190c8` |
| `0x006dc024` | KEEP_LINKS_WHEN_OFFLINE | read + write | `0x19128` |
| `0x006dc038` | SCRUB_REGISTRY | read + write | `0x19114` |
| `0x006dc040` | SET_AUTO_MOUNT | read + write | `0x19140` |
| `0x006dc044` | BOOT_DL_ASSIGNMENT | read + write | `0x19178` |
| `0x006dc04c` | PREPARE_VOLUME_REMOVAL | read + write | `0x19190` |
| `0x006dc050` | PREPARE_VOLUME_REMOVAL | read + write | `0x19190` |
| `0x006dc054` | SILO_ARRIVAL | read + write | `0x191a8` |

The case RVA is the first source-mapped statement. ARM64 address-materialization
instructions can precede it. Both preparation codes deliberately retain the same case
site. Silo-specific status paths and default slots are preserved in the
[complete fixture](../tests/fixtures/mountmgr-arm64-bn6.json).

This fixture exposed three generic destination errors: a goto's branch address was used
instead of its label, an empty equality branch's fallthrough was missed, and a synthetic
block address displaced its first statement. Recovery now follows bounded structured
edges, retains branch evidence, and reports unavailable destinations explicitly. Real
branch shapes are replayed offline in addition to focused synthetic tests.

`driver_surface` preserves successful entry/import sections and partial security/traversal
sections. The default traversal visits 74 functions at depth 2, within its 128-function
limit, and explicitly reports truncation. That bound does not invalidate the ordinary map.

## Static security and independent runtime access

Static evidence identifies `IoCreateDevice` at RVAs `0x189c` and `0x1c0d4`, device type
`0x12`, extension size `0x178`, and characteristics `0x100`. The adapter did not recover
an SDDL, class GUID or symbolic-link literal and keeps that section partial.

WinDbg independently resolved `\GLOBAL??\MountPointManager` to
`\Device\MountPointManager` and read its live security descriptor. Its four allow ACEs
match the DACL obtained through a handle:
`D:(A;;FX;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FX;;;RC)`.
This is an observed runtime configuration, not an inferred static default.

A temporary local account in Users, with a verified non-administrator token, was tested
alongside SYSTEM. The probe deleted that account in `finally`; cleanup confirmed none
remained. Opens used the DOS device name and sharing mode read/write.

| Operation | SYSTEM | Standard user |
|---|---|---|
| Mountmgr open with desired access 0 | succeeds | succeeds |
| Mountmgr `FILE_READ_ATTRIBUTES` or `READ_CONTROL` open | succeeds | succeeds |
| Mountmgr generic read, write, or read/write open | succeeds | access denied (5) |
| `QUERY_AUTO_MOUNT` (`0x006d003c`) on a zero-access handle | succeeds, 4 bytes | succeeds, 4 bytes |
| `QUERY_POINTS_ADMIN` (`0x006d4008`) on that handle | access denied (5) | access denied (5) |
| HEVD opens at all six tested access masks | succeeds | succeeds |

Only the two verified mountmgr query codes were submitted. HEVD received no IOCTLs.
The standard-user HEVD observation extends the earlier SYSTEM-only open/close test for
SHA-256 `8cd7546a42fe11308e512e54282c0d8b60f8c8774ec8823c5550ba5e53ac706e`.
Its observed DACL is recorded separately in [runtime access results](mountmgr-runtime-access.json).
These observations neither certify buffer handling nor establish a vulnerability.

## Live bridge and lifecycle

The identified mountmgr build passed a 32-byte equal comparison, companion breakpoint
installation and hit at query-case RVA `0x18eb4`, stop following, preservation of manual
navigation, and companion run-to at RVA `0x18ec4`. The read-only query completed with
four output bytes. The test removed its breakpoint and left no session behind.

Additional real GUI/VM checks passed:

- Native MCP symbol and type edits invalidate cached analysis; evidence append is undone
  through the registered Undo action, restoring the previous comment.
- Start is disabled while listening; Stop disables both actions while stopping. A stopped
  listener refuses connections and can restart through the actual menu action.
- Cancelling an SDK request during real busy analysis removes its completion subscription;
  a subsequent wait completes successfully.
- Rebasing to `0x150000000` preserves PE identity and RVA, revalidates pairing and still
  compares equal bytes. Delayed samples across rebase trigger validation before another poll.
- Closing the paired tab removes its binary ID, discards a delayed sample and refuses
  focused actions. Reopening the saved database produces a new ID and its original base.
- A loopback fault proxy forwarding actual WinDbg MCP traffic verifies reconnect validation,
  stale-response discard after unpair, terminal HTTP authentication failure, and an ambiguous
  breakpoint timeout. The breakpoint request reached WinDbg exactly once and was not retried.
- A disposable user-mode loader actually unloads one `bridge_fixture.dll` build and loads
  another at the **same base**, with different timestamp metadata. All three companion
  focused actions refuse the old identity; breakpoint inventory and IP remain unchanged.
  This tests module replacement without unloading either kernel driver.
- Normal Qt quit while paired stops the listener thread and outbound client. The debugger
  session remains usable afterward; the test then explicitly ends it and resumes the guest.

Two transport issues surfaced only in live testing. SDK 2.1.1's JSON-only response path
leaves abandoned requests running, so the listener uses its cancellable Streamable HTTP
response mode. This may stream a response on `/mcp`; it adds no legacy `/sse` endpoint.
The SDK also normalizes HTTP 401/403 into a generic MCP error, so an HTTP response hook
preserves those statuses for terminal pairing handling. Real HTTP regressions cover both.

One temporary test probe passed an invalid object to a native UI binding and crashed the
owned GUI. The crash trace identifies that probe call. The test restarted from the saved
BNDB and completed close/rebase/shutdown through valid registered actions. No probe ships
with the plugin; the temporary plugin was removed after testing.

Selected outcomes are in [live results](mountmgr-live-results.json) and the
[authenticated IOCTL map](mountmgr-ioctl-recovery-results.json). The complete Python suite
passes **88 tests**, including real fixture and branch-shape replay, official-SDK transport,
authentication and cancellation regressions. Ruff formatting/lint and Markdown lint pass.
No Rust source changed; the recorded Windows unit, protocol, debugger smoke, cross-target
lint and result-budget results remain applicable.

## Reproduce

With the exact original binary available locally, verify all recorded routing expectations:

```console
python tools/mountmgr_reference.py --binary /path/to/mountmgr.sys --output /tmp/mountmgr-routing.json
python -m pytest tests
```

The [access probe](../tools/driver_access_probe.ps1) is opt-in for an elevated disposable
Windows debuggee. It checks the original mountmgr hash before sending either read-only
query, creates one temporary standard user, and removes it on exit. It does not install
or start HEVD; that identified test driver must already be present for the HEVD checks.
Parallels shared folders can expose the script directly; their share names differ by VM.

Live acceptance used temporary GUI/proxy instrumentation, explicit debugger sessions and
locally stored credentials. Pairings and credentials are not in the fixtures. Broader
builds, silo runtime execution and other Windows configurations require their own evidence.
