# Binary Ninja–WinDbg MCP Companion

A focused companion to **Binary Ninja 6 native MCP**, targeting Personal on Apple Silicon
macOS and its Python 3.13 interpreter. Native MCP handles general inspection and editing.
This plugin adds PE identity/RVA coordinates, structured driver evidence, and optional
WinDbg following and focused actions. It uses the **official MCP Python SDK 2.1.1**.

The optional [binary similarity tools](docs/similarity.md) compare two open PE builds
using external BinDiff on Personal or native BinDiff/WARP on Ultimate, and return
agent-readable disassembly differences. Personal requires the optional export helper
and a user-installed BinDiff CLI; see the setup guide. Real Personal comparisons
passed, including lifecycle checks and live guarded WinDbg handoff on ARM64 fixtures.
Ultimate execution remains tentative because of cost and does not gate Personal delivery.
See [release preparation](docs/release.md) for building and checking the optional helper.

Driver analysis works without WinDbg. The companion reads Binary Ninja's structured IL
through its Python API; native MCP currently renders IL as text. It selects views by its
own binary IDs because native MCP's active view is shared across clients. The companion
does not proxy native MCP or control its settings, listener, or credentials.

## Installation

Version 0.2 requires Binary Ninja **6.0.10601 or later** with its **Python 3.13**
interpreter. Binary Ninja installs Python dependencies into its shared per-user package
directory. On macOS with the bundled interpreter this is
`~/Library/Application Support/Binary Ninja/python313/site-packages/`.
No Python path override or separate dependency directory is needed.

[Extension Manager installs dependencies automatically](https://docs.binary.ninja/guide/plugins.html#installing-prerequisites)
from the included `requirements.txt`. This repository is not yet published in the manager.
For a local checkout, put the repository (or a symlink named `binja-windbg-mcp`) in
Binary Ninja's per-user `plugins` directory, then restart Binary Ninja. Your symlink can
point directly to the checkout; no copy or pip command is required.

For these manual installs, the companion checks dependencies on startup and installs
missing packages through Binary Ninja's own Python module installer in a background task.
**WinDbg MCP > Status** reports progress or errors, and **Start** retries a failed install.
The installer uses Binary Ninja's configured interpreter, proxy, and package location.
**Stop** during installation prevents the listener from starting; the package installation
finishes. Once dependencies are available, the listener starts automatically. Updating a
bundled package requires one further restart so already imported modules use the new version.

All runtime versions are pinned in `requirements.txt`. The matching `requirements.lock`
adds hashes for reproducible development installs; Binary Ninja's installer accepts plain
package requirements rather than pip include/hash directives. Incompatible versions of
user-installed packages are reported before the companion requests installation. Bundled packages may
receive updates in the shared user directory; the application bundle is never modified.
Resolve shared-package conflicts in the Extension Manager or with the **Install python3
module** command-palette action, then restart. A Python 3.10 package directory from version 0.1 is not reused by 3.13.

The companion autostarts at `http://127.0.0.1:8766/mcp`. The **WinDbg MCP** menu provides
Start, Stop, Status, and Connection Information even when no binary is open. Start is
enabled when stopped or ready to retry a failure; Stop is enabled during startup or while
running. Both are disabled while shutdown finishes or a dependency update requires a
restart. Status and Connection Information remain available. Port collisions are visible startup
failures. Stop is asynchronous; Start works after Status reports stopped. Only `/mcp`
is served. Native Binary Ninja MCP is a separate server, normally on port `24642`.

Quitting Binary Ninja stops the listener and closes the local WinDbg pairing. Pending
UI/analysis work is cancelled, and late dependency-setup completion cannot restart the
listener. Shutdown allows up to three seconds for network cleanup before returning to
Binary Ninja's exit sequence. It does not end the debugger session or remove breakpoints.
Closing a binary view alone leaves the process-wide listener running.

First startup creates `binja-windbg-mcp/profiles.json` under Binary Ninja's user data
directory, with mode `0600` and a generated 32-byte bearer token encoded in hex. Configure
the host with `Authorization: Bearer <token>` for the companion. Connection Information
shows the credential file location, never its contents.

## Native MCP and migration from 0.1

Configure the MCP host with native Binary Ninja MCP, this companion, and optionally
[windbg-mcp](https://github.com/glslang/windbg-mcp). Each connection has its own endpoint
and credential configuration. The tested native surface and its limits are recorded in
[the native MCP test drive](docs/binja6-native-mcp-test-drive.md).

| Removed companion tools | Use native MCP instead |
|---|---|
| `get_code` | `bn_function_disassembly`, `bn_function_il`, `bn_function_decompile` |
| `function_info`, `function_cfg` | `bn_function_info`, `bn_function_basic_blocks` |
| `xrefs` | Native function and data reference tools, choosing the required direction |
| `search` | `bn_function_search`, `bn_symbol_list` |
| `set_comment` | `bn_comment_get`, `bn_comment_set` |
| `rename_symbol` | `bn_symbol_rename`; native variable renaming is also available |
| `apply_type` | Native type definition, function prototype, and data-variable tools; import missing type libraries explicitly in the UI |

These are workflow replacements, not argument-compatible aliases. Native function tools
use function-start address expressions in the selected native view. Native comments
replace existing text; read and combine it explicitly when appending. Native results for
code, IL, CFG, and references are formatted text. Driver analysis still uses structured
IL internally and does not parse native MCP's rendering.

Native `binaryView` handles cannot be used as companion `binary_id` values. Call each
server's listing tools and identify the intended file. Paths are descriptive metadata;
debugger mapping uses PE identity and RVA. Do not compute `SizeOfImage` from view span.

## Tools and profiles

The companion exposes 22 tools in six startup-configured groups:

| Group | Tools |
|---|---|
| `workspace` | `list_binaries`, `current_location`, `navigate`, `wait_for_analysis` |
| `driver` | `driver_entry`, `sink_imports`, `device_security`, `ioctl_map`, `driver_surface` |
| `evidence` | `add_evidence` |
| `pair` | `pair_windbg`, `windbg_pair_status`, `unpair_windbg` |
| `debug` | `set_breakpoint_here`, `run_to_here`, `compare_runtime_bytes` |
| `similarity` | `similarity_start`, `similarity_status`, `similarity_results`, `similarity_diff`, `similarity_cancel`, `similarity_close` |

All groups are enabled by default. `workspace` is always included; `debug` includes
`pair`. The retired `analysis` and `edit` groups fail with migration guidance. Existing
`groups: "all"` profiles need no changes; replace explicit `edit` with `evidence` and
remove `analysis`. Restart to apply group changes. The retained `wait_for_analysis`
waits on an explicit binary ID with cancellation and a deadline; native MCP provides
general analysis control on its shared active view.

Edit `profiles.json` locally while the companion is stopped:

```json
{
  "token": "<generated companion token>",
  "groups": "all",
  "windbg": {
    "debugger": {
      "url": "http://127.0.0.1:8765/mcp",
      "token": "<same WinDbg bearer credential used by the host>"
    }
  }
}
```

Remote HTTP requires a loopback tunnel. HTTPS verifies certificates. Profile URLs with
credentials, queries, or fragments are refused, and redirects are disabled. The native
Binary Ninja MCP connection is configured separately in the host.

The [live HEVD E2E test](docs/hevd-e2e.md) passed pairing, guarded actions, byte comparison
and cursor following on the Windows ARM64 VM. Static recovery now maps all 29 IOCTL cases
in that identified HEVD build, checked against its disassembly; the report records the
remaining traversal and runtime-coverage limits.

## Driver analysis and evidence

`list_binaries` returns open PE views with companion IDs, architecture, PE header
identity, current base, analysis state, and available original-file SHA-256. Timestamp
and `SizeOfImage` are matching metadata; they do not establish cryptographic identity.
Unrecoverable original bytes are reported with an unavailable hash. Addresses use padded
lowercase 64-bit hex; RVAs use unpadded lowercase hex.

Driver recovery accepts named WDM MajorFunction registrations, control-code comparisons
and resolved switches, including supported aliases. Unresolved KMDF registration and
unsupported flow remain explicit. For WDM routines registered exclusively for device
control, exact typed reads can be matched to the database's `DeviceIoControl` layout even
when BN renders another union member. This requires matching offsets, widths and base
type; mixed-major-function dispatches require additional path proof and are not reinterpreted.
It never automatically applies NT types. Use native
MCP or the UI to supply required types; relevant notifications invalidate cached captures.
The version 1 sink inventory is in `binja_windbg_mcp/analysis.py`. Import presence alone
does not establish reachability. IOCTL sizes stay null unless proven; conditional checks
remain separate evidence. Static device-security arguments are defaults, not runtime
access observations.

Traversal is optional for IOCTL maps and enabled by `driver_surface`: depth 2 and 128
functions by default, hard limits 8 and 1,024. Composite results retain partial sections.

`add_evidence` is the companion's only analysis edit. It appends an undoable
`[windbg-evidence]` comment with image coordinate, available file identity, debugger
session/profile, runtime address, context, timestamp, and note. Identity, image name, and
view generation are revalidated inside the edit. Tokens and kernel connection strings
must never be included. Native MCP supplies ordinary comments and all symbol/type edits.

## Direct WinDbg pairing

`pair_windbg(profile, session_id, binary_id)` requires explicit unpairing before replacement.
One outbound SDK task serializes polling with focused actions. Intervals are clamped to
200–5000 ms, at least one second while running. Transient failures retry after 1, 2, 4, 8,
then 10 seconds, independently of the polling interval. Successful reconnect validation
preserves this backoff; a successful location response or `target_running` resets it.
Queue latency counts. Authenticated polling can renew WinDbg leases and keep sessions alive.

Only changed stops in the paired module navigate. Repeated samples preserve manual
navigation; reconnect/rebase requires validation. Focused actions require the cursor in
the paired view and use worker-side coordinate guards. Ambiguous breakpoint/run-to
timeouts are reported without retry. Byte comparison reports current-view/runtime bytes,
incomplete reads, modification state, and relocations, without guessing why bytes differ.

Unpair closes the outbound connection and local work without ending the debugger session
or removing breakpoints. Pairings are never persisted. Authentication failures stop polling,
including errors wrapped by the SDK. When pairing stops, queued actions fail as unsent;
actions interrupted in flight report an uncertain outcome without retry.

## Verification

```console
uv run --no-project --python 3.13 --with pytest --with ruff --with-requirements requirements.txt python -m pytest tests
uv run --no-project --python 3.13 --with ruff ruff check .
uv run --no-project --python 3.13 --with ruff ruff format --check .
```

The official-SDK HTTP test binds a temporary loopback socket. Its tool golden is refreshed
only with `UPDATE_GOLDEN=1`. Runtime versions are pinned in both requirements files; the
development lock also verifies hashes. Pytest and Ruff are development tools, absent
from the runtime requirements. The commands above supply them in a `uv` environment;
a runtime-only `.venv` is not sufficient to run the suite. An existing Python 3.13
test environment with these tools and the pinned runtime dependencies also works.
The HTTP tests require permission to bind temporary loopback sockets.
[Validation results and scope](docs/binja-windbg-mcp-validation.md) distinguish
Python tests, the live native-server test drive, and companion UI/real-driver acceptance.
The identified HEVD and mountmgr builds pass static and live bridge acceptance. UI
lifecycle, paired shutdown, actual module replacement and connection failures were
exercised against the installed application and Windows VM.

The [implementation plan](docs/binja-windbg-mcp-plan.md) records completed acceptance
and remaining scope. Structured WinDbg dispatch reachability completed windbg-mcp
item 60 on 2026-09-10; coverage import and report export remain deferred.

The [complete mountmgr acceptance](docs/mountmgr-e2e.md) records 24 recognized IOCTL codes,
93 host/silo case records, standard-user runtime access, guarded live actions, real module
replacement, reconnect/authentication faults, cancellation and paired GUI shutdown.
