# Binary Ninja–WinDbg MCP Bridge

A Python UI plugin for Binary Ninja 5.3 Personal on Apple Silicon macOS. It uses the
**official MCP Python SDK 2.1.1** for authenticated Streamable HTTP and the outbound
WinDbg client. The implementation is under active validation; see the acceptance status
below before relying on recovered driver mappings.

Workspace, static analysis, driver evidence, and editing work without a debugger. Pairing
and focused runtime actions optionally connect to the separate
[windbg-mcp server](https://github.com/glslang/windbg-mcp).

## Installation

Use a copy of this directory named `binja-windbg-mcp` in Binary Ninja's per-user plugins
directory. Install `requirements.lock` into a Python 3.10 package directory visible to
Binary Ninja's embedded interpreter. The lock contains exact versions and wheel hashes:

```console
python3.10 -m pip install --require-hashes -r requirements.lock --target /path/to/plugin-dependencies
```

Add that dependency directory to Binary Ninja's Python path before loading the plugin.
Do not use a Python 3.11+ wheel environment for the embedded 3.10 interpreter. Restart
Binary Ninja after installing dependencies. This repository does not install into or
modify the application bundle automatically.

The listener autostarts at `http://127.0.0.1:8766/mcp`. The **WinDbg MCP** menu provides
Start, Stop, Status, and Connection Information. Port collisions produce a visible failure.
Stop finishes asynchronously so active jobs can release the UI thread; Start works after
Status reports stopped. Only `/mcp` is served; no stdio or legacy `/sse` endpoint exists.

On first startup, the plugin creates `binja-windbg-mcp/profiles.json` under Binary Ninja's
user data directory. It has mode `0600` and contains a 32-byte random token encoded in hex.
Configure the MCP host with `Authorization: Bearer <token>` in its HTTP headers. Connection
Information shows the credential file location, never the token. Keep this file private.

## Profiles and groups

Edit `profiles.json` locally while the listener is stopped, then restart Binary Ninja:

```json
{
  "token": "<generated listener token>",
  "groups": "all",
  "windbg": {
    "debugger": {
      "url": "http://127.0.0.1:8765/mcp",
      "token": "<same WinDbg bearer credential used by the MCP host>"
    }
  }
}
```

Use an SSH tunnel for remote HTTP, or HTTPS with certificate verification. URLs with
embedded credentials, queries, or fragments are refused; redirects are disabled.
Groups are `workspace`, `analysis`, `driver`, `edit`, `pair`, and `debug`, selected by a
comma-separated string. All 24 tools are enabled by default; workspace is always included
and debug includes pair. Restart to apply group changes.

## Analysis and explicit edits

List binaries to obtain a process-lifetime ID. Calls select that ID rather than guessing
between duplicate views. PE identity comes from raw PE headers even after a rebase.
Addresses use padded lowercase 64-bit hex; RVAs use unpadded lowercase hex. Timestamp and
SizeOfImage are matching metadata, not cryptographic identity. Hashes are unavailable
when original bytes cannot be recovered reliably, including saved BNDB provenance that
cannot be established.

Code, CFG, xrefs, and symbol search are capped and report truncation. Driver recovery uses
structured HLIL with available named layouts; it never automatically applies NT types.
The sink inventory is version 1, defined in `binja_windbg_mcp/analysis.py`. Imports alone
prove neither reachability nor absence of equivalent or dynamically resolved code.

Dispatch recovery supports named WDM MajorFunction array assignments. IOCTL recovery
supports comparisons and resolved switches tied to the named control-code field, including
single-assignment aliases. Unsupported indirect flow and unresolved KMDF registration are
reported. Exact sizes remain null unless proven; minimum/conditional evidence is separate.
Traversal is optional for IOCTL maps and enabled by the composite driver surface: depth 2,
128 functions by default; hard limits 8 and 1,024. Static security arguments are defaults,
not effective runtime access. Probe observations are not vulnerability verdicts.

Comments append by default. Evidence uses an undoable `[windbg-evidence]` comment record
with explicit provenance. Function/data rename and named-type import/application are
undoable; local variables are deferred. Never place credentials or kernel connection
strings in comments or evidence notes.

## Pairing

Call `pair_windbg(profile, session_id, binary_id)`. Explicitly unpair before replacing it.
One outbound SDK task owns the connection and serializes polling with focused actions.
Polling intervals are clamped to 200–5000 ms, at least one second while running; transient
failures back off to ten seconds. Queue latency counts, so sub-second following is best effort. Authenticated polling can renew WinDbg leases/idle activity and keep sessions alive.

Only stops in the paired module navigate. Repeated identical samples preserve manual
navigation. Rebase/reconnect requires validation. The three focused actions require the
cursor in the paired view and use worker-side coordinate guards. Breakpoint and run-to
mutations are never retried after ambiguous timeouts. Byte comparison reports raw
current-view/runtime differences, incomplete reads, modification state, and relocation
ranges; it does not infer why bytes differ.

Unpair closes local work and the MCP connection. It does not end the debugger session or
remove breakpoints. Pairings are never persisted.

## Verification and acceptance status

Offline tests and an official-SDK HTTP interoperability test run without a Binary Ninja
license or debugger:

```console
python3.10 -m pytest tests
ruff check .
ruff format --check .
```

The HTTP test requires permission to bind a temporary loopback socket. Update its checked-in
tool golden only with `UPDATE_GOLDEN=1`. Runtime dependencies are hash-pinned; pytest and
ruff are development-only tools.

Verified against installed Binary Ninja **5.3.9757 Personal** API definitions and Python 3.10;
UI type signatures were inspected without running UI operations. Headless loading of the
UI module is deliberately refused by Binary Ninja. Actual UI lifecycle, analysis-completion,
undo/rebase behavior, and real HEVD/mountmgr analysis remain acceptance gates. Synthetic
fixtures are not substitutes for captured Binary Ninja output or runtime access observations.

Detailed automated results and open acceptance gates are in
[the validation record](docs/binja-windbg-mcp-validation.md).

The complete intended scope and remaining acceptance requirements are in
[the implementation plan](docs/binja-windbg-mcp-plan.md). Structured WinDbg dispatch
reachability is tracked separately as [windbg-mcp FOLLOWUPS.md](https://github.com/glslang/windbg-mcp/blob/main/FOLLOWUPS.md) item 60.
