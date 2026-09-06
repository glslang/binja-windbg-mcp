"""Live opt-in test for the pinned ARM64 HEVD fixture; see docs/hevd-e2e.md."""

import argparse
import asyncio
import base64
import copy
import json
import subprocess
import time
from contextlib import AsyncExitStack
from pathlib import Path

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

parser = argparse.ArgumentParser(
    description="Opt-in live HEVD bridge test; ends the supplied session."
)
parser.add_argument(
    "--bn-connection", type=Path, required=True, help="Private JSON containing url and token"
)
parser.add_argument(
    "--windbg-connection", type=Path, required=True, help="Private JSON containing url and token"
)
parser.add_argument(
    "--session-id", required=True, help="Disposable attached kernel session; ended on exit"
)
parser.add_argument("--binary-id", required=True)
parser.add_argument("--debuggee-vm", required=True, help="Parallels VM with this HEVD build loaded")
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = args.output
root.mkdir(parents=True, exist_ok=True)
sid, bid = args.session_id, args.binary_id
coord = {
    "module": "HEVD",
    "image_name": "HEVD.sys",
    "identity": {
        "timestamp": 1734099220,
        "size": 585728,
        "pdb": {"guid": "A75E3B9A77BD44C4A5C5E8F7F563A002", "age": 1},
    },
    "rva": "0x87078",
}


def ps(script, vm, timeout):
    command = base64.b64encode(script.encode("utf-16le")).decode()
    result = subprocess.run(
        ["prlctl", "exec", vm, "powershell.exe", "-NoProfile", "-EncodedCommand", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return result.stdout


records = []


async def main():
    async with AsyncExitStack() as stack:
        clients = {}
        for name in ["windbg", "bn"]:
            cfg = json.loads(
                (args.bn_connection if name == "bn" else args.windbg_connection).read_text()
            )
            http = await stack.enter_async_context(
                httpx2.AsyncClient(
                    headers={"Authorization": "Bearer " + cfg["token"]}, trust_env=False, timeout=60
                )
            )
            clients[name] = await stack.enter_async_context(
                Client(
                    streamable_http_client(cfg["url"], http_client=http), read_timeout_seconds=60
                )
            )

        async def call(server, name, args=None, require=True):
            args = dict(args or {})
            if server == "windbg":
                args["session_id"] = sid
            start = time.monotonic()
            r = await clients[server].call_tool(name, args)
            d = r.model_dump(mode="json", by_alias=True)
            records.append(
                {
                    "server": server,
                    "tool": name,
                    "arguments": args,
                    "elapsed_seconds": round(time.monotonic() - start, 3),
                    "result": d,
                }
            )
            (root / "runtime-results.json").write_text(json.dumps(records, indent=2))
            value = r.structured_content
            print(server, name, json.dumps(value or {"content": d["content"]})[:2200], flush=True)
            if require:
                assert not r.is_error, d
            return value or d

        async def nav(rva):
            await call("bn", "navigate", {"binary_id": bid, "coordinate": dict(coord, rva=rva)})

        async def stop(execution):
            await call("windbg", "break_in", {"execution": execution})
            return await call(
                "windbg", "wait_for_stop", {"execution": execution, "timeout_ms": 10000}
            )

        owned_bp = None
        pending_trigger = None
        execution = None
        pairing_matches = False
        try:
            binaries = await call("bn", "list_binaries")
            selected = next(b for b in binaries["binaries"] if b["binary_id"] == bid)
            assert (
                selected["file_sha256"]
                == "8cd7546a42fe11308e512e54282c0d8b60f8c8774ec8823c5550ba5e53ac706e"
            )
            assert selected["active"] and selected["identity"] == coord["identity"]
            pairing = await call("bn", "windbg_pair_status")
            pairing_matches = (
                pairing.get("paired")
                and pairing.get("session_id") == sid
                and pairing.get("binary_id") == bid
            )
            assert pairing_matches, "Pair the selected binary with this disposable session first"
            before = await call("windbg", "execute", {"command": "bl"})
            bad = copy.deepcopy(coord)
            bad["identity"]["timestamp"] ^= 1
            for name, parameters in [
                ("read_memory", {"size": 32}),
                ("set_breakpoint", {}),
                ("run_to_address", {"timeout_ms": 1000}),
            ]:
                outcome = await call(
                    "windbg", name, dict(parameters, coordinate=bad), require=False
                )
                assert (
                    outcome["status"] == "error"
                    and "identity" in outcome["error"]["message"].lower()
                ), outcome
            after = await call("windbg", "execute", {"command": "bl"})
            assert before["content"] == after["content"]
            await nav("0x87078")
            comparison = await call("bn", "compare_runtime_bytes")
            assert comparison["equal"] and not comparison["incomplete"]
            bp = await call("bn", "set_breakpoint_here")
            (root / "installed-bp.json").write_text(json.dumps(bp, indent=2))
            # The new tool has one typed breakpoint record.
            owned_bp = bp["breakpoint"]["id"] if "breakpoint" in bp else bp.get("id")
            assert owned_bp is not None, bp
            await nav("0x870a4")
            run = await call("windbg", "continue_async", {"max_run_ms": 30000})
            execution = run["execution"]
            pending_trigger = asyncio.create_task(
                asyncio.to_thread(
                    ps,
                    Path(__file__).with_name("hevd_open.ps1").read_text(),
                    vm=args.debuggee_vm,
                    timeout=60,
                )
            )
            await call("windbg", "wait_for_stop", {"execution": execution, "timeout_ms": 10000})
            loc = await call("windbg", "current_location")
            assert loc["coordinate"]["rva"] == "0x87078", loc
            deadline = time.monotonic() + 8
            while True:
                bnloc = await call("bn", "current_location", {"binary_id": bid})
                if bnloc.get("coordinate", {}).get("rva") == "0x87078":
                    break
                assert time.monotonic() < deadline, bnloc
                await asyncio.sleep(0.3)
            await nav("0x870a4")
            await asyncio.sleep(1.5)
            manual = await call("bn", "current_location", {"binary_id": bid})
            assert manual["coordinate"]["rva"] == "0x870a4", manual
            await call("windbg", "execute", {"command": f"bc {owned_bp}"})
            owned_bp = None
            await nav("0x8709c")
            cursor = await call("bn", "current_location", {"binary_id": bid})
            expected_rva = cursor["coordinate"]["rva"]
            assert expected_rva != "0x87078"
            reached = await call("bn", "run_to_here")
            assert reached["status"] == "ok", reached
            loc = await call("windbg", "current_location")
            assert loc["coordinate"]["rva"] == expected_rva, loc
            await call("bn", "unpair_windbg")
            finalrun = await call("windbg", "continue_async", {"max_run_ms": 30000})
            execution = finalrun["execution"]
            trigger = await pending_trigger
            pending_trigger = None
            (root / "runtime-open.json").write_text(trigger)
            assert json.loads(trigger)["Win32Error"] == 0
            await stop(execution)
            execution = None
            finalbp = await call("windbg", "execute", {"command": "bl"})
            assert finalbp["content"] == before["content"]
        finally:
            # Keep session release reachable even if the companion disconnects during cleanup.
            try:
                try:
                    if pairing_matches:
                        await call("bn", "unpair_windbg", require=False)
                finally:
                    if execution:
                        await stop(execution)
                    if owned_bp is not None:
                        await call(
                            "windbg", "execute", {"command": f"bc {owned_bp}"}, require=False
                        )
            finally:
                released = await call("windbg", "end_session")
                assert released["released"], released
                if pending_trigger:
                    await pending_trigger
        print("PASS: identity guards, bytes, breakpoint, following, manual cursor, run-to, cleanup")


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Run without -O; this test requires assertions")
    asyncio.run(main())
