import asyncio

import httpx2
import pytest
from mcp import Client
from mcp.server import MCPServer

from binja_windbg_mcp import pairing as module
from binja_windbg_mcp.pairing import Pairing

IDENTITY = {"timestamp": 123, "size": 4096}
COORDINATE = {"module": "driver", "image_name": "driver.sys", "identity": IDENTITY, "rva": "0x100"}


class Workspace:
    generation = ["binary", 0x1000, 0]
    navigations = []

    def current_location(self, binary_id):
        return {
            "binary_id": binary_id,
            "identity": IDENTITY,
            "coordinate": COORDINATE,
            "generation": list(self.generation),
        }

    def navigate(self, binary_id, coordinate, generation, still_valid=None):
        if still_valid and not still_valid():
            raise ValueError("closed")
        assert list(generation) == self.generation
        self.navigations.append(coordinate.rva)

    def byte_snapshot(self, binary_id, size):
        return {
            "coordinate": dict(COORDINATE),
            "generation": list(self.generation),
            "data": (b"\x90" * size).hex(),
            "modified": False,
            "relocations": [],
        }


class Profiles:
    def profile(self, name):
        return "http://127.0.0.1/mcp", "credential"


def test_pairing_serializes_follows_only_changes_and_never_retries_mutation(monkeypatch):
    server = MCPServer("windbg-test")
    sample = {
        "status": "ok",
        "location_state": "mapped",
        "address": "0x0000000000100100",
        "thread": 1,
        "processor": 0,
        "coordinate": COORDINATE,
    }
    mutations = []

    @server.tool(structured_output=True)
    async def modules(session_id: str, limit: int) -> dict[str, object]:
        return {
            "status": "ok",
            "modules": [{"name": "driver", "image_name": "driver.sys", **IDENTITY}],
        }

    @server.tool(structured_output=True)
    async def current_location(session_id: str) -> dict[str, object]:
        return sample

    @server.tool(structured_output=True)
    async def set_breakpoint(session_id: str, coordinate: dict[str, object]) -> dict[str, object]:
        mutations.append(coordinate)
        return {"status": "error", "error": {"category": "timeout"}}

    @server.tool(structured_output=True)
    async def read_memory(
        session_id: str, coordinate: dict[str, object], size: int
    ) -> dict[str, object]:
        return {
            "status": "ok",
            "data": (b"\x90" * size).hex(),
            "read_size": size,
            "requested_size": size,
        }

    monkeypatch.setattr(module, "Client", lambda *args, **kwargs: Client(server))
    workspace = Workspace()
    workspace.navigations = []

    async def check():
        pair = Pairing(workspace, Profiles())
        await pair.pair("debugger", "session", "binary", 200)
        try:
            await asyncio.sleep(0.55)
            assert workspace.navigations == ["0x100"]
            result = await pair.action("set_breakpoint_here")
            assert result["status"] == "uncertain"
            assert len(mutations) == 1
            assert mutations[0]["identity"] == IDENTITY
            assert (await pair.action("compare_runtime_bytes", 32))["equal"]
            sample["address"] = "0x0000000000100200"
            sample["coordinate"] = {**COORDINATE, "module": "nt"}
            await asyncio.sleep(0.25)
            assert workspace.navigations == ["0x100"]
            sample.update(status="error", error={"category": "target_running"})
            await asyncio.sleep(0.25)
            assert pair.state["state"] == "target_running"
            try:
                await pair.pair("debugger", "session", "binary")
            except ValueError:
                pass
            else:
                raise AssertionError("replacement should require unpair")
        finally:
            await pair.unpair()
        assert pair.state == {"paired": False}
        assert len(mutations) == 1

    asyncio.run(check())


def test_pair_validation_checks_image_name_without_an_active_cursor():
    server = MCPServer("windbg-test")
    module_row = {"name": "other", "image_name": "other.sys", **IDENTITY}

    @server.tool(structured_output=True)
    async def modules(session_id: str, limit: int) -> dict[str, object]:
        return {"status": "ok", "modules": [module_row]}

    @server.tool(structured_output=True)
    async def current_location(session_id: str) -> dict[str, object]:
        return {"status": "ok"}

    class InactiveWorkspace(Workspace):
        def current_location(self, binary_id):
            return {
                **super().current_location(binary_id),
                "coordinate": None,
                "image_name": "driver.sys",
            }

    async def check():
        pair = Pairing(InactiveWorkspace(), Profiles())
        pair.state = {"binary_id": "binary", "session_id": "session"}
        async with Client(server) as client:
            with pytest.raises(ValueError, match="image name mismatch"):
                await pair._validate(client)
            module_row.update(name="driver", image_name="driver.sys")
            await pair._validate(client)
            assert pair.module["name"] == "driver"

    asyncio.run(check())


@pytest.mark.parametrize(
    "failure", ["401", "403", "nested_401", "nested_403", "stale_session", "worker_lost", "invalid"]
)
def test_terminal_poll_failure_stops_and_refuses_queued_actions(monkeypatch, failure):
    server = MCPServer("windbg-test")
    connections, mutations = [], []

    @server.tool(structured_output=True)
    async def modules(session_id: str, limit: int) -> dict[str, object]:
        return {
            "status": "ok",
            "modules": [{"name": "driver", "image_name": "driver.sys", **IDENTITY}],
        }

    @server.tool(structured_output=True)
    async def current_location(session_id: str) -> dict[str, object]:
        return {"status": "ok"}

    @server.tool(structured_output=True)
    async def set_breakpoint(session_id: str, coordinate: dict[str, object]) -> dict[str, object]:
        mutations.append(coordinate)
        return {"status": "ok"}

    def connect(*args, **kwargs):
        connections.append(True)
        return Client(server)

    monkeypatch.setattr(module, "Client", connect)

    async def check():
        pair = Pairing(Workspace(), Profiles())
        polling, release = asyncio.Event(), asyncio.Event()
        original_call = pair._call
        actions = []

        async def call(client, tool, args):
            if tool != "current_location":
                return await original_call(client, tool, args)
            polling.set()
            await release.wait()
            if failure.endswith(("401", "403")):
                request = httpx2.Request("POST", "http://127.0.0.1/mcp")
                error = httpx2.HTTPStatusError(
                    "test authentication failure",
                    request=request,
                    response=httpx2.Response(int(failure[-3:]), request=request),
                )
                if failure.startswith("nested"):
                    raise ExceptionGroup("transport", [ExceptionGroup("request", [error])])
                raise error
            if failure == "invalid":
                raise ValueError("WinDbg structured contract unavailable")
            return {"status": "error", "error": {"category": failure}}

        monkeypatch.setattr(pair, "_call", call)
        await pair.pair("debugger", "session", "binary", 200)
        try:
            await asyncio.wait_for(polling.wait(), 2)
            actions = [asyncio.create_task(pair.action("set_breakpoint_here")) for _ in range(3)]
            await asyncio.sleep(0)
            assert pair.queue.qsize() == 3
            actions[-1].cancel()
            await asyncio.gather(actions[-1], return_exceptions=True)
            release.set()
            await asyncio.wait_for(asyncio.shield(pair.task), 2)
            results = await asyncio.wait_for(
                asyncio.gather(*actions[:-1], return_exceptions=True), 1
            )
            assert all(isinstance(result, ValueError) for result in results)
            assert all("before action was sent" in str(result) for result in results)
            assert pair.queue.empty()
            assert not mutations
            assert len(connections) == 1
            expected = (
                "authentication_failed"
                if failure.endswith(("401", "403"))
                else "validation_failed"
                if failure == "invalid"
                else failure
            )
            assert pair.state["state"] == expected
            with pytest.raises(ValueError, match="no active pairing"):
                await pair.action("set_breakpoint_here")
        finally:
            release.set()
            await pair.unpair()
            for action in actions:
                action.cancel()
            await asyncio.gather(*actions, return_exceptions=True)

    asyncio.run(check())


def test_unpair_resolves_inflight_and_queued_actions_without_retry(monkeypatch):
    server = MCPServer("windbg-test")
    mutations = []

    @server.tool(structured_output=True)
    async def modules(session_id: str, limit: int) -> dict[str, object]:
        return {
            "status": "ok",
            "modules": [{"name": "driver", "image_name": "driver.sys", **IDENTITY}],
        }

    @server.tool(structured_output=True)
    async def current_location(session_id: str) -> dict[str, object]:
        return {"status": "error", "error": {"category": "target_running"}}

    monkeypatch.setattr(module, "Client", lambda *args, **kwargs: Client(server))

    async def check():
        pair = Pairing(Workspace(), Profiles())
        entered = asyncio.Event()
        actions = []

        async def action(*args):
            mutations.append(True)
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(pair, "_action", action)
        await pair.pair("debugger", "session", "binary", 200)
        try:
            actions.append(asyncio.create_task(pair.action("set_breakpoint_here")))
            await asyncio.wait_for(entered.wait(), 2)
            actions.append(asyncio.create_task(pair.action("set_breakpoint_here")))
            await asyncio.sleep(0)
            assert pair.queue.qsize() == 1
            await asyncio.wait_for(pair.unpair(), 2)
            running, queued = await asyncio.wait_for(
                asyncio.gather(*actions, return_exceptions=True), 1
            )
            assert running["status"] == "uncertain"
            assert isinstance(queued, ValueError)
            assert "before action was sent" in str(queued)
            assert len(mutations) == 1
            assert pair.queue.empty()
            assert (await pair.unpair()) == {"paired": False}
        finally:
            await pair.unpair()
            for pending in actions:
                pending.cancel()
            await asyncio.gather(*actions, return_exceptions=True)

    asyncio.run(check())
