import asyncio

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
