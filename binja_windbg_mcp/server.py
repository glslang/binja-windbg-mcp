"""Official MCP v2 Streamable HTTP server and its loopback lifecycle."""

from __future__ import annotations

import asyncio
import hmac
import socket
import threading
from datetime import datetime, timezone

import uvicorn
from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from .core import Budget, Coordinate
from .pairing import Pairing

GROUPS = {
    "workspace": ("list_binaries", "current_location", "navigate", "wait_for_analysis"),
    "driver": ("driver_entry", "sink_imports", "device_security", "ioctl_map", "driver_surface"),
    "evidence": ("add_evidence",),
    "pair": ("pair_windbg", "windbg_pair_status", "unpair_windbg"),
    "debug": ("set_breakpoint_here", "run_to_here", "compare_runtime_bytes"),
}


def selected_tools(spec):
    groups = set(GROUPS) if spec == "all" else {group.strip() for group in spec.split(",")}
    if groups & {"analysis", "edit"}:
        raise ValueError("analysis/edit groups were retired; use native MCP and the evidence group")
    if groups - GROUPS.keys():
        raise ValueError("unknown tool group")
    groups.add("workspace")
    if "debug" in groups:
        groups.add("pair")
    return {tool for group in groups for tool in GROUPS[group]}


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(max_length=256)
    profile: str = Field(max_length=256)
    runtime_address: str = Field(pattern=r"^0x[0-9a-f]{16}$")
    thread: int | None = None
    processor: int | None = None
    note: str = Field(max_length=8192)


def make_server(workspace, profiles):
    server = MCPServer(
        "binja-windbg-mcp",
        version="0.2.0",
        instructions=(
            "Companion to Binary Ninja 6 native MCP. Use native MCP for general inspection, "
            "file management, comments, symbol/variable edits and types. Use this server for "
            "PE coordinates, driver evidence and explicit WinDbg pairing. Binary IDs from "
            "list_binaries belong to this companion; native binaryView handles are not valid "
            "here. Native active-view selection is shared across clients. This server uses "
            "the Binary Ninja API directly with explicit binary IDs, never the native active "
            "view. File paths describe files; debugger mapping requires PE identity and RVA."
        ),
    )
    pairing = Pairing(workspace, profiles)
    selected = selected_tools(profiles.groups)

    def tool(group):
        def register(fn):
            assert fn.__name__ in GROUPS[group]
            if fn.__name__ in selected:
                server.add_tool(
                    fn,
                    structured_output=True,
                    annotations=ToolAnnotations(
                        read_only_hint=group not in ("evidence", "debug")
                        and fn.__name__ not in ("navigate", "pair_windbg", "unpair_windbg"),
                        destructive_hint=fn.__name__ == "run_to_here",
                        idempotent_hint=group not in ("evidence", "debug"),
                        open_world_hint=False,
                    ),
                )
            return fn

        return register

    async def query(name, binary_id, **kwargs):
        budget = Budget()
        try:
            return await asyncio.to_thread(
                workspace.query, name, binary_id, budget=budget, **kwargs
            )
        finally:
            budget.cancel.set()

    @tool("workspace")
    async def list_binaries() -> dict[str, object]:
        """List open PE views and process-lifetime binary IDs."""
        return await asyncio.to_thread(workspace.list_binaries)

    @tool("workspace")
    async def current_location(binary_id: str | None = None) -> dict[str, object]:
        """Get the selected view's coordinate and current cursor."""
        return await asyncio.to_thread(workspace.current_location, binary_id)

    @tool("workspace")
    async def navigate(binary_id: str, coordinate: Coordinate) -> dict[str, object]:
        """Navigate one selected binary after validating PE identity and RVA."""
        return await asyncio.to_thread(workspace.navigate, binary_id, coordinate)

    @tool("workspace")
    async def wait_for_analysis(binary_id: str, timeout_ms: int = 30000) -> dict[str, object]:
        """Wait for analysis completion, with cancellation and a bounded deadline."""
        return await workspace.wait_for_analysis(binary_id, timeout_ms)

    @tool("driver")
    async def driver_entry(binary_id: str) -> dict[str, object]:
        """Recover supported dispatch registrations and unresolved WDM/KMDF callbacks."""
        return await query("driver_entry", binary_id)

    @tool("driver")
    async def sink_imports(binary_id: str) -> dict[str, object]:
        """Inventory a versioned sink list; imports alone do not establish reachability."""
        return await query("sink_imports", binary_id)

    @tool("driver")
    async def device_security(binary_id: str) -> dict[str, object]:
        """Recover static device creation and namespace arguments; effective access is dynamic."""
        return await query("device_security", binary_id)

    @tool("driver")
    async def ioctl_map(
        binary_id: str, traverse: bool = False, depth: int = 2, function_limit: int = 128
    ) -> dict[str, object]:
        """Map proven control-code cases; optionally traverse bounded dispatch-to-sink paths."""
        return await query(
            "ioctl_map", binary_id, traverse=traverse, depth=depth, function_limit=function_limit
        )

    @tool("driver")
    async def driver_surface(
        binary_id: str, depth: int = 2, function_limit: int = 128
    ) -> dict[str, object]:
        """Compose dispatch, imports, security, and IOCTL evidence, retaining section failures."""
        return await query("driver_surface", binary_id, depth=depth, function_limit=function_limit)

    @tool("evidence")
    async def add_evidence(
        binary_id: str, coordinate: Coordinate, evidence: Evidence
    ) -> dict[str, object]:
        """Append an undoable provenance record. Never include tokens or connection strings."""
        snapshot = await asyncio.to_thread(workspace.current_location, binary_id)
        from .core import Identity

        coordinate.address(
            int(snapshot["image_base"], 16), Identity.model_validate(snapshot["identity"])
        )
        # Explicit allowlist of structured context; profile credentials are never loaded here.
        record = evidence.model_dump()
        if any(word in record["note"].casefold() for word in ("bearer ", "key=", "authorization")):
            raise ValueError("evidence must not contain credentials or connection strings")
        record.update(
            timestamp=datetime.now(timezone.utc).isoformat(),
            architecture=snapshot["architecture"],
            file_sha256=snapshot.get("file_sha256"),
        )
        return await asyncio.to_thread(
            workspace.add_evidence,
            binary_id,
            coordinate,
            record,
            snapshot["generation"],
        )

    @tool("pair")
    async def pair_windbg(
        profile: str, session_id: str, binary_id: str, poll_interval_ms: int = 500
    ) -> dict[str, object]:
        """Pair with an explicit session using a locally stored credential; polling can renew leases."""
        return await pairing.pair(profile, session_id, binary_id, poll_interval_ms)

    @tool("pair")
    async def windbg_pair_status() -> dict[str, object]:
        """Get pairing and focused-action availability."""
        return dict(pairing.state)

    @tool("pair")
    async def unpair_windbg() -> dict[str, object]:
        """Close local pairing work without ending the debugger session or removing breakpoints."""
        return await pairing.unpair()

    @tool("debug")
    async def set_breakpoint_here() -> dict[str, object]:
        """Explicitly install one identity-guarded breakpoint at the paired view's cursor."""
        return await pairing.action("set_breakpoint_here")

    @tool("debug")
    async def run_to_here() -> dict[str, object]:
        """Explicitly resume to the paired cursor using an identity-guarded debugger operation."""
        return await pairing.action("run_to_here")

    @tool("debug")
    async def compare_runtime_bytes(size: int = 32) -> dict[str, object]:
        """Compare 1–256 current BinaryView bytes with runtime bytes and report raw differences."""
        return await pairing.action("compare_runtime_bytes", size)

    return server, pairing


class Authenticated:
    def __init__(self, app, token, port):
        self.app, self.token, self.port = app, token, port

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {}
        duplicate = False
        for key, value in scope["headers"]:
            if key in headers:
                duplicate = True
            headers[key] = value
        hosts = {f"127.0.0.1:{self.port}".encode(), f"localhost:{self.port}".encode()}
        origins = {b"http://" + host for host in hosts}
        auth = headers.get(b"authorization", b"")
        status = 200
        if scope.get("path") != "/mcp":
            status = 404
        elif (
            duplicate
            or headers.get(b"host") not in hosts
            or (b"origin" in headers and headers[b"origin"] not in origins)
        ):
            status = 403
        elif not hmac.compare_digest(auth, ("Bearer " + self.token).encode()):
            status = 401
        if status != 200:
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send({"type": "http.response.body", "body": b"Request refused"})
            return
        await self.app(scope, receive, send)


class Listener:
    def __init__(self, workspace, profiles, port=8766):
        self.workspace, self.profiles, self.port = workspace, profiles, port
        self.thread = None
        self.state = "stopped"
        self._lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._loop = None
        self.http = None
        self._pairing = None
        self._unpair_task = None

    def start(self):
        with self._lock:
            if self.thread and self.thread.is_alive():
                return
            try:
                selected_tools(self.profiles.groups)
            except ValueError as error:
                self.state = f"startup failed: {error}"
                raise
            sock = socket.socket()
            try:
                sock.bind(("127.0.0.1", self.port))
                sock.listen(128)
            except OSError:
                sock.close()
                self.state = "startup failed: loopback port unavailable"
                raise
            self.port = sock.getsockname()[1]
            self._stop_requested.clear()
            self.http = None
            self._pairing = None
            self._unpair_task = None
            self.state = "starting"
            self.thread = threading.Thread(
                target=self._run, args=(sock,), name="binja-windbg-mcp", daemon=True
            )
            self.thread.start()

    def _run(self, sock):
        async def run():
            self._loop = asyncio.get_running_loop()
            server, pairing = make_server(self.workspace, self.profiles)
            self._pairing = pairing
            # SDK 2.1.1 watches client disconnects only on its streaming response path.
            app = Authenticated(
                server.streamable_http_app(json_response=False), self.profiles.token, self.port
            )
            self.http = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host="127.0.0.1",
                    port=self.port,
                    log_level="critical",
                    access_log=False,
                    lifespan="on",
                    timeout_graceful_shutdown=1,
                )
            )
            if self._stop_requested.is_set():
                self._request_stop()
            else:
                self.state = "listening"
            try:
                await self.http.serve(sockets=[sock])
            finally:
                if self._unpair_task is not None:
                    await self._unpair_task
                else:
                    await pairing.unpair()

        try:
            asyncio.run(run())
        except Exception:
            self.state = "listener failed; check dependencies and restart"
        else:
            self.state = "stopped"
        finally:
            self._loop = None
            sock.close()

    def _request_stop(self):
        # Runs on the network loop. Close polling immediately, before draining requests.
        if self.http is not None:
            self.http.should_exit = True
        if self._pairing is not None and self._unpair_task is None:
            self._unpair_task = asyncio.create_task(self._pairing.unpair())

    def stop(self):
        self._stop_requested.set()
        if self.thread and self.thread.is_alive():
            self.state = "stopping"
        loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(self._request_stop)
            except RuntimeError:
                pass  # The network loop has already closed.

    def shutdown(self):
        self.workspace.shutdown()
        self.stop()
        # Workspace shutdown releases workers waiting for the UI before this bounded join.
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=3)
