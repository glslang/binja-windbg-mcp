"""One task owns the outbound SDK context and serializes polling with explicit actions."""

from __future__ import annotations

import asyncio

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from .core import Coordinate, Identity, compare_bytes


def leaf_errors(error):
    children = getattr(error, "exceptions", ())
    if children:
        for child in children:
            yield from leaf_errors(child)
    else:
        yield error


async def reject_authentication_failure(response):
    # SDK 2.1.1 otherwise converts these statuses to an unclassified MCP error.
    if response.status_code in (401, 403):
        response.raise_for_status()


class Pairing:
    def __init__(self, workspace, profiles):
        self.workspace, self.profiles = workspace, profiles
        self.task = None
        self.epoch = 0
        self.state = {"paired": False}
        self.queue = asyncio.Queue(maxsize=8)

    async def pair(self, profile, session_id, binary_id, poll_interval_ms=500):
        if self.task is not None:
            raise ValueError("explicitly unpair before replacing a pairing")
        url, token = self.profiles.profile(profile)
        self.epoch += 1
        epoch = self.epoch
        self.state = {
            "paired": True,
            "profile": profile,
            "session_id": session_id,
            "binary_id": binary_id,
            "state": "connecting",
            "actions": {},
        }
        ready = asyncio.get_running_loop().create_future()
        self.task = asyncio.create_task(
            self._run(url, token, epoch, ready, min(max(poll_interval_ms, 200), 5000) / 1000)
        )
        try:
            await asyncio.wait_for(asyncio.shield(ready), 30)
        except BaseException:
            await self.unpair()
            raise
        return dict(self.state)

    async def unpair(self):
        self.epoch += 1
        task, self.task = self.task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._fail_queued_actions()
        self.state = {"paired": False}
        return dict(self.state)

    def _fail_queued_actions(self):
        while not self.queue.empty():
            _, _, future = self.queue.get_nowait()
            if not future.done():
                future.set_exception(ValueError("pairing stopped before action was sent"))

    async def _call(self, client, tool, args):
        result = await client.call_tool(tool, args)
        data = result.structured_content
        if not isinstance(data, dict) or "status" not in data:
            raise ValueError("WinDbg structured contract unavailable")
        return data

    async def _validate(self, client):
        snapshot = await asyncio.to_thread(self.workspace.current_location, self.state["binary_id"])
        tools_result = await client.list_tools()
        tool_list = tools_result.tools
        tools = {tool.name: tool for tool in tool_list}
        if not {"modules", "current_location"} <= tools.keys():
            raise ValueError("pairing requires modules and current_location")
        for name in ("modules", "current_location"):
            if not tools[name].output_schema:
                raise ValueError("pairing requires structured output schemas")
        modules = await self._call(
            client, "modules", {"session_id": self.state["session_id"], "limit": 1024}
        )
        if modules["status"] == "error":
            raise ValueError("module validation refused")
        if modules.get("matched", len(modules["modules"])) > len(modules["modules"]):
            raise ValueError("module validation inventory is truncated")
        identity = Identity.model_validate(snapshot["identity"])
        matches = [
            m
            for m in modules["modules"]
            if (m["timestamp"], m["size"]) == (identity.timestamp, identity.size)
        ]
        if len(matches) != 1:
            raise ValueError("selected PE identity missing or ambiguous in debugger")
        module = matches[0]
        expected_image = snapshot.get("image_name") or (snapshot.get("coordinate") or {}).get(
            "image_name"
        )
        if (
            not expected_image
            or module["image_name"].replace("\\", "/").rsplit("/", 1)[-1].casefold()
            != expected_image.casefold()
        ):
            raise ValueError("selected image name mismatch")
        remote_identity = Identity(
            timestamp=module["timestamp"], size=module["size"], pdb=module.get("pdb")
        )
        Coordinate(
            module=module["name"],
            image_name=module["image_name"],
            identity=remote_identity,
            rva="0x0",
        ).address(0, identity)
        self.module = module
        self.generation = snapshot["generation"]
        self.state["actions"] = {
            name: {
                "enabled": name in tools
                and "coordinate" in tools[name].input_schema.get("properties", {})
                and bool(tools[name].output_schema),
                "reason": "requires guarded coordinate input and structured output",
            }
            for name in ("set_breakpoint", "run_to_address", "read_memory")
        }

    async def _run(self, url, token, epoch, ready, interval):
        delay, last = interval, None
        retry_delay = 0
        current_future = None
        try:
            while epoch == self.epoch:
                try:
                    async with httpx2.AsyncClient(
                        headers={"Authorization": "Bearer " + token},
                        verify=True,
                        follow_redirects=False,
                        trust_env=False,
                        timeout=30,
                        event_hooks={"response": [reject_authentication_failure]},
                    ) as http:
                        async with Client(
                            streamable_http_client(url, http_client=http), read_timeout_seconds=30
                        ) as client:
                            await self._validate(client)
                            if not ready.done():
                                ready.set_result(True)
                            self.state["state"] = "following"
                            delay = interval
                            while epoch == self.epoch:
                                try:
                                    name, size, current_future = await asyncio.wait_for(
                                        self.queue.get(), delay
                                    )
                                except asyncio.TimeoutError:
                                    sample = await self._call(
                                        client,
                                        "current_location",
                                        {"session_id": self.state["session_id"]},
                                    )
                                    if epoch != self.epoch:
                                        break
                                    if sample["status"] == "error":
                                        category = sample["error"]["category"]
                                        self.state["state"] = category
                                        if category in ("stale_session", "worker_lost"):
                                            return
                                        if category == "target_running":
                                            retry_delay = 0
                                            delay = max(interval, 1)
                                            continue
                                        raise ConnectionError("location unavailable")
                                    # Reconnect validation alone does not establish poll recovery.
                                    retry_delay = 0
                                    delay = interval
                                    snapshot = await asyncio.to_thread(
                                        self.workspace.current_location, self.state["binary_id"]
                                    )
                                    if snapshot["generation"] != self.generation:
                                        await self._validate(client)
                                        last = None
                                        continue
                                    changed = (
                                        sample.get("address"),
                                        sample.get("thread"),
                                        sample.get("processor"),
                                        sample.get("coordinate"),
                                    )
                                    self.state["location"] = sample
                                    self.state["state"] = sample.get("location_state", "unknown")
                                    coordinate = sample.get("coordinate")
                                    if (
                                        changed != last
                                        and coordinate
                                        and coordinate["module"].casefold()
                                        == self.module["name"].casefold()
                                    ):
                                        if epoch != self.epoch:
                                            break
                                        await asyncio.to_thread(
                                            self.workspace.navigate,
                                            self.state["binary_id"],
                                            Coordinate.model_validate(coordinate),
                                            self.generation,
                                            lambda: epoch == self.epoch,
                                        )
                                    last = changed
                                    continue
                                if current_future.cancelled():
                                    current_future = None
                                    continue
                                try:
                                    response = await self._action(client, name, size, epoch)
                                    if not current_future.done():
                                        current_future.set_result(response)
                                except (TimeoutError, asyncio.TimeoutError, httpx2.TransportError):
                                    if not current_future.done():
                                        current_future.set_result(
                                            {
                                                "status": "uncertain",
                                                "reason": "request may have completed; mutation was not retried",
                                            }
                                        )
                                except Exception:
                                    if not current_future.done():
                                        current_future.set_exception(
                                            ValueError(
                                                "focused action refused; inspect pairing status and selected view"
                                            )
                                        )
                                finally:
                                    # Cancellation leaves the active request for shutdown to resolve.
                                    if current_future.done():
                                        current_future = None
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    # Never serialize exception text: transport errors may contain request headers.
                    if not ready.done():
                        ready.set_exception(ValueError("pairing validation or connection failed"))
                        return
                    errors = tuple(leaf_errors(error))
                    if any(
                        isinstance(leaf, httpx2.HTTPStatusError)
                        and leaf.response.status_code in (401, 403)
                        for leaf in errors
                    ):
                        self.state["state"] = "authentication_failed"
                        return
                    if any(isinstance(leaf, ValueError) for leaf in errors):
                        self.state["state"] = "validation_failed"
                        return
                    self.state["state"] = "reconnecting"
                    retry_delay = min(max(1, retry_delay * 2), 10)
                    await asyncio.sleep(retry_delay)
        finally:
            if current_future is not None and not current_future.done():
                current_future.set_result(
                    {"status": "uncertain", "reason": "pairing closed during action"}
                )
            self._fail_queued_actions()
            if not ready.done():
                ready.cancel()

    async def action(self, name, size=32):
        if self.task is None or self.task.done():
            raise ValueError("no active pairing")
        if not 1 <= size <= 256:
            raise ValueError("byte count must be 1–256")
        future = asyncio.get_running_loop().create_future()
        self.queue.put_nowait((name, size, future))
        return await future

    async def _action(self, client, name, size, epoch):
        tool = {
            "set_breakpoint_here": "set_breakpoint",
            "run_to_here": "run_to_address",
            "compare_runtime_bytes": "read_memory",
        }[name]
        if not self.state["actions"][tool]["enabled"]:
            raise ValueError("guarded action unsupported")
        snapshot = await asyncio.to_thread(
            self.workspace.byte_snapshot,
            self.state["binary_id"],
            size if tool == "read_memory" else 1,
        )
        if epoch != self.epoch or snapshot["generation"] != self.generation:
            raise ValueError("pairing generation changed; revalidate first")
        coordinate = snapshot["coordinate"]
        coordinate["module"] = self.module["name"]
        coordinate["image_name"] = self.module["image_name"].replace("\\", "/").rsplit("/", 1)[-1]
        args = {"session_id": self.state["session_id"], "coordinate": coordinate}
        if tool == "read_memory":
            args["size"] = size
        try:
            result = await self._call(client, tool, args)
        except Exception:
            if tool != "read_memory":
                return {
                    "status": "uncertain",
                    "reason": "mutation request may have completed; it was not retried",
                }
            raise
        if result["status"] == "error":
            if tool != "read_memory" and result["error"]["category"] == "timeout":
                return {
                    "status": "uncertain",
                    "reason": "mutation may have completed; it was not retried",
                }
            return result
        if tool != "read_memory":
            return result
        current = await asyncio.to_thread(self.workspace.current_location, self.state["binary_id"])
        if epoch != self.epoch or current["generation"] != snapshot["generation"]:
            raise ValueError("comparison became stale")
        if result.get("requested_size") != size or result.get("read_size") != len(
            bytes.fromhex(result["data"])
        ):
            raise ValueError("invalid structured memory result")
        comparison = compare_bytes(
            bytes.fromhex(snapshot["data"]),
            bytes.fromhex(result["data"]),
            size,
            snapshot["relocations"],
        )
        return {
            "status": "ok",
            "coordinate": coordinate,
            "modified": snapshot["modified"],
            **comparison,
        }
