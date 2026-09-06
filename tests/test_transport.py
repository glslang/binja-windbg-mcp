import asyncio
import json
import os
import time
from pathlib import Path

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from binja_windbg_mcp.profiles import Profiles
from binja_windbg_mcp.server import Listener


class Workspace:
    def list_binaries(self):
        return {"binaries": []}


def test_sdk_interoperability_auth_and_restart(tmp_path):
    profiles = Profiles(tmp_path)
    listener = Listener(Workspace(), profiles, port=0)
    listener.start()
    deadline = time.monotonic() + 10
    while listener.state == "starting" and time.monotonic() < deadline:
        time.sleep(0.01)
    assert listener.state == "listening"
    url = f"http://127.0.0.1:{listener.port}/mcp"

    async def check():
        async with httpx2.AsyncClient(trust_env=False) as http:
            for _ in range(100):
                try:
                    response = await http.post(url)
                    break
                except httpx2.ConnectError:
                    await asyncio.sleep(0.01)
            assert response.status_code == 401
            assert (await http.post(url, headers={"Host": "evil.test"})).status_code == 403
            assert (
                await http.post(url, headers={"Origin": "https://evil.test"})
            ).status_code == 403
            assert (await http.get(url.replace("/mcp", "/sse"))).status_code == 404
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + profiles.token}, trust_env=False
        ) as http:
            async with Client(streamable_http_client(url, http_client=http)) as client:
                listed = await client.list_tools()
                names = sorted(tool.name for tool in listed.tools)
                assert len(names) == 16
                result = await client.call_tool("list_binaries", {})
                assert result.structured_content == {"binaries": []}
                surface = [
                    tool.model_dump(mode="json", exclude_none=True)
                    for tool in sorted(listed.tools, key=lambda tool: tool.name)
                ]
                path = Path(__file__).with_name("tools_list.json")
                if os.environ.get("UPDATE_GOLDEN"):
                    path.write_text(json.dumps(surface, indent=2) + "\n")
                assert surface == json.loads(path.read_text())

    try:
        asyncio.run(check())
        collision = Listener(Workspace(), profiles, listener.port)
        with pytest.raises(OSError):
            collision.start()
    finally:
        listener.stop()
        listener.thread.join(10)
    assert not listener.thread.is_alive()
    listener.start()
    time.sleep(0.2)
    listener.stop()
    listener.thread.join(10)
    assert listener.state == "stopped"


def test_retired_profile_group_fails_before_binding_with_migration_guidance(tmp_path):
    profiles = Profiles(tmp_path)
    profiles._data["groups"] = "workspace,edit"
    listener = Listener(Workspace(), profiles, port=0)
    with pytest.raises(ValueError, match="retired.*native MCP"):
        listener.start()
    assert listener.thread is None
    assert "evidence" in listener.state
