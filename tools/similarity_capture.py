"""Opt-in Ultimate comparison capture over the companion's authenticated MCP endpoint."""

import argparse
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


async def call(client, name, **arguments):
    result = await client.call_tool(name, arguments)
    data = result.structured_content
    if (
        result.is_error
        or not isinstance(data, dict)
        or data.get("status") in ("error", "unavailable")
    ):
        raise RuntimeError(f"{name} failed; verify capabilities and inputs")
    return data


async def pages(client, name, **arguments):
    records, offset = [], 0
    while True:
        result = await call(client, name, offset=offset, limit=100, **arguments)
        records.extend(result["items"])
        following = result["next_offset"]
        if following is None:
            return records
        if following <= offset:
            raise RuntimeError("pagination did not advance")
        offset = following


async def capture(client, reference, target, timeout_ms=120000, diff_count=10):
    capabilities = (await call(client, "similarity_status"))["capabilities"]
    if not all(capabilities["providers"].get(name) for name in ("Google BinDiff", "WARP")):
        raise RuntimeError("capture requires BN6 Ultimate with Google BinDiff and WARP")
    before = (await call(client, "list_binaries"))["binaries"]
    comparison_id = None
    try:
        started = await call(
            client,
            "similarity_start",
            reference_binary_id=reference,
            target_binary_id=target,
            timeout_ms=timeout_ms,
        )
        comparison_id = started["comparison_id"]
        async with asyncio.timeout(timeout_ms / 1000 + 30):
            while True:
                status = await call(client, "similarity_status", comparison_id=comparison_id)
                if not status["active"]:
                    break
                await asyncio.sleep(0.1)
            if status["state"] != "completed" or not status["coverage_complete"]:
                raise RuntimeError("comparison did not complete with full coverage")
            matches = await pages(client, "similarity_results", comparison_id=comparison_id)
            unmatched = {
                side: await pages(
                    client,
                    "similarity_results",
                    comparison_id=comparison_id,
                    side=side,
                    kind="unmatched",
                )
                for side in ("reference", "target")
            }
            differences = []
            for result in matches[:diff_count]:
                first = await call(
                    client,
                    "similarity_diff",
                    comparison_id=comparison_id,
                    result_id=result["result_id"],
                    limit=1,
                )
                first["items"] = await pages(
                    client,
                    "similarity_diff",
                    comparison_id=comparison_id,
                    result_id=result["result_id"],
                )
                first["next_offset"] = None
                first["truncated"] = False
                differences.append(first)
            after = (await call(client, "list_binaries"))["binaries"]
            for binary_id in (reference, target):
                old = next(b for b in before if b["binary_id"] == binary_id)
                new = next(b for b in after if b["binary_id"] == binary_id)
                if any(old[k] != new[k] for k in ("generation", "identity", "modified")):
                    raise RuntimeError("comparison inputs changed during capture")
            return {
                "capture_version": 1,
                "capabilities": capabilities,
                "comparison": status,
                "matches": matches,
                "unmatched": unmatched,
                "differences": differences,
                "input_generations_unchanged": True,
            }
    finally:
        if comparison_id is not None:
            await call(client, "similarity_close", comparison_id=comparison_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--connection", type=Path, required=True, help="Private JSON with url and token"
    )
    parser.add_argument("--reference", required=True, help="Reference companion binary ID")
    parser.add_argument("--target", required=True, help="Target companion binary ID")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-ms", type=int, default=120000)
    parser.add_argument("--diff-count", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.timeout_ms <= 600000 or not 0 <= args.diff_count <= 100:
        parser.error("timeout-ms must be 1–600000 and diff-count 0–100")
    config = json.loads(args.connection.read_text())
    url = urlsplit(config["url"])
    if (
        url.username
        or url.password
        or url.query
        or url.fragment
        or not url.hostname
        or url.scheme not in ("http", "https")
        or (url.scheme == "http" and url.hostname not in ("localhost", "127.0.0.1", "::1"))
    ):
        parser.error("connection must use loopback HTTP or HTTPS without credentials in the URL")

    async def run():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + config["token"]},
            trust_env=False,
            follow_redirects=False,
        ) as http:
            async with Client(streamable_http_client(config["url"], http_client=http)) as client:
                return await capture(
                    client, args.reference, args.target, args.timeout_ms, args.diff_count
                )

    report = asyncio.run(run())
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Captured {len(report['matches'])} matches; comparison closed")


if __name__ == "__main__":
    main()
