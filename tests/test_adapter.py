from types import SimpleNamespace as N

from binja_windbg_mcp.adapter import Workspace, _capture_function, _field_path
from binja_windbg_mcp.core import Budget


def node(operation, address=0x1100, operands=(), **kwargs):
    return N(operation=N(name=operation), address=address, operands=operands, **kwargs)


def constant(value):
    return node("HLIL_CONST", constant=value)


def field(path):
    source = node("HLIL_VAR", expr_type=None)
    for part in path.split("."):
        source.expr_type = N(members=[N(name=part, offset=0)])
        source = node("HLIL_STRUCT_FIELD", src=source, offset=0, operands=[source], expr_type=None)
    return source


def test_adapter_recovers_comparison_chain_switch_and_conditional_sizes():
    control = field("Parameters.DeviceIoControl.IoControlCode")
    size = field("Parameters.DeviceIoControl.InputBufferLength")
    check = node("HLIL_CMP_UGE", left=size, right=constant(8))
    handler = node("HLIL_BLOCK", address=0x1200, operands=[check])
    comparison = node(
        "HLIL_IF",
        condition=node("HLIL_CMP_E", left=control, right=constant(0x22E004)),
        true=handler,
        false=node("HLIL_BLOCK"),
    )
    switch = node(
        "HLIL_SWITCH",
        condition=control,
        cases=[
            N(
                values=[constant(0x22E008), constant(0x22E00C)],
                body=node("HLIL_BLOCK", address=0x1300),
            )
        ],
    )
    function = N(start=0x1100, hlil=N(root=node("HLIL_BLOCK", operands=[comparison, switch])))
    view = N(start=0x1000)
    result = _capture_function(view, function, {}, Budget())
    assert [case["code"] for case in result["control_cases"]] == [0x22E004, 0x22E008, 0x22E00C]
    assert result["control_cases"][0]["evidence"][1]["kind"] == "conditional_size"
    assert result["control_cases"][0]["site"] == "0x200"


def test_adapter_retains_unresolved_switch_and_requires_layouts():
    switch = node("HLIL_SWITCH", condition=constant(10), cases=[])
    function = N(start=0x1000, hlil=N(root=switch))
    result = _capture_function(N(start=0x1000), function, {}, Budget())
    assert not result["control_cases"]
    assert result["unresolved"][0]["reason"] == "switch input not established"
    assert (
        _field_path(node("HLIL_STRUCT_FIELD", src=node("HLIL_VAR", expr_type=None), offset=0))
        is None
    )


def test_cache_invalidation_discards_immutable_results():
    workspace = Workspace()
    key = (1, "PE")
    workspace._ids[key] = "binary"
    workspace._revision[key] = 1
    workspace._cache[("binary", 1)] = {"value": 2}
    workspace.invalidate(key)
    assert workspace._revision[key] == 2
    assert workspace._cache == {}


def test_duplicate_views_need_a_selected_binary_and_closed_views_are_refused(monkeypatch):
    import pytest

    from binja_windbg_mcp import adapter

    monkeypatch.setattr(adapter, "main_thread", lambda fn: fn())
    workspace = Workspace()
    workspace._ids = {(1, "PE"): "one", (2, "PE"): "two"}
    rows = [((1, "PE"), object(), True, 0x1000), ((2, "PE"), object(), True, 0x1000)]
    monkeypatch.setattr(workspace, "_views", lambda: rows)
    with pytest.raises(ValueError):
        workspace.acquire(None)
    assert workspace.acquire("two")[0] == (2, "PE")
    rows.clear()
    with pytest.raises(ValueError):
        workspace.acquire("two")


def test_analysis_wait_cancellation_releases_subscription(monkeypatch):
    import asyncio

    workspace = Workspace()
    cancelled = []
    event = N(cancel=lambda: cancelled.append(True))
    view = N(add_analysis_completion_event=lambda callback: event)
    monkeypatch.setattr(workspace, "acquire", lambda _: ((1, "PE"), view, True, 0))

    async def check():
        task = asyncio.create_task(workspace.wait_for_analysis("binary", 10000))
        while not workspace._waiters:
            await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert cancelled == [True]
        assert workspace._waiters[(1, "PE")] == []

    asyncio.run(check())
