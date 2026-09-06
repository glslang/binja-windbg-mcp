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

    monkeypatch.setattr(adapter, "main_thread", lambda fn, **kwargs: fn())
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
    view = N(
        add_analysis_completion_event=lambda callback: event, analysis_state=N(name="AnalyzeState")
    )
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


def test_explicit_binary_queries_ignore_shared_active_view_and_refresh_after_edits(monkeypatch):
    import pytest

    from binja_windbg_mcp import adapter
    from binja_windbg_mcp.core import Identity

    workspace = Workspace()
    keys = [(1, "PE"), (2, "PE")]
    workspace._ids = dict(zip(keys, ["one", "two"]))
    views = [N(start=0x1000, file=N(raw=N(read=None))), N(start=0x5000, file=N(raw=N(read=None)))]
    active = [0]
    calls = []
    monkeypatch.setattr(adapter, "main_thread", lambda fn, **kwargs: fn())
    monkeypatch.setattr(
        adapter, "pe_identity", lambda _: (Identity(timestamp=1, size=0x3000), "x86_64")
    )
    monkeypatch.setattr(
        workspace,
        "_views",
        lambda: [(k, v, i == active[0], v.start) for i, (k, v) in enumerate(zip(keys, views))],
    )

    def capture(view, budget, imports_only):
        calls.append(view.start)
        return {"imports": {"ProbeForRead": hex(view.start)}}

    monkeypatch.setattr(adapter, "capture_driver", capture)
    first = workspace.query("sink_imports", "one")
    active[0] = 1
    again = workspace.query("sink_imports", "one")
    assert first == again and calls == [0x1000]
    again["imports"].clear()
    assert workspace.query("sink_imports", "one")["imports"]
    workspace.invalidate(keys[0])  # Native symbol/type edits trigger the same notifications.
    workspace.query("sink_imports", "one")
    assert calls == [0x1000, 0x1000]
    with pytest.raises(ValueError, match="unambiguous"):
        workspace.query("sink_imports", "view_1")  # Native MCP handles are a different namespace.
    with pytest.raises(ValueError, match="native MCP"):
        workspace.query("get_code", "one")


def test_evidence_edit_is_pinned_and_rejects_stale_or_mismatched_provenance(monkeypatch):
    import json

    import pytest

    from binja_windbg_mcp import adapter
    from binja_windbg_mcp.core import Coordinate, Identity

    monkeypatch.setattr(adapter, "main_thread", lambda fn, **kwargs: fn())
    identity = Identity(timestamp=1, size=0x3000)
    monkeypatch.setattr(adapter, "pe_identity", lambda _: (identity, "x86_64"))
    workspace = Workspace()
    key = (1, "PE")
    workspace._ids[key] = "paired"
    text, undo = ["existing comment"], []
    view = N(
        start=0x180000000,
        file=N(raw=N(read=None), original_filename="driver.sys"),
        is_valid_offset=lambda address: True,
        begin_undo_actions=lambda: undo.append("begin") or "group",
        commit_undo_actions=lambda group: undo.append("commit"),
        revert_undo_actions=lambda group: undo.append("revert"),
        get_comment_at=lambda address: text[0],
        set_comment_at=lambda address, value: text.__setitem__(0, value),
    )
    monkeypatch.setattr(workspace, "acquire", lambda binary: (key, view, False, None))
    coordinate = Coordinate(
        module="driver", image_name="driver.sys", identity=identity, rva="0x1000"
    )
    stamp = workspace.stamp(key, view)
    workspace.invalidate(key)
    with pytest.raises(ValueError, match="generation changed"):
        workspace.add_evidence("paired", coordinate, {"note": "observed"}, stamp)
    assert undo == []
    for changed, message in (
        ({"image_name": "other.sys"}, "image name"),
        ({"identity": Identity(timestamp=2, size=0x3000)}, "identity"),
    ):
        with pytest.raises(ValueError, match=message):
            workspace.add_evidence(
                "paired", coordinate.model_copy(update=changed), {}, workspace.stamp(key, view)
            )
        assert undo == []
    workspace.add_evidence(
        "paired",
        coordinate,
        {"note": "observed", "file_sha256": "hash"},
        workspace.stamp(key, view),
    )
    assert undo == ["begin", "commit"]
    assert text[0].startswith("existing comment\n[windbg-evidence] ")
    record = json.loads(text[0].split("[windbg-evidence] ")[1])
    assert record["coordinate"]["rva"] == "0x1000" and record["file_sha256"] == "hash"


def test_metadata_uses_typed_analysis_state_property(monkeypatch):
    from binja_windbg_mcp import adapter
    from binja_windbg_mcp.core import Identity

    monkeypatch.setattr(
        adapter, "pe_identity", lambda _: (Identity(timestamp=1, size=0x3000), "x86_64")
    )
    monkeypatch.setattr(adapter, "original_hash", lambda _, **kwargs: None)
    workspace = Workspace()
    key = (1, "PE")
    workspace._ids[key] = "binary"
    view = N(
        start=0x140000000,
        file=N(raw=N(read=None), filename="driver.sys", original_filename="driver.sys"),
        analysis_info=N(state=0),
        analysis_state=N(name="IdleState"),
        modified=False,
    )
    assert workspace.metadata(key, view, True)["analysis_state"] == "IdleState"


def test_idle_analysis_wait_completes_without_another_analysis_pass(monkeypatch):
    import asyncio

    workspace = Workspace()
    cancelled = []
    view = N(
        add_analysis_completion_event=lambda callback: N(cancel=lambda: cancelled.append(True)),
        analysis_state=N(name="IdleState"),
    )
    monkeypatch.setattr(workspace, "acquire", lambda _: ((1, "PE"), view, True, 0))
    assert asyncio.run(workspace.wait_for_analysis("binary", timeout_ms=100)) == {
        "status": "success"
    }
    assert cancelled == [True]
    assert workspace._waiters[(1, "PE")] == []


def test_shutdown_releases_ui_wait_and_discards_late_callback(monkeypatch):
    import sys
    import threading

    from binja_windbg_mcp import adapter

    queued, executed, errors = [], [], []
    scheduled = threading.Event()
    closing = threading.Event()

    def schedule(callback):
        queued.append(callback)
        scheduled.set()

    bn = N(is_main_thread=lambda: False, execute_on_main_thread=schedule)
    monkeypatch.setitem(sys.modules, "binaryninja", bn)

    def request():
        try:
            adapter.main_thread(lambda: executed.append(True), cancel=closing)
        except InterruptedError as error:
            errors.append(error)

    worker = threading.Thread(target=request)
    worker.start()
    try:
        assert scheduled.wait(1)
    finally:
        closing.set()
        worker.join(1)
    assert not worker.is_alive()
    assert len(errors) == 1
    queued[0]()  # Qt may dispatch an already queued request during teardown.
    assert not executed


def test_workspace_shutdown_cancels_active_analysis_and_clears_its_budget(monkeypatch):
    import threading

    workspace = Workspace()
    started = threading.Event()
    errors = []

    def capture(name, binary_id, depth, function_limit, traverse, budget):
        started.set()
        budget.cancel.wait(2)
        budget.check()

    monkeypatch.setattr(workspace, "_query", capture)

    def request():
        try:
            workspace.query("driver_surface", "binary")
        except InterruptedError as error:
            errors.append(error)

    worker = threading.Thread(target=request)
    worker.start()
    try:
        assert started.wait(1)
    finally:
        workspace.shutdown()
        worker.join(1)
    assert not worker.is_alive()
    assert len(errors) == 1
    assert not workspace._budgets


def test_workspace_shutdown_cancels_analysis_completion_subscription(monkeypatch):
    import asyncio

    import pytest

    workspace = Workspace()
    subscribed, cancelled = [], []
    view = N(analysis_state=N(name="AnalyzeState"))

    def subscribe(callback):
        subscribed.append(True)
        return N(cancel=lambda: cancelled.append(True))

    view.add_analysis_completion_event = subscribe
    monkeypatch.setattr(workspace, "acquire", lambda _: ((1, "PE"), view, False, None))

    async def run():
        waiter = asyncio.create_task(workspace.wait_for_analysis("binary"))
        async with asyncio.timeout(2):
            while not subscribed:
                await asyncio.sleep(0.01)
            workspace.shutdown()
            with pytest.raises(asyncio.CancelledError):
                await waiter

    asyncio.run(run())
    assert cancelled == [True]
    assert workspace._waiters[(1, "PE")] == []


def test_selected_frame_survives_app_deactivation_without_guessing_between_windows(monkeypatch):
    import sys

    from binja_windbg_mcp.adapter import current_frame

    first, second = object(), object()
    contexts = [N(getCurrentViewFrame=lambda: first)]
    active = [None]
    monkeypatch.setitem(
        sys.modules,
        "binaryninjaui",
        N(UIContext=N(activeContext=lambda: active[0], allContexts=lambda: contexts)),
    )
    assert current_frame() is first
    contexts.append(N(getCurrentViewFrame=lambda: second))
    assert current_frame() is None
    active[0] = contexts[1]
    assert current_frame() is second
    active[0] = None
    contexts.clear()
    assert current_frame() is None
