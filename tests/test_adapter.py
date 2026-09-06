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


def ioctl_types(pointer_size=8):
    integer = N(width=4, type_class=N(name="IntegerTypeClass"))
    control = N(
        width=4 * pointer_size,
        members=[
            N(name=name, offset=index * pointer_size, type=integer)
            for index, name in enumerate(
                ("OutputBufferLength", "InputBufferLength", "IoControlCode")
            )
        ],
    )
    union = N(width=control.width, members=[N(name="DeviceIoControl", offset=0, type=control)])
    return N(
        width=64 + pointer_size, members=[N(name="Parameters", offset=pointer_size, type=union)]
    )


def ioctl_read(stack, offset, size=4, pointer_size=8):
    pointer = N(target=stack, width=pointer_size, type_class=N(name="PointerTypeClass"))
    base = node("HLIL_VAR", expr_type=pointer)
    parameter_offset = pointer_size
    parameters = node(
        "HLIL_DEREF_FIELD", src=base, offset=parameter_offset, size=32, expr_type=None
    )
    return node("HLIL_STRUCT_FIELD", src=parameters, offset=offset - parameter_offset, size=size)


def test_union_field_uses_member_index_and_refuses_ambiguous_or_invalid_indices():
    union = N(members=[N(name="Create", offset=0), N(name="DeviceIoControl", offset=0)])
    base = node("HLIL_VAR", expr_type=union)
    assert _field_path(node("HLIL_STRUCT_FIELD", src=base, offset=0)) is None
    assert (
        _field_path(node("HLIL_STRUCT_FIELD", src=base, offset=0, member_index=1))
        == "DeviceIoControl"
    )
    assert _field_path(node("HLIL_STRUCT_FIELD", src=base, offset=0, member_index=10)) is None
    assert _field_path(node("HLIL_STRUCT_FIELD", src=base, offset=0, member_index=-1)) is None
    assert _field_path(node("HLIL_STRUCT_FIELD", src=base, offset=4, member_index=1)) is None


def test_typed_ioctl_reads_use_the_actual_architecture_layout_and_exact_width():
    from binja_windbg_mcp.adapter import _ioctl_field_path, _ioctl_layout

    for pointer_size in (4, 8):
        stack = ioctl_types(pointer_size)
        layout = _ioctl_layout(stack)
        context = (stack, layout, pointer_size)
        offset = 3 * pointer_size
        read = ioctl_read(stack, offset, pointer_size=pointer_size)
        assert _ioctl_field_path(read, context) == "Parameters.DeviceIoControl.IoControlCode"
        assert _ioctl_field_path(read, None) is None
        assert (
            _ioctl_field_path(ioctl_read(stack, offset, size=8, pointer_size=pointer_size), context)
            is None
        )
        assert (
            _ioctl_field_path(ioctl_read(stack, offset + 1, pointer_size=pointer_size), context)
            is None
        )
        assert (
            _ioctl_field_path(ioctl_read(N(), offset, pointer_size=pointer_size), context) is None
        )
        assert _ioctl_field_path(read, (stack, layout, pointer_size * 2)) is None


def test_missing_malformed_and_overlapping_ioctl_layouts_are_not_guessed():
    from binja_windbg_mcp.adapter import _ioctl_layout

    assert _ioctl_layout(None) == {}
    stack = ioctl_types()
    union = stack.members[0].type
    union.members[0].name = "Create"
    assert _ioctl_layout(stack) == {}
    stack = ioctl_types()
    fields = stack.members[0].type.members[0].type.members
    fields[2].offset = fields[1].offset
    assert _ioctl_layout(stack) == {}
    fields[2].offset = 1000
    assert "IoControlCode" not in _ioctl_layout(stack)


def test_untyped_union_offsets_require_dispatch_context_and_immutable_alias():
    from binja_windbg_mcp.adapter import _ioctl_layout

    stack = ioctl_types()
    source = ioctl_read(stack, 24)
    check = node("HLIL_CMP_UGE", left=ioctl_read(stack, 16), right=constant(8))
    variable = N(identifier=10)
    init = node("HLIL_VAR_INIT", dest=variable, src=source)
    alias = node("HLIL_VAR", var=variable)
    comparison = node(
        "HLIL_IF",
        condition=node("HLIL_CMP_E", left=alias, right=constant(0x22E004)),
        true=node("HLIL_BLOCK", address=0x1200, operands=[check]),
        false=node("HLIL_BLOCK"),
    )
    function = N(start=0x1100, hlil=N(root=node("HLIL_BLOCK", operands=[init, comparison])))
    view = N(start=0x1000)
    context = (stack, _ioctl_layout(stack), 8)
    assert not _capture_function(view, function, {}, Budget())["control_cases"]
    result = _capture_function(view, function, {}, Budget(), ioctl_context=context)
    assert [case["code"] for case in result["control_cases"]] == [0x22E004]
    evidence = result["control_cases"][0]["evidence"][1]
    assert evidence["field"] == "Parameters.DeviceIoControl.InputBufferLength"
    assert evidence["kind"] == "conditional_size" and evidence["value"] == 8
    function.hlil.root.operands.append(node("HLIL_ASSIGN", dest=alias, src=constant(1)))
    assert not _capture_function(view, function, {}, Budget(), ioctl_context=context)[
        "control_cases"
    ]


def test_real_hevd_union_read_replays_through_the_adapter():
    import json
    from pathlib import Path

    from binja_windbg_mcp.adapter import _ioctl_field_path, _ioctl_layout

    fixture = json.loads(
        Path(__file__).with_name("fixtures").joinpath("inputs/hevd-ioctl-input.json").read_text()
    )

    def load_type(record):
        return N(
            width=record["width"],
            type_class=N(name=record["class"] + "Class"),
            members=[
                N(name=member["name"], offset=member["offset"], type=load_type(member["type"]))
                for member in record.get("members", [])
            ],
        )

    stack = load_type(fixture["stack_type"])
    read = fixture["read"]
    assert read["base_matches"] and read["base_registered_name"] == "_IO_STACK_LOCATION"
    layout = _ioctl_layout(stack)
    assert layout == read["layout"]
    pointer = N(width=read["pointer_size"], target=stack, type_class=N(name="PointerTypeClass"))
    base = node(read["operations"][2], expr_type=pointer)
    parameters = node(read["operations"][1], src=base, offset=read["offsets"][1])
    source = node(
        read["operations"][0], src=parameters, offset=read["offsets"][0], size=read["read_size"]
    )
    assert _ioctl_field_path(source, None) is None
    assert _ioctl_field_path(source, (stack, layout, read["pointer_size"])) == (
        "Parameters.DeviceIoControl.IoControlCode"
    )


def test_capture_reinterprets_union_offsets_only_for_registered_control_dispatches(monkeypatch):
    import sys

    from binja_windbg_mcp import adapter

    stack = ioctl_types()
    functions = [N(start=0x1000), N(start=0x1100), N(start=0x1200), N(start=0x1300)]
    view = N(
        start=0x1000,
        entry_point=0x1000,
        arch=N(name="aarch64"),
        address_size=8,
        functions=functions,
        get_symbols=lambda: [],
        get_type_by_name=lambda name: stack if name == "_IO_STACK_LOCATION" else None,
        get_function_at=lambda address: next(f for f in functions if f.start == address),
    )
    monkeypatch.setitem(sys.modules, "binaryninja", N(core_version=lambda: "6.0.fixture"))
    called = []

    def capture(view, function, layouts, budget, ioctl_context=None):
        called.append((function.start, ioctl_context is not None))
        return {
            "rva": hex(function.start - view.start),
            "registrations": [
                {"major_function": major, "callback_rva": rva}
                for major, rva in [(14, "0x100"), (15, "0x200"), (0, "0x300"), (14, "0x300")]
            ]
            if function.start == 0x1000
            else [],
            "unresolved": [],
        }

    monkeypatch.setattr(adapter, "_capture_function", capture)
    result = adapter.capture_driver(view, Budget())
    assert len(result["functions"]) == 4
    assert called == [(f.start, False) for f in functions] + [(0x1100, True), (0x1200, True)]
