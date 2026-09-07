import asyncio
import copy
import threading
from types import SimpleNamespace as N

import pytest

from binja_windbg_mcp.similarity import (
    PROVIDERS,
    SimilarityError,
    SimilarityManager,
    align_instructions,
    page,
)
from binja_windbg_mcp.similarity_adapter import NativeRun, NativeSimilarity, function_record


def snapshot(binary_id, base=0x1000, timestamp=1):
    return {
        "binary_id": binary_id,
        "generation": [binary_id, base, 0],
        "image_base": f"0x{base:016x}",
        "image_name": "driver.sys",
        "identity": {"timestamp": timestamp, "size": 0x10000},
        "architecture": "x86_64",
    }


def match(result_id="match_1", provider="Google BinDiff", score=200):
    return {
        "result_id": result_id,
        "provider": provider,
        "similarity": score,
        "confidence": 123,
        "reference": function_record(snapshot("old"), 0x1100, "old_fn"),
        "target": function_record(snapshot("new", 0x5000, 2), 0x5200, "new_fn"),
    }


class Run:
    def __init__(self):
        self.snapshots = {"reference": snapshot("old"), "target": snapshot("new", 0x5000, 2)}
        self.keys = ("old", "new")
        self.started, self.stopped, self.release = (threading.Event() for _ in range(3))
        self.progress = 0.25
        self.unresolved = 0
        self.rows = [match(), match("match_2", "WARP", 255)]
        self.valid = True
        self.cleaned = False
        self.extract_error = False

    def validate(self):
        if not self.valid:
            raise SimilarityError("stale", "view changed")

    def start(self):
        self.started.set()

    @property
    def finished(self):
        return self.release.is_set()

    def request_stop(self):
        self.stopped.set()

    def records(self):
        yield from self.rows
        if self.extract_error:
            raise RuntimeError("provider extraction failed")

    def unmatched(self, records):
        return {
            "reference": [],
            "target": [function_record(snapshot("new", 0x5000, 2), 0x5500, "no_match")],
        }

    def finish(self):
        assert self.release.wait(2), "native handles released before provider completion"
        self.cleaned = True


class Backend:
    def __init__(self, run=None):
        self.run = run or Run()
        self.available = dict.fromkeys(PROVIDERS, True)
        self.prepare_error = None

    def capabilities(self):
        return {"available": any(self.available.values()), "providers": self.available}

    def prepare(self, reference, target, providers, check):
        check()
        if self.prepare_error:
            raise self.prepare_error
        return self.run

    def instructions(self, record, snapshots):
        self.run.validate()
        return {
            "reference": [{"text": "ret", "rva": "0x100"}],
            "target": [{"text": "nop", "rva": "0x200"}, {"text": "ret", "rva": "0x201"}],
        }, dict.fromkeys(("reference", "target"), False)


@pytest.fixture
def running():
    backend = Backend()
    manager = SimilarityManager(None, backend)
    job_id = manager.start("old", "new")["comparison_id"]
    assert backend.run.started.wait(1)
    yield manager, backend, job_id
    backend.run.release.set()
    manager.join(2)


def finish(manager, backend, job_id):
    backend.run.release.set()
    manager.join(2)
    assert not manager.status(job_id)["active"]


def test_cancel_retains_handles_until_provider_finishes_and_keeps_partial_results(running):
    manager, backend, job_id = running
    manager.cancel(job_id)
    assert backend.run.stopped.wait(1)
    assert manager.status(job_id)["active"] and not backend.run.cleaned
    with pytest.raises(SimilarityError, match="still active"):
        manager.start("other", "new")
    finish(manager, backend, job_id)
    result = manager.results(job_id)
    assert result["state"] == "cancelled" and not result["coverage_complete"]
    assert len(result["items"]) == 2 and backend.run.cleaned


def test_filters_pagination_scores_and_identity_are_preserved(running):
    manager, backend, job_id = running
    finish(manager, backend, job_id)
    first = manager.results(job_id, limit=1)
    assert first["coverage_complete"] and first["next_offset"] == 1
    assert first["items"][0]["provider"] == "WARP"
    second = manager.results(job_id, offset=first["next_offset"], limit=1)
    assert second["next_offset"] is None and second["items"][0]["confidence"] == 123
    result = manager.results(job_id, min_similarity=240)
    assert len(result["items"]) == 1
    item = result["items"][0]
    assert item["reference"]["coordinate"]["identity"]["timestamp"] == 1
    assert item["target"]["coordinate"]["identity"]["timestamp"] == 2
    item["target"]["coordinate"]["identity"]["timestamp"] = 99
    assert manager.results(job_id)["items"][0]["target"]["coordinate"]["identity"]["timestamp"] == 2
    unmatched = manager.results(job_id, kind="unmatched")
    assert unmatched["items"][0]["name"] == "no_match"
    assert manager.diff(job_id, "match_1")["items"][0]["kind"] == "insert"


def test_invalidation_marks_completed_results_stale_and_refuses_diff(running):
    manager, backend, job_id = running
    finish(manager, backend, job_id)
    manager.invalidate("new")
    assert manager.results(job_id)["state"] == "stale"
    with pytest.raises(SimilarityError, match="changed"):
        manager.diff(job_id, "match_1")


def test_view_change_while_running_requests_stop(running):
    manager, backend, job_id = running
    manager.invalidate("old")
    assert backend.run.stopped.wait(1)
    finish(manager, backend, job_id)
    assert manager.status(job_id)["state"] == "stale"


def test_generation_change_detected_without_notification_during_diff(running):
    manager, backend, job_id = running
    finish(manager, backend, job_id)
    backend.run.valid = False
    with pytest.raises(SimilarityError):
        manager.diff(job_id, "match_1")
    assert manager.status(job_id)["state"] == "stale"


def test_close_drains_before_forgetting_and_is_idempotent(running):
    manager, backend, job_id = running
    assert manager.close(job_id)["active"]
    assert backend.run.stopped.wait(1)
    assert manager.status(job_id)["closing"]
    backend.run.release.set()
    manager.join(2)
    assert manager.close(job_id)["state"] == "closed"
    with pytest.raises(SimilarityError):
        manager.results(job_id)


def test_timeout_uses_cooperative_stop(running):
    manager, backend, job_id = running
    manager._jobs[job_id].deadline = 0
    assert backend.run.stopped.wait(1)
    finish(manager, backend, job_id)
    assert manager.status(job_id)["state"] == "timed_out"


def test_stop_restart_and_shutdown_preserve_ownership(running):
    manager, backend, job_id = running
    manager.stop_all()
    assert backend.run.stopped.wait(1)
    manager.resume()
    with pytest.raises(SimilarityError, match="still active"):
        manager.start("old", "new")
    backend.run.release.set()
    manager.join(2)
    assert manager.status()["comparisons"] == []
    manager.stop_all(shutdown=True)
    with pytest.raises(SimilarityError, match="shutting down"):
        manager.resume()


def test_failure_preserves_completed_records(running):
    manager, backend, job_id = running
    backend.run.extract_error = True
    finish(manager, backend, job_id)
    result = manager.results(job_id)
    assert result["state"] == "failed" and not result["coverage_complete"]
    assert len(result["items"]) == 2


def test_retained_comparison_limit_requires_explicit_close():
    backend = Backend()
    backend.run.release.set()
    manager = SimilarityManager(None, backend)
    ids = []
    for _ in range(4):
        ids.append(manager.start("old", "new")["comparison_id"])
        manager.join(2)
    with pytest.raises(SimilarityError, match="limit 4"):
        manager.start("old", "new")
    manager.close(ids[0])
    manager.start("old", "new")
    manager.join(2)


def test_missing_provider_is_explicit_without_silent_fallback():
    backend = Backend()
    backend.available["WARP"] = False
    manager = SimilarityManager(None, backend)
    with pytest.raises(SimilarityError, match="WARP") as caught:
        manager.start("old", "new")
    assert caught.value.code == "similarity_unavailable"
    assert not backend.run.started.is_set()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"providers": []},
        {"providers": ["WARP", "WARP"]},
        {"timeout_ms": 600001},
        {"providers": ["Other"]},
    ],
)
def test_start_rejects_invalid_options(kwargs):
    with pytest.raises(SimilarityError):
        SimilarityManager(None, Backend()).start("old", "new", **kwargs)


def test_disassembly_alignment_ignores_address_and_preserves_insert_delete_replace():
    def rows(*names):
        return [{"text": text, "address": hex(i)} for i, text in enumerate(names)]

    left, right = rows("push", "mov", "add", "ret"), rows("push", "xor", "ret", "nop")
    right[0]["address"] = "0xffff"
    result = align_instructions(left, right)
    assert result[0]["kind"] == "equal"
    assert result[1]["kind"] == result[2]["kind"] == "replace"
    assert result[-1]["kind"] == "insert"
    assert align_instructions(rows("ret"), [])[0]["kind"] == "delete"


def test_page_enforces_size_and_input_bounds():
    data = [{"text": "x" * 10000} for _ in range(100)]
    first = page(data, 0, 100)
    assert 0 < first["next_offset"] < 100
    second = page(data, first["next_offset"], 100)
    assert second["items"]
    for offset, limit in [(-1, 100), (0, 501), (0, 0)]:
        with pytest.raises(SimilarityError):
            page(data, offset, limit)


def native_run():
    snapshots = {"reference": snapshot("old"), "target": snapshot("new", 0x5000, 2)}
    entities = {1: N(address=0x1100), 2: N(address=0x1200)}
    targets = {9: N(address=0x5200), 10: N(address=0x5300)}
    results = {
        100: N(target=N(node_id=20, entity_id=9), provider_id=3, similarity=254, confidence=200),
        101: N(target=N(node_id=20, entity_id=10), provider_id=4, similarity=255, confidence=1),
        102: N(target=N(node_id=999, entity_id=9), provider_id=3, similarity=255, confidence=255),
    }
    reversed_result = N(
        target=N(node_id=10, entity_id=1), provider_id=3, similarity=254, confidence=200
    )
    nodes = {
        "reference": N(
            id=10,
            entities=[1, 2],
            get_entity=entities.get,
            get_results=lambda entity: [100, 101, 102] if entity == 1 else [],
            get_result=results.get,
        ),
        "target": N(
            id=20,
            entities=[9, 10],
            get_entity=targets.get,
            get_results=lambda entity: [900] if entity == 9 else [],
            get_result=lambda _: reversed_result,
        ),
    }
    functions = {
        "reference": {
            e.address: function_record(snapshots["reference"], e.address, "duplicate")
            for e in entities.values()
        },
        "target": {
            e.address: function_record(snapshots["target"], e.address, "duplicate")
            for e in targets.values()
        },
    }
    return NativeRun(
        None,
        None,
        nodes,
        {"Google BinDiff": N(id=3), "WARP": N(id=4)},
        {},
        {},
        snapshots,
        functions,
    )


def test_native_results_resolve_ids_reverse_ownership_and_keep_competing_matches():
    run = native_run()
    rows = list(run.records())
    assert len(rows) == 2  # Reverse report deduplicates; WARP's other target remains separate.
    assert rows[0]["reference"]["coordinate"]["rva"] == "0x100"
    assert rows[0]["target"]["coordinate"]["rva"] == "0x200"
    assert (rows[0]["similarity"], rows[0]["confidence"]) == (254, 200)
    assert run.unresolved == 1
    assert run.unmatched(rows)["reference"][0]["coordinate"]["rva"] == "0x200"


def test_personal_provider_creation_failure_is_reported_as_unavailable():
    provider = N(get_default_settings=lambda: object(), create=lambda _: None)
    bn = N(
        core_version=lambda: "6.0.10601",
        core_product_type=lambda: "Personal",
        SimilarityProviderType={name: provider for name in PROVIDERS},
    )
    result = NativeSimilarity(None, bn).capabilities()
    assert result["edition"] == "Personal" and not result["available"]
    assert not any(result["providers"].values())


def test_native_disassembly_is_bounded_and_rechecks_both_generations():
    snapshots = {"reference": snapshot("old"), "target": snapshot("new", 0x5000, 2)}
    views = {
        s["binary_id"]: N(
            start=int(s["image_base"], 16),
            get_function_at=lambda _: N(
                instructions=[([N(text="ret")], i + 0x6000) for i in range(2001)]
            ),
        )
        for s in snapshots.values()
    }
    stamps = {s["binary_id"]: tuple(s["generation"]) for s in snapshots.values()}
    workspace = N(
        _check_open=lambda: None,
        acquire=lambda bid: (bid, views[bid], False, None),
        stamp=lambda key, _: stamps[key],
    )
    backend = NativeSimilarity(workspace)
    rows, truncated = backend.instructions(match(), snapshots)
    assert all(len(side) == 2000 for side in rows.values()) and all(truncated.values())
    stamps["old"] = ("old", 0x1000, 1)
    with pytest.raises(SimilarityError, match="generation changed"):
        backend.instructions(match(), snapshots)


def test_result_limit_marks_coverage_incomplete(running, monkeypatch):
    from binja_windbg_mcp import similarity

    manager, backend, job_id = running
    monkeypatch.setattr(similarity, "MAX_RESULTS", 1)
    finish(manager, backend, job_id)
    result = manager.results(job_id)
    assert len(result["items"]) == 1 and not result["coverage_complete"]
    assert result["error"]["code"] == "result_limit"


def test_cleanup_failure_does_not_drop_live_handles(running):
    manager, backend, job_id = running
    original = backend.run.finish
    calls = []

    def finish_after_transient_error():
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("completion unavailable")
        original()

    backend.run.finish = finish_after_transient_error
    finish(manager, backend, job_id)
    assert backend.run.cleaned and len(calls) == 2
    assert not manager.status(job_id)["coverage_complete"]


def test_unresolved_provider_references_prevent_complete_coverage(running):
    manager, backend, job_id = running
    backend.run.unresolved = 1
    finish(manager, backend, job_id)
    result = manager.results(job_id)
    assert result["state"] == "partial" and not result["coverage_complete"]
    assert result["unresolved_results"] == 1


def prepared_backend():
    snapshots = {"old": snapshot("old"), "new": snapshot("new", 0x5000, 2)}
    stamps = {key: tuple(s["generation"]) for key, s in snapshots.items()}
    views = {
        bid: N(
            view_type="PE",
            analysis_state=N(name="IdleState"),
            functions=[N(start=int(s["image_base"], 16) + 0x100, name="fn")],
            is_valid_offset=lambda _: True,
        )
        for bid, s in snapshots.items()
    }
    workspace = N(
        _check_open=lambda: None,
        acquire=lambda bid: (bid, views[bid], False, None),
        metadata=lambda key, *_: copy.deepcopy(snapshots[key]),
        stamp=lambda key, _: stamps[key],
    )
    providers, nodes, edges = [], [], []
    session = N(
        add_provider=providers.append,
        graph=N(add_node=nodes.append, add_edge=lambda a, b: edges.append((a, b)) or True),
        run=lambda: N(is_finished=True, progress=1.0),
    )
    bn = N(
        SimilaritySession=lambda: session,
        SimilaritySessionNode=lambda view: N(view=view),
        SimilarityProviderType={
            name: N(get_default_settings=lambda: object(), create=lambda _: object())
            for name in PROVIDERS
        },
    )
    return NativeSimilarity(workspace, bn), snapshots, stamps, views, providers, nodes, edges


def test_native_prepare_pins_views_and_builds_graph_without_resolver_or_apply():
    backend, snapshots, stamps, views, providers, nodes, edges = prepared_backend()
    before = copy.deepcopy(snapshots)
    run = backend.prepare("old", "new", PROVIDERS, lambda: None)
    assert len(providers) == 2 and edges == [(nodes[0], nodes[1])]
    assert nodes[0].view is views["old"] and nodes[1].view is views["new"]
    assert run.snapshots == {"reference": snapshots["old"], "target": snapshots["new"]}
    run.validate()
    run.start()
    assert run.finished
    assert snapshots == before
    stamps["old"] = ("old", 0x1000, 1)
    with pytest.raises(SimilarityError, match="view changed"):
        run.validate()


@pytest.mark.parametrize("problem", ["busy", "architecture", "closed"])
def test_native_prepare_refuses_invalid_inputs(problem):
    backend, snapshots, stamps, views, providers, _, _ = prepared_backend()
    if problem == "busy":
        views["new"].analysis_state.name = "AnalyzeState"
    elif problem == "architecture":
        snapshots["new"]["architecture"] = "aarch64"
    else:
        stamps["old"] = (None, 0x1000, 1)

        # Closure while enumerating functions must be caught before constructing a session.
        def changed_stamp(*_):
            old = stamps["old"]
            stamps["old"] = (None, 0x1000, old[2] + 1)
            return old

        backend.workspace.stamp = changed_stamp
    with pytest.raises(SimilarityError):
        backend.prepare("old", "new", PROVIDERS, lambda: None)
    assert providers == []


def test_sdk_tools_include_structured_errors_generation_guard_and_annotations():
    from mcp import Client

    from binja_windbg_mcp.server import make_server

    backend = Backend()
    manager = SimilarityManager(None, backend)
    navigations = []
    workspace = N(
        similarity=manager,
        navigate=lambda *args, **kw: navigations.append(kw) or {"status": "success"},
    )
    server, _ = make_server(workspace, N(groups="all"))

    async def check():
        async with Client(server) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert not tools["similarity_start"].annotations.read_only_hint
            assert not tools["similarity_start"].annotations.idempotent_hint
            assert tools["similarity_results"].annotations.read_only_hint
            unavailable = await client.call_tool("similarity_results", {"comparison_id": "unknown"})
            assert unavailable.structured_content["error"]["code"] == "unknown_comparison"
            backend.available = dict.fromkeys(PROVIDERS, False)
            unavailable = await client.call_tool(
                "similarity_start", {"reference_binary_id": "old", "target_binary_id": "new"}
            )
            assert unavailable.structured_content["status"] == "unavailable"
            backend.available = dict.fromkeys(PROVIDERS, True)
            started = await client.call_tool(
                "similarity_start", {"reference_binary_id": "old", "target_binary_id": "new"}
            )
            job_id = started.structured_content["comparison_id"]
            assert await asyncio.to_thread(backend.run.started.wait, 1)
            backend.run.release.set()
            await asyncio.to_thread(manager.join, 2)
            result = await client.call_tool(
                "similarity_results", {"comparison_id": job_id, "limit": 1}
            )
            row = result.structured_content["items"][0]
            diff = await client.call_tool(
                "similarity_diff", {"comparison_id": job_id, "result_id": row["result_id"]}
            )
            assert diff.structured_content["comparison_kind"] == "instruction_text"
            await client.call_tool(
                "navigate",
                {
                    "binary_id": "new",
                    "coordinate": row["target"]["coordinate"],
                    "expected_generation": row["target"]["generation"],
                },
            )
            assert navigations[0]["expected_generation"] == tuple(row["target"]["generation"])
            await client.call_tool("similarity_cancel", {"comparison_id": job_id})
            await client.call_tool("similarity_close", {"comparison_id": job_id})
            status = await client.call_tool("similarity_status", {})
            assert status.structured_content["comparisons"] == []

    try:
        asyncio.run(check())
    finally:
        backend.run.release.set()
        manager.join(2)


@pytest.mark.parametrize("failure", [False, True])
def test_capture_runner_closes_owned_comparison_on_success_and_failure(failure):
    from mcp import Client

    from binja_windbg_mcp.server import make_server
    from tools.similarity_capture import capture

    backend = Backend()
    backend.run.release.set()
    backend.run.extract_error = failure
    manager = SimilarityManager(None, backend)
    binaries = [
        dict(snapshot("old"), modified=False),
        dict(snapshot("new", 0x5000, 2), modified=False),
    ]
    server, _ = make_server(
        N(similarity=manager, list_binaries=lambda: {"binaries": binaries}), N(groups="all")
    )

    async def check():
        async with Client(server) as client:
            if failure:
                with pytest.raises(RuntimeError, match="full coverage"):
                    await capture(client, "old", "new")
            else:
                report = await capture(client, "old", "new")
                assert report["input_generations_unchanged"]
                assert len(report["matches"]) == len(report["differences"]) == 2
                assert report["differences"][0]["next_offset"] is None
            assert not manager.status()["comparisons"]

    asyncio.run(check())


def test_navigation_generation_guard_refuses_stale_results_before_ui_action(monkeypatch):
    from binja_windbg_mcp import adapter
    from binja_windbg_mcp.core import Coordinate, Identity

    workspace = adapter.Workspace()
    key = (1, "PE")
    workspace._ids[key] = "new"
    navigations = []
    view = N(
        start=0x5000,
        file=N(raw=N(read=None)),
        view="Linear",
        is_valid_offset=lambda _: True,
        navigate=lambda *args: navigations.append(args) or True,
    )
    monkeypatch.setattr(adapter, "main_thread", lambda fn, **_: fn())
    monkeypatch.setattr(
        adapter, "pe_identity", lambda _: (Identity(timestamp=2, size=0x10000), "x86_64")
    )
    monkeypatch.setattr(workspace, "acquire", lambda _: (key, view, False, None))
    coordinate = Coordinate.model_validate(match()["target"]["coordinate"])
    stamp = workspace.stamp(key, view)
    workspace.navigate("new", coordinate, expected_generation=stamp)
    assert navigations == [("Linear", 0x5200)]
    workspace.invalidate(key)
    with pytest.raises(ValueError, match="generation changed"):
        workspace.navigate("new", coordinate, expected_generation=stamp)
    assert len(navigations) == 1
