import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace as N

import pytest
from test_similarity import prepared_backend, snapshot

from binja_windbg_mcp.similarity import PROVIDERS, SIDES, SimilarityError, SimilarityManager
from binja_windbg_mcp.similarity_adapter import function_record
from binja_windbg_mcp.similarity_backends import SimilarityBackends
from binja_windbg_mcp.similarity_external import (
    ExternalSimilarity,
    Process,
    address,
    executable,
    score,
)


class Exporter:
    def capabilities(self):
        return {"available": True}

    def export(self, view, destination, check):
        check()
        payload = {
            "id": destination.stem + "-identity",
            "functions": [f.start for f in view.functions],
        }
        destination.write_text(json.dumps(payload))
        return {
            "export_id": payload["id"],
            "functions": set(payload["functions"]),
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        }


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / "BinDiff with spaces"
    path.write_text(
        f"#!{sys.executable}\n"
        + """
import json, pathlib, sqlite3, sys
if sys.argv[1:] == ["--version"]:
    print("BinDiff 8")
    sys.exit(0)
args = dict(arg[2:].split("=", 1) for arg in sys.argv[1:])
a, b = (json.loads(pathlib.Path(args[key]).read_text()) for key in ("primary", "secondary"))
with sqlite3.connect(pathlib.Path(args["output_dir"]) / "comparison.BinDiff") as db:
    db.executescript("CREATE TABLE metadata (file1, file2, version); CREATE TABLE file (id, filename, hash); CREATE TABLE function (id, address1, address2, similarity, confidence);")
    db.execute("INSERT INTO metadata VALUES (1,2,'BinDiff 8')")
    db.executemany("INSERT INTO file VALUES (?,?,?)", [(1,args["primary"],a["id"]),(2,args["secondary"],b["id"])])
    db.execute("INSERT INTO function VALUES (1,?,?,0.5,1.0)", (a["functions"][0], b["functions"][0]))
"""
    )
    path.chmod(0o700)
    return path


def backend_for(binary):
    native, *_ = prepared_backend()
    backend = ExternalSimilarity(native.workspace, Exporter())
    backend.configure(str(binary))
    return backend


def router_with(native=True, external=True):
    router = SimilarityBackends(None)
    router.backends = {
        "native": N(
            capabilities=lambda: {
                "available": native,
                "providers": dict.fromkeys(PROVIDERS, native),
            }
        ),
        "external": N(
            capabilities=lambda: {
                "available": external,
                "providers": {PROVIDERS[0]: external, "WARP": False},
            }
        ),
    }
    return router


@pytest.mark.parametrize(
    "native,external,selection,providers,expected",
    [
        (True, True, "auto", None, "native"),
        (False, True, "auto", None, "external"),
        (True, True, "external", None, "external"),
        (True, False, "native", None, "native"),
        (False, True, "auto", [PROVIDERS[0]], "external"),
    ],
)
def test_backend_selection(native, external, selection, providers, expected):
    name, _, selected = router_with(native, external).select(selection, providers)
    assert name == expected
    assert selected == (PROVIDERS if expected == "native" else PROVIDERS[:1])


@pytest.mark.parametrize(
    "selection,providers", [("external", ["WARP"]), ("auto", ["WARP"]), ("native", None)]
)
def test_personal_does_not_drop_explicit_provider_requests(selection, providers):
    with pytest.raises(SimilarityError) as caught:
        router_with(False, True).select(selection, providers)
    assert caught.value.code == "similarity_unavailable"


def test_external_full_lifecycle_and_cleanup(binary):
    backend = backend_for(binary)
    router = router_with(False, True)
    router.backends["external"] = backend
    manager = SimilarityManager(None, router)
    started = manager.start("old", "new")
    manager.join(5)
    result = manager.results(started["comparison_id"])
    assert result["state"] == "completed", result
    assert result["coverage_complete"] and result["backend"] == "external"
    row = result["items"][0]
    assert row["backend"] == "external" and row["raw_similarity"] == 0.5
    assert (row["similarity"], row["confidence"]) == (128, 255)
    assert row["reference"]["coordinate"]["identity"]["timestamp"] == 1
    assert row["target"]["coordinate"]["identity"]["timestamp"] == 2


@pytest.fixture
def exported(binary):
    backend = backend_for(binary)
    run = backend.prepare("old", "new", PROVIDERS[:1], lambda: None)
    run.start()
    assert run.done.wait(5)
    assert run.error is None
    yield run
    run.finish()
    assert not run.root.exists()


def edit_database(run, sql):
    with sqlite3.connect(next(run.root.glob("*.BinDiff"))) as db:
        db.executescript(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE metadata SET file1=2, file2=1",
        "UPDATE file SET hash='wrong'",
        "DROP TABLE function",
        "UPDATE function SET similarity=2",
        "UPDATE function SET confidence=NULL",
        "INSERT INTO function SELECT * FROM function",
        "UPDATE function SET address1='oops'",
        "DELETE FROM metadata",
        "INSERT INTO metadata SELECT * FROM metadata",
    ],
)
def test_invalid_database_rejected(exported, sql):
    edit_database(exported, sql)
    with pytest.raises(SimilarityError) as caught:
        list(exported.records())
    assert caught.value.code == "invalid_database"


def test_corrupt_sqlite_rejected(exported):
    next(exported.root.glob("*.BinDiff")).write_bytes(b"not sqlite")
    with pytest.raises(SimilarityError, match="database"):
        list(exported.records())


def test_modified_export_rejected(exported):
    (exported.root / "reference.BinExport").write_text("different")
    with pytest.raises(SimilarityError, match="export changed"):
        list(exported.records())


def test_omitted_functions_are_not_unmatched(exported):
    exported.functions["reference"][0x1200] = function_record(snapshot("old"), 0x1200, "omitted")
    exported.functions["reference"][0x1300] = function_record(snapshot("old"), 0x1300, "unmatched")
    exported.exports["reference"]["functions"].add(0x1300)
    rows = list(exported.records())
    unmatched = exported.unmatched(rows)
    assert [r["name"] for r in unmatched["reference"]] == ["unmatched"]


def test_unresolved_match_does_not_become_false_unmatched(exported):
    edit_database(exported, "UPDATE function SET address2=99999")
    rows = list(exported.records())
    assert rows == [] and exported.unresolved == 1
    assert exported.unmatched(rows)["reference"] == []


def test_high_addresses_map_to_the_correct_view(exported):
    high = 0xFFFFF80000001100
    exported.functions["reference"] = {
        high: function_record(snapshot("old", high - 0x100), high, "kernel")
    }
    exported.exports["reference"]["functions"] = {high}
    edit_database(exported, f"UPDATE function SET address1={high - (1 << 64)}")
    rows = list(exported.records())
    assert rows[0]["reference"]["address"] == hex(high)


@pytest.mark.parametrize("value,expected", [(0, 0), (0.5, 128), (1, 255), (0.1, 26)])
def test_score_conversion(value, expected):
    assert score(value) == expected


@pytest.mark.parametrize("value", [-1, 1.1, None, True, "0.5", float("nan"), float("inf")])
def test_invalid_scores(value):
    with pytest.raises(SimilarityError):
        score(value)


def test_address_recovery():
    assert address(-1) == (1 << 64) - 1


def test_explicit_missing_executable_does_not_fall_back_to_path(binary, monkeypatch):
    monkeypatch.setenv("PATH", str(binary.parent))
    with pytest.raises(SimilarityError):
        executable("/missing/bindiff")


def test_stale_before_import_refuses_results(exported):
    exported.backend.workspace.stamp = lambda *_: ("changed", 1, 2)
    with pytest.raises(SimilarityError) as caught:
        list(exported.records())
    assert caught.value.code == "stale"


def test_cancellation_during_export_keeps_views_until_export_returns(binary):
    backend = backend_for(binary)
    entered, release = threading.Event(), threading.Event()
    original = backend.exporter.export

    def export(*args):
        entered.set()
        assert release.wait(3)
        return original(*args)

    backend.exporter.export = export
    run = backend.prepare("old", "new", PROVIDERS[:1], lambda: None)
    try:
        run.start()
        assert entered.wait(1)
        run.request_stop()
        assert not run.finished and run.root.exists()
        release.set()
        assert run.done.wait(3)
        assert run.error.code == "cancelled" and run.process is None
    finally:
        release.set()
        run.finish()
    assert not run.root.exists()


def test_owned_process_timeout_drains_output_and_kills_group(tmp_path):
    process = Process(
        [
            sys.executable,
            "-c",
            "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); os.write(1,b'x'*200000); time.sleep(60)",
        ]
    )
    deadline = time.monotonic() + 0.25

    def check():
        if time.monotonic() >= deadline:
            raise SimilarityError("timed_out", "deadline")

    with pytest.raises(SimilarityError):
        process.wait(check)
    assert process.process.poll() is not None and not process.reader.is_alive()
    assert len(process.output) <= 65536
    with pytest.raises(ProcessLookupError):
        os.killpg(process.process.pid, 0)


def test_executable_version_and_config(binary):
    backend = backend_for(binary)
    assert backend.capabilities()["available"]
    assert backend.probe()["version"] == "8"
    backend.configure("/nonexistent/bindiff")
    assert not backend.capabilities()["available"]


def test_failure_never_imports_partial_database(exported):
    exported.error = SimilarityError("bindiff_failed", "child failed")
    with pytest.raises(SimilarityError, match="child failed"):
        list(exported.records())
    assert exported.unmatched([]) == dict.fromkeys(SIDES, [])


def test_helper_abi_mismatch_is_unavailable_without_export(tmp_path, monkeypatch):
    from binja_windbg_mcp import binexport

    helper = tmp_path / "helper.dylib"
    helper.touch()
    monkeypatch.setattr(binexport, "HELPER", helper)
    monkeypatch.setattr(binexport.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(binexport.platform, "machine", lambda: "arm64")
    monkeypatch.setitem(
        sys.modules,
        "binaryninja",
        N(_binaryninjacore=N(BNIsUIEnabled=lambda: True, BNGetCurrentCoreABIVersion=lambda: 188)),
    )
    exporter = binexport.BinExport()
    exporter._library = N(BNMCPExportABI=lambda: 1, BNMCPCoreABI=lambda: 187)
    result = exporter.capabilities()
    assert not result["available"] and "ABI mismatch" in result["reason"]


def test_missing_helper_leaves_other_backend_discoverable(monkeypatch):
    from binja_windbg_mcp import binexport

    monkeypatch.setattr(binexport, "HELPER", Path("/missing/export-helper"))
    assert not binexport.BinExport().capabilities()["available"]
    assert router_with(True, False).select("auto", None)[0] == "native"


def test_bad_optional_config_does_not_disable_server(tmp_path):
    from binja_windbg_mcp.profiles import Profiles
    from binja_windbg_mcp.server import make_server

    profiles = Profiles(tmp_path)
    profiles._data["similarity"] = {"bindiff_path": "relative/path"}
    workspace = N()
    assert make_server(workspace, profiles)
    cap = workspace.similarity.backend.backends["external"].capabilities()
    assert not cap["available"] and "absolute" in cap["reason"]


def test_external_tool_argument_reaches_backend(binary):
    import asyncio

    from mcp import Client

    from binja_windbg_mcp.server import make_server

    backend = backend_for(binary)
    router = router_with(False, True)
    router.backends["external"] = backend
    workspace = N(similarity=SimilarityManager(None, router))
    server, _ = make_server(workspace, N(groups="all", bindiff_path=str(binary)))

    async def check():
        async with Client(server) as client:
            result = await client.call_tool(
                "similarity_start",
                {"reference_binary_id": "old", "target_binary_id": "new", "backend": "external"},
            )
            job = result.structured_content
            assert job["backend"] == "external"
            await asyncio.to_thread(workspace.similarity.join, 5)
            result = await client.call_tool(
                "similarity_results", {"comparison_id": job["comparison_id"]}
            )
            assert result.structured_content["state"] == "completed"
            assert result.structured_content["items"][0]["backend"] == "external"
            await client.call_tool("similarity_close", {"comparison_id": job["comparison_id"]})

    asyncio.run(check())


def test_binexport_failure_releases_temp_directory(binary):
    backend = backend_for(binary)

    def fail(*_):
        raise SimilarityError("export_failed", "injected export failure")

    backend.exporter.export = fail
    run = backend.prepare("old", "new", PROVIDERS[:1], lambda: None)
    run.start()
    assert run.done.wait(3)
    assert run.process is None and run.error.code == "export_failed"
    run.finish()
    assert not run.root.exists()


def test_real_personal_capture_matches_independent_fixture_expectations():
    from binja_windbg_mcp.similarity import align_instructions

    capture = json.loads((Path(__file__).parent / "fixtures/similarity/personal.json").read_text())
    assert capture["ok"] and capture["unchanged"] and capture["analysis_unchanged"]
    assert not capture["capabilities"]["backends"]["native"]["available"]
    for name, result in capture["comparisons"].items():
        assert result["coverage_complete"] and result["backend"] == "external"
        assert {r["reference"]["coordinate"]["rva"] for r in result["items"]} == {
            "0x1000",
            "0x1020",
        }
        assert {r["target"]["coordinate"]["rva"] for r in result["items"]} == {"0x1000", "0x1020"}
        assert result["navigation"]["address"] == (
            "0x0000000180001000" if name == "relocated" else "0x0000000140001000"
        )
        assert [r["coordinate"]["rva"] for r in result["unmatched"]["target"]] == (
            ["0x1040"] if name == "changed" else []
        )
        for row in result["items"]:
            assert row["similarity"] == score(row["raw_similarity"])
            assert row["confidence"] == score(row["raw_confidence"])
        for diff in result["diffs"]:
            rows = diff["items"]
            assert (
                align_instructions(
                    [r["reference"] for r in rows if r["reference"]],
                    [r["target"] for r in rows if r["target"]],
                )
                == rows
            )
        if name == "identical":
            assert all(r["kind"] == "equal" for diff in result["diffs"] for r in diff["items"])
        if name == "changed":
            assert any(r["kind"] != "equal" for diff in result["diffs"] for r in diff["items"])
