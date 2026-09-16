"""Offline regressions for endpoint correspondence and retained probe execution."""

import copy
import gzip
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gui = load("clrbhb_gui_probe")


@pytest.mark.parametrize("fault", [None, "unrelated_reference", "swapped", "missing", "duplicate"])
def test_comparison_requires_exact_endpoint_pairs(tmp_path, monkeypatch, fault):
    rows = [
        {
            "result_id": str(i),
            "reference": {"coordinate": {"rva": hex(0x10FC00 + i * 0x80)}},
            "target": {"coordinate": {"rva": hex(0x11AC00 + i * 0x80)}},
        }
        for i in range(8)
    ]
    if fault == "unrelated_reference":
        rows[0]["reference"]["coordinate"]["rva"] = "0x1000"
    elif fault == "swapped":
        rows[0]["reference"], rows[1]["reference"] = rows[1]["reference"], rows[0]["reference"]
    elif fault == "missing":
        rows.pop()
    elif fault == "duplicate":
        rows[-1] = copy.deepcopy(rows[0])
    config = {side: str(tmp_path / side) for side in ("reference", "target")}
    config["bindiff"] = "bindiff"
    similarity = Mock()
    similarity.backend.backends = {"external": Mock()}
    similarity.start.return_value = {"comparison_id": "comparison"}
    similarity.status.return_value = {
        "active": False,
        "state": "completed",
        "coverage_complete": True,
    }
    similarity.results.side_effect = lambda *a, **kw: {
        "items": [] if kw.get("kind") == "unmatched" else rows,
        "next_offset": None,
    }

    def diff(comparison, result_id, **kwargs):
        i = int(result_id)
        return {
            "items": [
                {
                    side: {
                        "rva": hex(base + 0x80 * i + offset),
                        "text": "instruction",
                        "text_truncated": False,
                    }
                    for side, base in (("reference", 0x10FC00), ("target", 0x11AC00))
                }
                for offset in (0, 4, 8)
            ],
            "next_offset": None,
            "truncated": False,
            "instructions_truncated": {"reference": False, "target": False},
        }

    similarity.diff.side_effect = diff
    workspace = Mock(similarity=similarity)
    workspace.list_binaries.return_value = {
        "binaries": [{"binary_id": side} for side in ("reference", "target")]
    }
    workspace.acquire.side_effect = lambda side: (
        side,
        SimpleNamespace(file=SimpleNamespace(original_filename=config[side])),
        None,
        None,
    )
    monkeypatch.setattr(gui, "state", lambda *args: {})
    report = {}
    assert gui.compare_endpoints(workspace, config, report, lambda: None) is (fault is None)
    similarity.close.assert_called_once_with("comparison")
    if fault:
        similarity.diff.assert_not_called()
        assert "eight expected endpoint pairs" in report["comparison"]["error"]
    else:
        assert len(report["comparison"]["diffs"]) == 8


def test_retained_capture_has_all_expected_pairs():
    source = TOOLS.parent / "docs/samples/clrbhb-native-acceptance-20260915.json.gz"
    report = json.loads(gzip.decompress(source.read_bytes()))
    selected = gui.endpoint_matches(report["capture"]["comparison"]["matches"])
    assert len(selected) == 8
    matches = {row["result_id"]: row for row in selected}
    for diff in report["capture"]["comparison"]["diffs"]:
        assert gui.endpoint_diff_complete(diff, matches[diff["result"]["result_id"]])
    endpoints = report["capture"]["endpoints"]
    assert len(endpoints) == 16 and all(gui.endpoint_analysis_complete(row) for row in endpoints)


@pytest.mark.parametrize("checkout_change", ["edited", "removed"])
def test_delayed_import_executes_the_hashed_snapshot(tmp_path, monkeypatch, checkout_change):
    # Loading the launcher requires its sibling installer, but this test never installs a plugin.
    monkeypatch.syspath_prepend(str(TOOLS))
    launcher_module = load("capture_arm64")
    live = tmp_path / "checkout"
    live.mkdir()
    launcher = live / "capture_arm64.py"
    launcher.write_text("original launcher")
    probe = live / "clrbhb_gui_probe.py"
    package = live / "binja_windbg_mcp"
    package.mkdir()
    for source in (TOOLS.parent / "binja_windbg_mcp").glob("*.py"):
        shutil.copy2(source, package / source.name)
    (package / "native").mkdir()
    helper = package / "native/libbinja_binexport.dylib"
    helper.write_bytes(b"snapshot export helper")
    original = b"""from pathlib import Path
def start(path):
    from binja_windbg_mcp import adapter, similarity_adapter, binexport
    helper = binexport.HELPER
    assert helper.read_bytes() == b"snapshot export helper"
    assert adapter.Workspace.__name__ == "Workspace"
    assert similarity_adapter.NativeSimilarity.__name__ == "NativeSimilarity"
    assert helper.parent.parent == Path(adapter.__file__).parent
    Path(path).write_text("snapshot executed")
"""
    probe.write_bytes(original)
    output = tmp_path / "capture"
    output.mkdir()
    result = output / "result.txt"
    code, hashes = launcher_module.snapshot_probe(output, launcher, [live], result)
    if checkout_change == "edited":
        probe.write_text('raise RuntimeError("live checkout was imported")\n')
        launcher.write_text("changed launcher")
        (package / "adapter.py").write_text('raise RuntimeError("live companion imported")\n')
        helper.write_bytes(b"changed export helper")
    else:
        shutil.rmtree(live)
    bootstrap = output / "bootstrap.py"
    bootstrap.write_text(
        """import sys
from types import SimpleNamespace
sys.modules["binaryninja"] = SimpleNamespace(execute_on_main_thread=lambda callback: callback())
sys.modules["PySide6.QtCore"] = SimpleNamespace(QTimer=SimpleNamespace(singleShot=lambda delay, callback: callback()))
"""
        + code
    )
    subprocess.run([sys.executable, str(bootstrap)], check=True)
    assert result.read_text() == "snapshot executed"
    assert hashes["probe_sha256"] == hashlib.sha256(original).hexdigest()
    assert hashes["launcher_sha256"] == hashlib.sha256(b"original launcher").hexdigest()
    assert (output / "sources/clrbhb_gui_probe.py").read_bytes() == original
    for relative, digest in hashes["companion_sha256"].items():
        assert hashlib.sha256((output / "sources" / relative).read_bytes()).hexdigest() == digest
    assert "binja_windbg_mcp/native/libbinja_binexport.dylib" in hashes["companion_sha256"]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing_branch",
        "missing_middle",
        "wrong_length",
        "wrong_address",
        "extra_instruction",
        "short_bounds",
        "extra_block",
        "truncated",
        "missing_il",
    ],
)
def test_endpoint_analysis_requires_three_instructions_and_exact_bounds(fault):
    instructions = [{"address": hex(0x1000 + offset), "length": 4} for offset in (0, 4, 8)]
    function = {
        "found": True,
        "instructions": instructions,
        "instructions_truncated": False,
        "bounds": [["0x1000", "0x100c"]],
        "llil": ["SystemHintOp_CLRBHB()"],
    }
    if fault == "missing_branch":
        instructions.pop()
    elif fault == "missing_middle":
        instructions.pop(1)
    elif fault == "wrong_length":
        instructions[2]["length"] = 2
    elif fault == "wrong_address":
        instructions[2]["address"] = "0x100c"
    elif fault == "extra_instruction":
        instructions.append({"address": "0x100c", "length": 4})
    elif fault == "short_bounds":
        function["bounds"][0][1] = "0x1008"
    elif fault == "extra_block":
        function["bounds"].append(["0x2000", "0x2004"])
    elif fault == "truncated":
        function["instructions_truncated"] = True
    elif fault == "missing_il":
        function["llil"] = None
    assert gui.endpoint_analysis_complete({"address": "0x1000", "function": function}) is (
        fault is None
    )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "single_row",
        "missing_side",
        "duplicate",
        "wrong_reference",
        "wrong_target",
        "text_truncated",
        "blank_text",
        "function_truncated",
    ],
)
def test_endpoint_diff_requires_three_complete_paired_rows(fault):
    match = {
        side: {"coordinate": {"rva": hex(base)}}
        for side, base in (("reference", 0x1000), ("target", 0x2000))
    }
    rows = [
        {
            side: {"rva": hex(base + offset), "text": "instruction", "text_truncated": False}
            for side, base in (("reference", 0x1000), ("target", 0x2000))
        }
        for offset in (0, 4, 8)
    ]
    diff = {
        "items": rows,
        "truncated": False,
        "next_offset": None,
        "instructions_truncated": {"reference": False, "target": False},
    }
    if fault == "single_row":
        del rows[1:]
    elif fault == "missing_side":
        rows[-1]["reference"] = None
    elif fault == "duplicate":
        rows[-1] = copy.deepcopy(rows[0])
    elif fault == "wrong_reference":
        rows[-1]["reference"]["rva"] = "0x3000"
    elif fault == "wrong_target":
        rows[-1]["target"]["rva"] = "0x3000"
    elif fault == "text_truncated":
        rows[-1]["target"]["text_truncated"] = True
    elif fault == "blank_text":
        rows[-1]["reference"]["text"] = " "
    elif fault == "function_truncated":
        diff["instructions_truncated"]["reference"] = True
    assert gui.endpoint_diff_complete(diff, match) is (fault is None)
