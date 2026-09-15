"""Offline regressions for endpoint correspondence and retained probe execution."""

import copy
import gzip
import hashlib
import importlib.util
import json
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
    similarity.diff.return_value = {
        "items": [{"text": "complete"}],
        "next_offset": None,
        "instructions_truncated": {"reference": False, "target": False},
    }
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
    original = b'from pathlib import Path\ndef start(path):\n    Path(path).write_text("snapshot executed")\n'
    probe.write_bytes(original)
    output = tmp_path / "capture"
    output.mkdir()
    result = output / "result.txt"
    code, hashes = launcher_module.snapshot_probe(output, launcher, [live], result)
    if checkout_change == "edited":
        probe.write_text('raise RuntimeError("live checkout was imported")\n')
        launcher.write_text("changed launcher")
    else:
        probe.unlink()
        launcher.unlink()
        live.rmdir()
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
