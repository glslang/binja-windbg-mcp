"""Opt-in GUI smoke test with disposable, synthetic x86-64 PE fixtures.

Run start(bindiff_path, new_output_directory) from an empty BN6 GUI's Python console.
The probe leaves its views open and writes result.json; it never starts WinDbg.
"""

import json
import struct
import threading
import time
import traceback
from pathlib import Path

import binaryninja as bn
from binaryninjaui import UIContext
from PySide6.QtCore import QCoreApplication, QTimer


def fixture(path, base, changed=False):
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 1 + changed, 0, 0, 240, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 4, 512)
    struct.pack_into("<IIQ", data, opt + 16, 0x1000, 0x1000, base)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HH", data, opt + 40, 6, 0)
    struct.pack_into("<HH", data, opt + 48, 6, 0)
    struct.pack_into("<II", data, opt + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<QQQQ", data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", data, opt + 108, 16)
    sec = opt + 240
    data[sec : sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, sec + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, sec + 36, 0x60000020)
    data[0x200:0x206] = b"\xe8\x1b\x00\x00\x00\xc3"
    data[0x220:0x226] = b"\xb8\x01\x00\x00\x00\xc3"
    if changed:
        data[0x205:0x20B] = b"\xe8\x36\x00\x00\x00\xc3"
        data[0x220:0x226] = b"\x31\xc0\xff\xc0\x90\xc3"
        data[0x240:0x248] = b"\x50\x51\x31\xc0\x59\x58\x90\xc3"
    path.write_bytes(data)


def _run(root, bindiff_path, quit_on_finish):
    report = {"version": bn.core_version()}
    workspace = None
    try:
        from binja_windbg_mcp.adapter import Workspace, main_thread

        for name, base, changed in [
            ("reference", 0x140000000, False),
            ("identical", 0x140000000, False),
            ("relocated", 0x180000000, False),
            ("changed", 0x140000000, True),
        ]:
            path = root / (name + ".exe")
            fixture(path, base, changed)

            def open_fixture():
                context = UIContext.activeContext()
                if context is None:
                    contexts = list(UIContext.allContexts())
                    if len(contexts) != 1:
                        raise RuntimeError("Expected one GUI context")
                    context = contexts[0]
                return context.openFilename(str(path))

            assert main_thread(open_fixture), "could not open fixture"
        workspace = Workspace()
        backend = workspace.similarity.backend.backends["external"]
        backend.configure(str(bindiff_path))
        binaries = workspace.list_binaries()["binaries"]
        assert len(binaries) == 4, binaries
        for item in binaries:
            _, view, _, _ = workspace.acquire(item["binary_id"])
            view.update_analysis_and_wait()
        before = workspace.list_binaries()["binaries"]
        analysis_before = analysis_state(workspace, before)
        ids = {b["image_name"].split(".")[0]: b["binary_id"] for b in before}
        report["capabilities"] = workspace.similarity.status()["capabilities"]
        report["comparisons"] = {}
        for target in ("identical", "relocated", "changed"):
            job = workspace.similarity.start(ids["reference"], ids[target], backend="external")
            while workspace.similarity.status(job["comparison_id"])["active"]:
                time.sleep(0.05)
            result = workspace.similarity.results(job["comparison_id"])
            result["unmatched"] = {
                side: workspace.similarity.results(
                    job["comparison_id"], side=side, kind="unmatched"
                )["items"]
                for side in ("reference", "target")
            }
            result["diffs"] = [
                workspace.similarity.diff(job["comparison_id"], row["result_id"])
                for row in result["items"]
            ]
            from binja_windbg_mcp.core import Coordinate

            endpoint = result["items"][0]["target"] if result["items"] else None
            if endpoint:
                result["navigation"] = workspace.navigate(
                    endpoint["binary_id"],
                    Coordinate.model_validate(endpoint["coordinate"]),
                    expected_generation=endpoint["generation"],
                )
            report["comparisons"][target] = result
            assert result["state"] == "completed", result
            assert result["items"], "no matches"
            workspace.similarity.close(job["comparison_id"])
        after = workspace.list_binaries()["binaries"]
        report["unchanged"] = all(
            all(
                a[k] == next(b for b in after if b["binary_id"] == a["binary_id"])[k]
                for k in ("generation", "identity", "modified", "file_sha256")
            )
            for a in before
        )
        assert report["unchanged"]
        report["analysis_unchanged"] = analysis_before == analysis_state(workspace, after)
        assert report["analysis_unchanged"]
        report["ok"] = True
    except Exception:
        report["error"] = traceback.format_exc()
    finally:
        if workspace:
            workspace.shutdown()
        (root / "result.json").write_text(json.dumps(report, indent=2))
        if quit_on_finish:
            bn.execute_on_main_thread(lambda: QCoreApplication.instance().quit())


def analysis_state(workspace, binaries):
    result = {}
    for item in binaries:
        _, view, _, _ = workspace.acquire(item["binary_id"])
        result[item["binary_id"]] = {
            "functions": [(f.start, f.name, str(f.type), dict(f.comments)) for f in view.functions],
            "bytes": view.read(view.start, view.end - view.start).hex(),
            "types": {str(k): str(v) for k, v in view.types.items()},
        }
    return result


def start(bindiff_path, output_directory, quit_on_finish=False):
    """Run from BN's Python console in an empty GUI; output_directory must be new."""
    from binaryninjaui import FileContext

    if FileContext.getOpenFileContexts():
        raise ValueError("Run this smoke test in an empty Binary Ninja window/process")
    root = Path(output_directory).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    QTimer.singleShot(
        100,
        lambda: threading.Thread(
            target=_run, args=(root, Path(bindiff_path).resolve(), quit_on_finish), daemon=True
        ).start(),
    )
