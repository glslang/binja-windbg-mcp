"""GUI-side probes. Import only inside the owned process from bn_followup_probe.py."""

import ctypes
import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

CLRBHB = bytes.fromhex("df2203d5")
SYNTHETIC = CLRBHB + bytes.fromhex("00040091c0035fd6")  # add x0, x0, #1; ret
INPUT_HASHES = {
    "reference": "65a014d83be9d2262e913d020425dc9bf0a301b6403dffa13e6fe7ae5460a57b",
    "target": "9a2eeb0e4a3d76aa9a6bfaf287540f5f1f7562d814e8ecb3c3f6df6b57a557b6",
}


def decode_instruction(arch, data, address):
    info = arch.get_instruction_info(data, address)
    text = arch.get_instruction_text(data, address)
    return {
        "address": hex(address),
        "bytes": data[:4].hex(),
        "length": info.length if info else None,
        "branches": [str(b.type) for b in info.branches] if info else None,
        "text": "".join(str(t) for t in text[0]) if text else None,
        "text_length": text[1] if text else None,
    }


def decoded_clrbhb(row):
    return (
        row["bytes"] == CLRBHB.hex()
        and row["length"] == 4
        and row["text_length"] == 4
        and row["branches"] == []
        and (row["text"] or "").strip().casefold() == "clrbhb"
    )


def endpoint_analysis_complete(row):
    function = row.get("function", {})
    instructions = function.get("instructions", [])
    return (
        function.get("found") is True
        and not function.get("instructions_truncated")
        and any(int(i["address"], 16) == int(row["address"], 16) + 4 for i in instructions)
        and any("SystemHintOp_CLRBHB" in i for i in function.get("llil", []))
    )


def function_evidence(view, address):
    function = view.get_function_at(address)
    if function is None:
        return {"address": hex(address), "found": False}
    instructions = []
    for block in function.basic_blocks:
        at = block.start
        for tokens, size in block:
            instructions.append(
                {
                    "address": hex(at),
                    "length": size,
                    "text": "".join(str(t) for t in tokens),
                }
            )
            at += size
            if len(instructions) >= 256:
                break
        if len(instructions) >= 256:
            break
    il = function.low_level_il
    return {
        "address": hex(address),
        "found": True,
        "name": function.name,
        "bounds": [[hex(b.start), hex(b.end)] for b in function.basic_blocks],
        "instructions": instructions,
        "instructions_truncated": len(instructions) >= 256,
        "llil": [str(i) for block in il for i in block][:256] if il is not None else None,
    }


def state(workspace, binaries):
    result = {}
    for item in binaries:
        _, view, _, _ = workspace.acquire(item["binary_id"])
        analysis = {
            "functions": [
                [f.start, f.name, str(f.type), sorted(f.comments.items())]
                for f in sorted(view.functions, key=lambda f: f.start)
            ],
            "types": sorted((str(k), str(v)) for k, v in view.types.items()),
        }
        digest = hashlib.sha256()
        for segment in sorted(view.segments, key=lambda s: s.start):
            for address in range(segment.start, segment.end, 1024 * 1024):
                digest.update(address.to_bytes(8, "little"))
                digest.update(view.read(address, min(1024 * 1024, segment.end - address)))
        result[item["binary_id"]] = {
            "analysis_sha256": hashlib.sha256(
                json.dumps(analysis, sort_keys=True).encode()
            ).hexdigest(),
            "bytes_sha256": digest.hexdigest(),
            "function_count": len(analysis["functions"]),
        }
    return result


def pages(method, *args, **kwargs):
    rows, offset = [], 0
    while True:
        result = method(*args, offset=offset, limit=100, **kwargs)
        rows.extend(result["items"])
        following = result["next_offset"]
        if following is None:
            return rows
        if following <= offset:
            raise RuntimeError("pagination did not advance")
        offset = following


def full_acceptance(status, analysis_unchanged, inputs_unchanged):
    return (
        status["state"] == "completed"
        and status["coverage_complete"]
        and analysis_unchanged
        and inputs_unchanged
    )


def endpoint_matches(matches):
    expected = {(0x10FC00 + offset, 0x11AC00 + offset) for offset in range(0, 0x400, 0x80)}
    targets = {target for _, target in expected}
    selected = [row for row in matches if int(row["target"]["coordinate"]["rva"], 16) in targets]
    actual = {
        (
            int(row["reference"]["coordinate"]["rva"], 16),
            int(row["target"]["coordinate"]["rva"], 16),
        )
        for row in selected
    }
    if len(selected) != len(expected) or actual != expected:
        raise ValueError("comparison must contain each of the eight expected endpoint pairs once")
    return selected


def compare_endpoints(workspace, config, report, save):
    comparison_id = None
    evidence = {"status": "failed"}
    report["comparison"] = evidence
    try:
        if not config.get("bindiff"):
            raise RuntimeError("external comparison requires a BinDiff path")
        workspace.similarity.backend.backends["external"].configure(config["bindiff"])
        before = workspace.list_binaries()["binaries"]
        ids = {}
        for binary in before:
            _, view, _, _ = workspace.acquire(binary["binary_id"])
            ids[Path(view.file.original_filename).resolve()] = binary["binary_id"]
        evidence["before"] = before
        evidence["analysis_before"] = state(workspace, before)
        started = workspace.similarity.start(
            ids[Path(config["reference"]).resolve()],
            ids[Path(config["target"]).resolve()],
            backend="external",
            providers=["Google BinDiff"],
            timeout_ms=120000,
        )
        comparison_id = started["comparison_id"]
        deadline = time.monotonic() + 150
        while True:
            status = workspace.similarity.status(comparison_id)
            if not status["active"]:
                break
            if time.monotonic() > deadline:
                raise TimeoutError("comparison deadline exceeded")
            time.sleep(0.1)
        evidence["result"] = status
        evidence["matches"] = pages(workspace.similarity.results, comparison_id)
        evidence["unmatched"] = {
            side: pages(workspace.similarity.results, comparison_id, side=side, kind="unmatched")
            for side in ("reference", "target")
        }
        selected = endpoint_matches(evidence["matches"])
        evidence["diffs"] = []
        for match in selected:
            diff = workspace.similarity.diff(comparison_id, match["result_id"], limit=1)
            diff["items"] = pages(workspace.similarity.diff, comparison_id, match["result_id"])
            diff["next_offset"], diff["truncated"] = None, False
            evidence["diffs"].append(diff)
            save()
        after = workspace.list_binaries()["binaries"]
        evidence["after"] = after
        evidence["analysis_after"] = state(workspace, after)
        unchanged = evidence["analysis_before"] == evidence["analysis_after"] and all(
            any(
                all(
                    a.get(k) == b.get(k)
                    for k in (
                        "binary_id",
                        "generation",
                        "identity",
                        "modified",
                        "file_sha256",
                    )
                )
                for a in after
            )
            for b in before
        )
        evidence["inputs_unchanged"] = unchanged
        text_complete = len(selected) == 8 and all(
            d["items"] and not any(d["instructions_truncated"].values()) for d in evidence["diffs"]
        )
        evidence["status"] = (
            "passed"
            if full_acceptance(status, unchanged, unchanged) and text_complete
            else "failed"
        )
    except Exception as error:
        evidence["error"] = type(error).__name__ + ": " + str(error)
    finally:
        save()
        if comparison_id:
            try:
                workspace.similarity.close(comparison_id)
            except Exception as error:
                evidence["cleanup_error"] = type(error).__name__
                evidence["status"] = "failed"
        save()
    return evidence["status"] == "passed"


def capture_decode(config, report, save):
    import binaryninja as bn
    from binaryninjaui import UIContext

    from binja_windbg_mcp.adapter import Workspace, main_thread
    from binja_windbg_mcp.similarity_adapter import NativeSimilarity

    report["replacement"] = loaded_replacement(config)
    arch = bn.Architecture["aarch64"]
    report["native_capabilities"] = NativeSimilarity(None).capabilities()
    report["synthetic_instruction"] = decode_instruction(arch, SYNTHETIC, 0x1000)
    synthetic = bn.BinaryView.new(SYNTHETIC)
    try:
        synthetic.platform = arch.standalone_platform
        synthetic.add_function(0)
        synthetic.update_analysis_and_wait()
        report["synthetic_function"] = function_evidence(synthetic, 0)
    finally:
        synthetic.file.close()
    report["native_decode_passed"] = decoded_clrbhb(report["synthetic_instruction"])
    report["synthetic_analysis_passed"] = len(
        report["synthetic_function"].get("instructions", [])
    ) == 3 and any("SystemHintOp_CLRBHB" in i for i in report["synthetic_function"]["llil"])
    save()
    report["endpoints"] = []
    workspace = None
    try:
        if config.get("reference"):
            for side in ("reference", "target"):
                path = config[side]
                if hashlib.sha256(Path(path).read_bytes()).hexdigest() != INPUT_HASHES[side]:
                    raise RuntimeError(
                        "endpoint RVAs require the recorded ARM64 Secure Kernel pair"
                    )

                def open_file(path=path):
                    (context,) = UIContext.allContexts()
                    return context.openFilename(path)

                if not main_thread(open_file):
                    raise RuntimeError("could not open selected PE in GUI")
            workspace = Workspace()
            for binary in workspace.list_binaries()["binaries"]:
                _, view, _, _ = workspace.acquire(binary["binary_id"])
                view.update_analysis_and_wait()
                path = Path(view.file.original_filename).resolve()
                side = "reference" if path == Path(config["reference"]).resolve() else "target"
                first = 0x10FC00 if side == "reference" else 0x11AC00
                report.setdefault("inputs", {})[side] = {
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "architecture": binary["architecture"],
                    "identity": binary["identity"],
                }
                for offset in range(8):
                    at = view.start + first + offset * 0x80
                    row = decode_instruction(view.arch, view.read(at, 12), at)
                    row.update(
                        {
                            "side": side,
                            "rva": hex(at - view.start),
                            "function": function_evidence(view, at),
                        }
                    )
                    report["endpoints"].append(row)
                save()
        report["endpoint_decoding_passed"] = len(report["endpoints"]) == 16 and all(
            decoded_clrbhb(row) for row in report["endpoints"]
        )
        report["endpoint_analysis_passed"] = len(report["endpoints"]) == 16 and all(
            endpoint_analysis_complete(row) for row in report["endpoints"]
        )
        # Full comparison is meaningful after native decoding succeeds. Keep the old
        # fallback capture as evidence when this prerequisite still fails.
        report["comparison"] = {
            "status": "not_run",
            "reason": "native decoding/analysis prerequisite not met",
        }
        prerequisites = (
            report["native_decode_passed"]
            and report["synthetic_analysis_passed"]
            and report["endpoint_decoding_passed"]
            and report["endpoint_analysis_passed"]
        )
        report["ok"] = prerequisites and compare_endpoints(workspace, config, report, save)
    finally:
        if workspace:
            workspace.shutdown()
        save()


def loaded_replacement(config):
    import binaryninja as bn

    dyld = ctypes.CDLL(None)
    dyld._dyld_image_count.restype = ctypes.c_uint32
    dyld._dyld_get_image_name.argtypes = [ctypes.c_uint32]
    dyld._dyld_get_image_name.restype = ctypes.c_char_p
    paths = [
        Path(dyld._dyld_get_image_name(i).decode()).resolve()
        for i in range(dyld._dyld_image_count())
    ]
    expected = Path(config["replacement"]).resolve()
    candidates = [p for p in paths if p.name == "libarch_arm64.dylib"]
    disabled = not bn.Settings().get_bool("corePlugins.architectures.aarch64")
    if candidates != [expected] or not disabled:
        raise RuntimeError(
            "expected only the replacement ARM64 plugin with bundled plugin disabled"
        )
    return {
        "path": str(expected),
        "sha256": hashlib.sha256(expected.read_bytes()).hexdigest(),
        "bundled_disabled": disabled,
        "loaded_arm64_images": [str(p) for p in candidates],
    }


def start(config_path):
    import binaryninja as bn
    from binaryninjaui import FileContext, UIContext
    from PySide6.QtWidgets import QApplication

    config = json.loads(Path(config_path).read_text())
    output = Path(config["output"])
    report = {
        "schema_version": 1,
        "ok": False,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "bn_version": bn.core_version(),
        "edition": bn.core_product_type(),
    }

    def save():
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")

    def finish():
        try:
            if QApplication.instance().activeModalWidget() is not None:
                raise RuntimeError("modal dialog blocks ordinary Quit")
            for context in FileContext.getOpenFileContexts():
                for view in context.getAllDataViews():
                    view.file.modified = False
            (context,) = UIContext.allContexts()
            handler = context.getCurrentActionHandler()
            if not handler.isValidAction("Quit"):
                raise RuntimeError("Quit action unavailable")
            handler.executeAction("Quit")
        except Exception as error:
            report["cleanup_error"] = str(error)
            report["ok"] = False
            save()

    def background():
        try:
            capture_decode(config, report, save)
        except Exception as error:
            report["error"] = type(error).__name__ + ": " + str(error)
            report["ok"] = False
        finally:
            save()
            bn.execute_on_main_thread(finish)

    threading.Thread(target=background, name="clrbhb-probe", daemon=True).start()
