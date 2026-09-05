"""Run capture_fixture(bv, path) from Binary Ninja's Python console, after analysis."""

import json
from pathlib import Path

from .adapter import capture_driver
from .core import Budget, original_hash, pe_identity


def capture_fixture(view, path, expected_mappings):
    """Write a real adapter capture with independently reviewed code-to-handler expectations.

    Invoke from a Binary Ninja background task with an active-job reference to bv.
    expected_mappings is a list of {code, dispatch_rva, case_rva} records reviewed in the UI.
    This helper is not an MCP tool and never acquires binaries or changes their analysis.
    """
    identity, architecture = pe_identity(view.file.raw.read)
    digest = original_hash(view)
    if digest is None:
        raise ValueError("capture requires recoverable original file bytes and a pinned SHA-256")
    capture = capture_driver(view, Budget(120))
    if capture.get("truncated"):
        raise ValueError("capture is incomplete; do not publish it as a complete fixture")
    record = {
        "capture": capture,
        "file_sha256": digest,
        "architecture": architecture,
        "identity": identity.model_dump(),
        "expected_mappings": expected_mappings,
        "analysis_version": capture["analysis_version"],
    }
    destination = Path(path)
    with destination.open("x") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    return str(destination)
