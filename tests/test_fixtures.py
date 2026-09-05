"""Replay real captures when present; never substitute synthetic data for acceptance."""

import json
from pathlib import Path

import pytest

from binja_windbg_mcp.analysis import ioctl_map
from binja_windbg_mcp.core import Budget


@pytest.mark.parametrize("path", sorted(Path(__file__).with_name("fixtures").glob("*.json")))
def test_real_driver_capture(path):
    fixture = json.loads(path.read_text())
    assert len(bytes.fromhex(fixture["file_sha256"])) == 32
    assert fixture["analysis_version"].startswith("5.3.")
    assert fixture["capture"]["architecture"] == fixture["architecture"]
    actual = ioctl_map(fixture["capture"], Budget())["cases"]

    def project(case):
        return case["code"], case["dispatch_rva"], case["case_rva"]

    assert sorted(map(project, actual)) == sorted(map(project, fixture["expected_mappings"]))
