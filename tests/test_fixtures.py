"""Replay real captures when present; never substitute synthetic data for acceptance."""

import json
from pathlib import Path

import pytest

from binja_windbg_mcp.analysis import driver_surface, ioctl_map
from binja_windbg_mcp.core import Budget


@pytest.mark.parametrize("path", sorted(Path(__file__).with_name("fixtures").glob("*.json")))
def test_real_driver_capture(path):
    fixture = json.loads(path.read_text())
    assert len(bytes.fromhex(fixture["file_sha256"])) == 32
    assert fixture["analysis_version"] == fixture["capture"]["analysis_version"]
    assert fixture["analysis_version"].startswith("6.")
    assert fixture["capture"]["architecture"] == fixture["architecture"]
    actual = ioctl_map(fixture["capture"], Budget())["cases"]

    def project(case):
        return case["code"], case["dispatch_rva"], case["case_rva"]

    assert sorted(map(project, actual)) == sorted(map(project, fixture["expected_mappings"]))


def test_hevd_capture_preserves_partial_analysis_and_independent_sections():
    fixture = json.loads(
        Path(__file__).with_name("fixtures").joinpath("hevd-arm64-bn6-partial.json").read_text()
    )
    result = driver_surface(fixture["capture"], Budget())
    assert result["driver_entry"]["status"] == "success"
    assert (
        sorted(
            [root["major_function"], root["callback_rva"]]
            for root in result["driver_entry"]["roots"]
        )
        == fixture["expected_roots"]
    )
    assert result["ioctl_map"]["status"] == fixture["expected_ioctls_status"]
    assert result["ioctl_map"]["unresolved"] == fixture["expected_unresolved"]
    assert (
        sorted(sink["name"] for sink in result["sink_imports"]["imports"])
        == fixture["expected_sink_imports"]
    )
    assert (
        result["device_security"]["creation_and_namespace_calls"][0]["device_characteristics"]
        == 0x100
    )
    traversal = result["ioctl_map"]["traversal"]
    assert traversal["depth"] == 2 and traversal["visited"] == 57
    assert traversal["truncated"] and traversal["paths"]


def test_current_hevd_fixture_recovers_all_reviewed_cases_without_inventing_sizes():
    fixture = json.loads(
        Path(__file__).with_name("fixtures").joinpath("hevd-arm64-bn6-ioctls.json").read_text()
    )
    result = ioctl_map(fixture["capture"], Budget())
    assert result["status"] == "success" and result["unresolved"] == []
    assert sorted(int(case["code"], 16) for case in result["cases"]) == list(
        range(0x222003, 0x222074, 4)
    )
    assert all(case["in_size"] is None and case["out_size"] is None for case in result["cases"])
    assert result["traversal"]["enabled"] is False
    composite = driver_surface(fixture["capture"], Budget())
    assert len(composite["ioctl_map"]["cases"]) == 29
    assert composite["ioctl_map"]["traversal"]["truncated"]  # Same intentional depth boundary.
