import copy
import os
import struct

import pytest

from binja_windbg_mcp.analysis import driver_surface, ioctl_map, sink_imports
from binja_windbg_mcp.core import (
    Budget,
    Coordinate,
    Identity,
    compare_bytes,
    ioctl_case,
    pe_identity,
)
from binja_windbg_mcp.profiles import Profiles, validate_url
from binja_windbg_mcp.server import GROUPS, selected_tools


def test_rebased_coordinate_and_identity():
    identity = Identity(timestamp=10, size=4096)
    value = Coordinate(module="driver", image_name="driver.sys", identity=identity, rva="0x123")
    assert value.address(0xFFFF800000000000, identity) == 0xFFFF800000000123
    assert value.address(0x1000, identity) == 0x1123
    with pytest.raises(ValueError):
        value.address(0, Identity(timestamp=11, size=4096))
    with pytest.raises(ValueError):
        value.address(0, identity, 4096)
    with pytest.raises(ValueError):
        value.address(2**64 - 1, identity)


def test_pe_header_uses_raw_offsets():
    image = bytearray(512)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 60, 128)
    image[128:132] = b"PE\0\0"
    struct.pack_into("<H", image, 132, 0x8664)
    struct.pack_into("<I", image, 136, 1234)
    struct.pack_into("<H", image, 148, 240)
    struct.pack_into("<H", image, 152, 0x20B)
    struct.pack_into("<I", image, 208, 0xA000)
    identity, arch = pe_identity(lambda offset, size: image[offset : offset + size])
    assert identity == Identity(timestamp=1234, size=0xA000)
    assert arch == "x86_64"
    with pytest.raises(ValueError):
        pe_identity(lambda offset, size: b"")


def capture():
    return {
        "entry_rva": "0x1000",
        "imports": {"ProbeForRead": "0x9000", "WdfVersionBind": "0x9010"},
        "types": {"missing": ["_DRIVER_OBJECT"]},
        "functions": [
            {"rva": "0x1000", "registrations": [{"major_function": 14, "callback_rva": "0x2000"}]},
            {
                "rva": "0x2000",
                "control_cases": [
                    {
                        "input": "Parameters.DeviceIoControl.IoControlCode",
                        "code": 0x22E004,
                        "site": "0x2100",
                        "evidence": [{"kind": "minimum_size", "size": 8}],
                    },
                    {
                        "input": "Parameters.DeviceIoControl.IoControlCode",
                        "code": 0x22E004,
                        "site": "0x2200",
                    },
                ],
                "calls": [{"name": "helper", "site": "0x2300", "target_rva": "0x3000"}],
            },
            {"rva": "0x3000", "calls": [{"name": "ProbeForRead", "site": "0x3100"}]},
        ],
    }


def test_ctl_decoding_and_conditional_sizes():
    case = ioctl_case(0x22E004, 0x2000, 0x2100)
    assert case["required_access"] == "read_write"
    assert case["function"] == 0x801
    result = ioctl_map(capture(), Budget())
    assert len(result["cases"]) == 2
    assert result["cases"][0]["in_size"] is None
    assert "predicted_reachable" not in result["cases"][0]
    assert result["traversal"]["enabled"] is False


def test_sink_paths_bounded_and_composite_partial():
    result = driver_surface(capture(), Budget(), depth=0)
    assert result["driver_entry"]["unresolved_callbacks"]
    assert result["sink_imports"]["status"] == "success"
    assert result["ioctl_map"]["traversal"]["truncated"]
    assert (
        ioctl_map(capture(), Budget(), traverse=True)["traversal"]["paths"][0]["sink"]
        == "ProbeForRead"
    )
    for kwargs in ({"depth": 9}, {"function_limit": 1025}, {"function_limit": 0}):
        with pytest.raises(ValueError):
            ioctl_map(capture(), Budget(), **kwargs)


def test_unknown_input_not_an_ioctl_and_capture_immutable():
    data = capture()
    data["functions"][1]["control_cases"][0]["input"] = "unknown"
    original = copy.deepcopy(data)
    assert len(ioctl_map(data, Budget())["cases"]) == 1
    assert data == original
    budget = Budget()
    budget.cancel.set()
    with pytest.raises(InterruptedError):
        sink_imports(data, budget)


def test_partial_comparison_and_relocations():
    result = compare_bytes(b"\x00\x11", b"\x00\x22", 3, [{"offset": 1, "size": 8}])
    assert result["differing_offsets"] == [1]
    assert result["incomplete"] and not result["equal"]
    assert result["runtime_data"] == "0022"


def test_profiles_private_and_url_policy(tmp_path):
    profiles = Profiles(tmp_path)
    assert len(bytes.fromhex(profiles.token)) == 32
    assert os.stat(profiles.path).st_mode & 0o777 == 0o600
    assert Profiles(tmp_path).token == profiles.token
    os.chmod(profiles.path, 0o644)
    with pytest.raises(ValueError):
        Profiles(tmp_path)
    for url in (
        "http://remote/mcp",
        "https://user:secret@remote/mcp",
        "https://remote/mcp?token=a",
        "file:///mcp",
    ):
        with pytest.raises(ValueError):
            validate_url(url)
    assert validate_url("https://remote/mcp")
    assert validate_url("http://127.0.0.1:8765/mcp")


def test_profiles_symlink_refused(tmp_path):
    (tmp_path / "profiles.json").symlink_to(tmp_path / "absent")
    with pytest.raises(OSError):
        Profiles(tmp_path)


def test_groups_exactly_once():
    names = [name for group in GROUPS.values() for name in group]
    assert len(names) == len(set(names)) == 16
    assert selected_tools("debug") == set(GROUPS["workspace"] + GROUPS["pair"] + GROUPS["debug"])
    with pytest.raises(ValueError):
        selected_tools("typo")


def test_pdb_matching_rejects_unmatched_and_age_mismatch():
    identity = Identity(timestamp=1, size=4096, pdb={"guid": "ABCD", "age": 1})
    coordinate = Coordinate(module="driver", image_name="driver.sys", identity=identity, rva="0x1")
    assert (
        coordinate.address(0, Identity(timestamp=1, size=4096, pdb={"guid": "abcd", "age": 1})) == 1
    )
    for pdb in ({"guid": "ABCD", "age": 2}, {"guid": "ABCD", "age": 1, "unmatched": True}):
        with pytest.raises(ValueError):
            coordinate.address(0, Identity(timestamp=1, size=4096, pdb=pdb))


@pytest.mark.parametrize("spec", ["analysis", "edit", "workspace,edit", "debug,analysis"])
def test_retired_groups_explain_native_mcp_migration(spec):
    with pytest.raises(ValueError, match="retired.*native MCP"):
        selected_tools(spec)


def test_original_hash_uses_binary_view_length_and_rejects_partial_or_modified_bytes():
    import hashlib
    from types import SimpleNamespace as N

    from binja_windbg_mcp.core import original_hash

    data = b"x" * (1024 * 1024 + 3)
    raw = N(
        length=len(data), modified=False, read=lambda offset, size: data[offset : offset + size]
    )
    view = N(file=N(raw=raw, filename="driver.sys"))
    assert original_hash(view) == hashlib.sha256(data).hexdigest()
    raw.read = lambda offset, size: b""
    assert original_hash(view) is None
    raw.modified = True
    assert original_hash(view) is None
    raw.modified = False
    view.file.filename = "driver.bndb"
    assert original_hash(view) is None
