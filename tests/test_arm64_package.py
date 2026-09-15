"""Offline checks for compatibility gates and reversible profile installation."""

import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "build_arm64", Path(__file__).resolve().parents[1] / "tools/build_arm64.py"
)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    installation = tmp_path / "Binary Ninja.app"
    revision = installation / "Contents/Resources/api_REVISION.txt"
    revision.parent.mkdir(parents=True)
    revision.write_text(builder.SDK_REVISION)
    package = tmp_path / "package"
    package.mkdir()
    (package / builder.PLUGIN).write_bytes(b"test-library")
    manifest = {
        "sdk_revision": builder.SDK_REVISION,
        "core_abi": 187,
        "platform": "macos-arm64",
        "plugin": builder.PLUGIN,
        "plugin_sha256": builder.digest(package / builder.PLUGIN),
    }
    builder.write_json(package / "manifest.json", manifest)
    monkeypatch.setattr(builder, "stopped", lambda: None)
    return package, tmp_path / "profile", installation


@pytest.mark.parametrize("previous", [None, True, False])
def test_install_uninstall_preserves_profile(inputs, previous):
    package, profile, installation = inputs
    profile.mkdir()
    settings = {"ui.allowWelcome": False}
    if previous is not None:
        settings[builder.SETTING] = previous
    builder.write_json(profile / "settings.json", settings)
    builder.install(package, profile, installation)
    installed = json.loads((profile / "settings.json").read_text())
    assert installed[builder.SETTING] is False
    installed["user.changed"] = 1
    builder.write_json(profile / "settings.json", installed)
    builder.uninstall(profile)
    assert json.loads((profile / "settings.json").read_text()) == {**settings, "user.changed": 1}
    assert not (profile / "plugins" / builder.PLUGIN).exists()
    assert not (profile / builder.RECEIPT).exists()


def test_mismatched_sdk_leaves_profile_absent(inputs):
    package, profile, installation = inputs
    (installation / "Contents/Resources/api_REVISION.txt").write_text("0" * 40)
    with pytest.raises(ValueError, match="pinned SDK"):
        builder.install(package, profile, installation)
    assert not profile.exists()


def test_tampered_package_leaves_profile_absent(inputs):
    package, profile, installation = inputs
    (package / builder.PLUGIN).write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        builder.install(package, profile, installation)
    assert not profile.exists()


def test_existing_plugin_is_not_replaced(inputs):
    package, profile, installation = inputs
    target = profile / "plugins" / builder.PLUGIN
    target.parent.mkdir(parents=True)
    target.write_bytes(b"another plugin")
    with pytest.raises(ValueError, match="existing replacement"):
        builder.install(package, profile, installation)
    assert target.read_bytes() == b"another plugin"
    assert not (profile / builder.RECEIPT).exists()


def test_changed_plugin_is_not_removed(inputs):
    package, profile, installation = inputs
    builder.install(package, profile, installation)
    target = profile / "plugins" / builder.PLUGIN
    target.write_bytes(b"changed externally")
    with pytest.raises(ValueError, match="unowned file"):
        builder.uninstall(profile)
    assert target.exists()
    assert (profile / builder.RECEIPT).exists()


def test_new_setting_is_not_overwritten_on_uninstall(inputs):
    package, profile, installation = inputs
    builder.install(package, profile, installation)
    builder.write_json(profile / "settings.json", {builder.SETTING: True})
    builder.uninstall(profile)
    assert json.loads((profile / "settings.json").read_text()) == {builder.SETTING: True}


@pytest.mark.parametrize("name,link", [("root/../escape", False), ("root/link", True)])
def test_archive_rejects_escape_and_links(tmp_path, name, link):
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as out:
        item = tarfile.TarInfo(name)
        if link:
            item.type = tarfile.SYMTYPE
            item.linkname = "/tmp/elsewhere"
            out.addfile(item)
        else:
            item.size = 1
            out.addfile(item, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="unsafe|link"):
        builder.extract(archive, tmp_path / "source")
    assert not (tmp_path / "escape").exists()
