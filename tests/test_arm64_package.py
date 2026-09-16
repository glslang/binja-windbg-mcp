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
    monkeypatch.setattr(builder, "verify_arm64_executable", lambda executable: None)
    monkeypatch.setattr(builder.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(builder.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(builder.platform, "mac_ver", lambda: ("13.0", ("", "", ""), "arm64"))
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


@pytest.mark.parametrize("system,machine", [("Darwin", "x86_64"), ("Linux", "arm64")])
@pytest.mark.parametrize("existing", [False, True])
def test_incompatible_host_does_not_modify_profile(inputs, monkeypatch, system, machine, existing):
    package, profile, installation = inputs
    monkeypatch.setattr(builder.platform, "system", lambda: system)
    monkeypatch.setattr(builder.platform, "machine", lambda: machine)
    if existing:
        profile.mkdir()
        (profile / "settings.json").write_text('{"unrelated": true}\n')
    with pytest.raises(ValueError, match="native arm64 Python"):
        builder.install(package, profile, installation)
    if existing:
        assert list(profile.iterdir()) == [profile / "settings.json"]
        assert (profile / "settings.json").read_text() == '{"unrelated": true}\n'
    else:
        assert not profile.exists()


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_partial_copy_never_publishes_plugin_or_receipt(inputs, monkeypatch, failure):
    package, profile, installation = inputs
    profile.mkdir()
    settings = profile / "settings.json"
    settings.write_text('{"unrelated": true}\n')

    def partial_copy(source, destination):
        Path(destination).write_bytes(b"partial")
        raise failure("interrupted")

    monkeypatch.setattr(builder.shutil, "copy2", partial_copy)
    with pytest.raises(failure):
        builder.install(package, profile, installation)
    assert list((profile / "plugins").iterdir()) == []
    assert not (profile / builder.RECEIPT).exists()
    assert settings.read_text() == '{"unrelated": true}\n'


def test_copied_plugin_is_verified_before_publication(inputs, monkeypatch):
    package, profile, installation = inputs
    monkeypatch.setattr(builder.shutil, "copy2", lambda src, dst: Path(dst).write_bytes(b"changed"))
    with pytest.raises(ValueError, match="copied plugin hash mismatch"):
        builder.install(package, profile, installation)
    assert list((profile / "plugins").iterdir()) == []
    assert not (profile / builder.RECEIPT).exists()
    assert not (profile / "settings.json").exists()


@pytest.mark.parametrize("stage", ["rename", "settings"])
def test_install_interruption_after_receipt_is_removable(inputs, monkeypatch, stage):
    package, profile, installation = inputs
    original_write = builder.write_json
    original_replace = Path.replace

    def replace(source, target):
        if Path(target).name == builder.PLUGIN:
            assert json.loads((profile / "settings.json").read_text())[builder.SETTING] is False
            if stage == "rename":
                raise OSError("rename interrupted")
        return original_replace(source, target)

    def write(path, value):
        if stage == "settings" and path.name == "settings.json":
            assert not (profile / "plugins" / builder.PLUGIN).exists()
            raise OSError("settings interrupted")
        return original_write(path, value)

    with monkeypatch.context() as failures:
        failures.setattr(Path, "replace", replace)
        failures.setattr(builder, "write_json", write)
        with pytest.raises(OSError, match="interrupted"):
            builder.install(package, profile, installation)
    assert (profile / builder.RECEIPT).exists()
    builder.uninstall(profile)
    assert list((profile / "plugins").iterdir()) == []
    assert not (profile / builder.RECEIPT).exists()


def source_archive(path, files):
    with tarfile.open(path, "w") as out:
        for name, value in files.items():
            item = tarfile.TarInfo("archive-root/" + name)
            item.size = len(value)
            out.addfile(item, io.BytesIO(value))


def test_rebuild_uses_verified_archives_and_fresh_sources(inputs, monkeypatch, tmp_path):
    from types import SimpleNamespace

    _, _, installation = inputs
    root = tmp_path / "repo"
    work = tmp_path / "work"
    (root / "native/arm64").mkdir(parents=True)
    (root / "native/arm64/README.md").write_text("test readme")
    patch = root / "native/arm64/clrbhb.patch"
    patch.write_text(
        "--- a/arch/arm64/entry.c\n+++ b/arch/arm64/entry.c\n@@ -1 +1 @@\n-original\n+patched\n"
    )
    sdk_archive = tmp_path / "sdk.tar"
    fmt_archive = tmp_path / "fmt.tar"
    source_archive(sdk_archive, {"arch/arm64/entry.c": b"original\n", "LICENSE.txt": b"SDK"})
    source_archive(fmt_archive, {"LICENSE": b"FMT"})
    monkeypatch.setattr(builder, "SDK_SHA256", builder.digest(sdk_archive))
    monkeypatch.setattr(builder, "FMT_SHA256", builder.digest(fmt_archive))
    monkeypatch.setattr(builder, "__file__", str(root / "tools/build_arm64.py"))
    # The old cache marker matches, but its source has been modified.
    legacy = work / "sdk/arch/arm64/entry.c"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("untrusted\n")
    builder.write_json(
        work / "source.json",
        {
            "sdk_revision": builder.SDK_REVISION,
            "patch_sha256": builder.digest(patch),
            "fmt_revision": builder.FMT_REVISION,
        },
    )
    real_run = builder.subprocess.run
    sources = []

    def run(command, **kwargs):
        if command[0] == "git":
            return real_run(command, **kwargs)
        assert command[0] == "test-cmake"
        if "-S" in command:
            source = Path(command[command.index("-S") + 1])
            sources.append(source)
            assert (source / "entry.c").read_text() == "patched\n"
            assert (source.parents[1] / "vendor/fmt/LICENSE").read_bytes() == b"FMT"
            build = Path(command[command.index("-B") + 1])
            assert not build.exists()
            build.mkdir()
            (build / builder.PLUGIN).write_bytes(b"compiled")
            # A generated/edit artifact must never be trusted by the next invocation.
            (source / "entry.c").write_text("modified after configure\n")
        return None

    monkeypatch.setattr(builder.subprocess, "run", run)
    args = SimpleNamespace(
        bn_install=installation,
        build_dir=work,
        sdk_archive=sdk_archive,
        fmt_archive=fmt_archive,
        cmake="test-cmake",
        jobs=1,
    )
    builder.build(args)
    builder.build(args)
    assert len(sources) == 2 and sources[0] != sources[1]
    assert not any(source.exists() for source in sources)
    assert legacy.read_text() == "untrusted\n"
    assert builder.read_package(root / "dist/arm64-clrbhb-bn6-abi187-macos-arm64")
    sdk_archive.write_bytes(b"tampered cached archive")
    with pytest.raises(ValueError, match="source archive hash mismatch"):
        builder.build(args)
    assert len(sources) == 2  # Refused before invoking the compiler.


@pytest.mark.parametrize("release", ["11.0", "12.7.6", "", "unknown", "13.bad"])
@pytest.mark.parametrize("existing", [False, True])
def test_unsupported_macos_leaves_profile_unchanged(inputs, monkeypatch, release, existing):
    package, profile, installation = inputs
    monkeypatch.setattr(builder.platform, "mac_ver", lambda: (release, (), "arm64"))
    if existing:
        profile.mkdir()
        (profile / "settings.json").write_text('{"unrelated": true}\n')
    with pytest.raises(ValueError, match="macOS"):
        builder.install(package, profile, installation)
    if existing:
        assert list(profile.iterdir()) == [profile / "settings.json"]
        assert (profile / "settings.json").read_text() == '{"unrelated": true}\n'
    else:
        assert not profile.exists()


@pytest.mark.parametrize("release", ["13.0", "13.6.9", "14.0", "26.0"])
def test_minimum_and_newer_macos_allow_install(inputs, monkeypatch, release):
    package, profile, installation = inputs
    monkeypatch.setattr(builder.platform, "mac_ver", lambda: (release, (), "arm64"))
    builder.install(package, profile, installation)
    assert (profile / "plugins" / builder.PLUGIN).read_bytes() == b"test-library"
    assert json.loads((profile / "settings.json").read_text())[builder.SETTING] is False
    builder.uninstall(profile)


@pytest.mark.parametrize("returncode", [0, 1])
def test_executable_architecture_uses_selected_app(tmp_path, monkeypatch, returncode):
    from types import SimpleNamespace
    from unittest.mock import Mock

    executable = tmp_path / "Selected.app/Contents/MacOS/binaryninja"
    run = Mock(return_value=SimpleNamespace(returncode=returncode))
    monkeypatch.setattr(builder.subprocess, "run", run)
    if returncode:
        with pytest.raises(ValueError, match="arm64 slice"):
            builder.verify_arm64_executable(executable)
    else:
        builder.verify_arm64_executable(executable)
    run.assert_called_once_with(
        ["/usr/bin/lipo", "-verify_arch", "arm64", str(executable)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("existing", [False, True])
def test_incompatible_app_leaves_profile_unchanged(inputs, monkeypatch, existing):
    package, profile, installation = inputs
    checked = []

    def reject(executable):
        checked.append(executable)
        raise ValueError("selected Binary Ninja executable must contain an arm64 slice")

    monkeypatch.setattr(builder, "verify_arm64_executable", reject)
    if existing:
        profile.mkdir()
        (profile / "settings.json").write_text('{"unrelated": true}\n')
    with pytest.raises(ValueError, match="arm64 slice"):
        builder.install(package, profile, installation)
    assert checked == [installation / "Contents/MacOS/binaryninja"]
    if existing:
        assert list(profile.iterdir()) == [profile / "settings.json"]
        assert (profile / "settings.json").read_text() == '{"unrelated": true}\n'
    else:
        assert not profile.exists()


@pytest.mark.parametrize("previous", [None, True, False])
@pytest.mark.parametrize("stage", ["remove", "restore"])
def test_interrupted_uninstall_never_enables_both_providers(inputs, monkeypatch, previous, stage):
    package, profile, installation = inputs
    profile.mkdir()
    original_settings = {"unrelated": True}
    if previous is not None:
        original_settings[builder.SETTING] = previous
    settings_file = profile / "settings.json"
    builder.write_json(settings_file, original_settings)
    builder.install(package, profile, installation)
    target = profile / "plugins" / builder.PLUGIN
    original_unlink = Path.unlink

    def unlink(path, *args, **kwargs):
        if path == target:
            assert json.loads(settings_file.read_text())[builder.SETTING] is False
            if stage == "remove":
                raise OSError("removal interrupted")
        return original_unlink(path, *args, **kwargs)

    def restore(path, value):
        assert not target.exists()
        assert (profile / builder.RECEIPT).exists()
        raise OSError("settings restore interrupted")

    with monkeypatch.context() as failures:
        failures.setattr(Path, "unlink", unlink)
        failures.setattr(builder, "write_json", restore)
        with pytest.raises(OSError, match="interrupted"):
            builder.uninstall(profile)
    assert json.loads(settings_file.read_text())[builder.SETTING] is False
    assert target.exists() is (stage == "remove")
    assert (profile / builder.RECEIPT).exists()
    builder.uninstall(profile)
    assert not target.exists()
    assert not (profile / builder.RECEIPT).exists()
    assert json.loads(settings_file.read_text()) == original_settings
