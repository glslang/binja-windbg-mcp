import re
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace as N

import pytest

from binja_windbg_mcp import bootstrap

ROOT = Path(__file__).resolve().parents[1]


def test_extension_manager_requirements_match_hash_lock_and_project():
    requirements = bootstrap.read_requirements(ROOT / "requirements.txt")
    lock = (ROOT / "requirements.lock").read_text()
    assert requirements == re.findall(r"^([a-zA-Z0-9_.-]+==[^\s\\]+)", lock, re.M)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert set(project["dependencies"]) <= set(requirements)
    assert len(requirements) == len(set(requirements))


def installed_versions(monkeypatch, versions):
    def version(name):
        if name not in versions:
            raise bootstrap.metadata.PackageNotFoundError(name)
        return versions[name]

    monkeypatch.setattr(bootstrap.metadata, "version", version)


def test_missing_packages_use_native_installer_with_all_pins(tmp_path, monkeypatch):
    path = tmp_path / "requirements.txt"
    path.write_text("mcp==2.1.1\nuvicorn==0.52.4\n")
    versions = {"uvicorn": "0.52.4"}
    installed_versions(monkeypatch, versions)
    calls = []

    def install(requirements):
        calls.append(requirements)
        versions["mcp"] = "2.1.1"
        return True

    bootstrap.ensure_dependencies(path, install)
    assert calls == ["mcp==2.1.1\nuvicorn==0.52.4"]
    bootstrap.ensure_dependencies(path, install)
    assert len(calls) == 1  # Satisfied installations never contact the package index.


def test_shared_version_conflict_never_invokes_installer(tmp_path, monkeypatch):
    path = tmp_path / "requirements.txt"
    path.write_text("mcp==2.1.1\nuvicorn==0.52.4\n")
    installed_versions(monkeypatch, {"mcp": "1.0.0"})
    with pytest.raises(bootstrap.DependencyError, match="mcp: installed 1.0.0"):
        bootstrap.ensure_dependencies(path, lambda _: pytest.fail("shared package overwrite"))


@pytest.mark.parametrize(
    "success,message", [(False, "Start retries"), (True, "Restart Binary Ninja")]
)
def test_install_failure_or_invisible_packages_remain_retryable(
    tmp_path, monkeypatch, success, message
):
    path = tmp_path / "requirements.txt"
    path.write_text("mcp==2.1.1\n")
    installed_versions(monkeypatch, {})
    with pytest.raises(bootstrap.DependencyError, match=message):
        bootstrap.ensure_dependencies(path, lambda _: success)


def test_native_install_uses_registered_provider_core_entry_point(monkeypatch):
    calls = []
    core = N(BNInstallScriptingProviderModules=lambda *args: calls.append(args) or True)
    bn = N(ScriptingProvider={"Python": N(handle="registered-provider")}, _binaryninjacore=core)
    monkeypatch.setitem(sys.modules, "binaryninja", bn)
    assert bootstrap.install_with_binary_ninja(bn, "mcp==2.1.1")
    assert calls == [("registered-provider", "mcp==2.1.1")]


class FakeBN:
    def __init__(self):
        self.commands, self.tasks, self.pending, self.logs = {}, [], [], []
        self.PluginCommand = N(
            register=lambda name, _, callback: self.commands.update({name: callback})
        )
        owner = self

        class Task:
            def __init__(self, *args):
                owner.tasks.append(self)

            def start(self):
                pass

        self.BackgroundTaskThread = Task

    def execute_on_main_thread(self, callback):
        self.pending.append(callback)

    def core_version_info(self):
        return N(build=10601)

    def log_error(self, message):
        self.logs.append(message)

    log_info = log_error


def test_setup_keeps_menus_available_and_serializes_retries(monkeypatch):
    bn = FakeBN()
    plugin = bootstrap.Plugin(bn)
    assert len(bn.commands) == 4

    def fail(*args):
        raise bootstrap.DependencyError("installation failed; Start retries")

    monkeypatch.setattr(bootstrap, "ensure_dependencies", fail)
    plugin.start()
    plugin.start()
    assert len(bn.tasks) == 1
    bn.tasks[0].run()
    assert plugin.job is not None  # Completion is handled on the UI thread.
    bn.pending.pop(0)()
    assert "installation failed" in plugin.state
    assert plugin.job is None
    plugin.start()
    assert len(bn.tasks) == 2


def test_stop_during_setup_suppresses_late_listener_start(monkeypatch):
    bn = FakeBN()
    plugin = bootstrap.Plugin(bn)
    monkeypatch.setattr(bootstrap, "ensure_dependencies", lambda *args: None)
    plugin.start()
    plugin.stop()
    bn.tasks[0].run()
    bn.pending.pop(0)()
    assert plugin.listener is None
    assert plugin.state == "stopped"


def test_unexpected_setup_error_does_not_log_arbitrary_exception_text(monkeypatch):
    bn = FakeBN()
    plugin = bootstrap.Plugin(bn)

    def fail(*args):
        raise RuntimeError("credential-bearing URL")

    monkeypatch.setattr(bootstrap, "ensure_dependencies", fail)
    plugin.start()
    bn.tasks[0].run()
    bn.pending.pop(0)()
    assert "RuntimeError" in plugin.state
    assert "credential-bearing" not in " ".join(bn.logs)


def test_bundled_updates_install_but_require_restart(tmp_path, monkeypatch):
    path = tmp_path / "requirements.txt"
    path.write_text("idna==3.19\n")
    versions = {"idna": "3.10"}
    installed_versions(monkeypatch, versions)
    calls = []
    with pytest.raises(bootstrap.DependencyError, match="Dependencies installed. Restart"):
        bootstrap.ensure_dependencies(path, lambda text: calls.append(text) or True, lambda _: True)
    assert calls == ["idna==3.19"]


def test_bundled_zip_metadata_can_be_updated_but_shared_user_packages_cannot(monkeypatch):
    class ZipLocation:
        def __str__(self):
            return "/Applications/Binary Ninja.app/Contents/Resources/bundled-python3/lib/python313.zip/"

    bn = N(get_install_directory=lambda: "/Applications/Binary Ninja.app/Contents/MacOS")
    monkeypatch.setattr(
        bootstrap.metadata, "distribution", lambda _: N(locate_file=lambda _: ZipLocation())
    )
    assert bootstrap.is_bundled_dependency(bn, "idna")
    monkeypatch.setattr(
        bootstrap.metadata,
        "distribution",
        lambda _: N(locate_file=lambda _: Path("/tmp/user/site-packages")),
    )
    assert not bootstrap.is_bundled_dependency(bn, "idna")


def test_start_cannot_bypass_restart_after_updating_loaded_packages(monkeypatch):
    bn = FakeBN()
    plugin = bootstrap.Plugin(bn)

    def restart(*args):
        raise bootstrap.RestartRequired("Dependencies installed. Restart Binary Ninja")

    monkeypatch.setattr(bootstrap, "ensure_dependencies", restart)
    plugin.start()
    bn.tasks[0].run()
    bn.pending.pop(0)()
    plugin.stop()
    plugin.start()
    assert len(bn.tasks) == 1
    assert plugin.listener is None
    assert "Restart Binary Ninja" in plugin.state
