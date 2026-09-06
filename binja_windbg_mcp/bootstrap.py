"""Dependency setup and UI commands; imports only the standard library until ready."""

import importlib
import re
import sys
from importlib import metadata
from pathlib import Path


class DependencyError(RuntimeError):
    pass


class RestartRequired(DependencyError):
    pass


def read_requirements(path):
    requirements = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+", line):
            raise DependencyError("requirements.txt must contain one exact package pin per line")
        requirements.append(line)
    if not requirements:
        raise DependencyError("requirements.txt is empty")
    return requirements


def check_requirements(requirements):
    missing, conflicts = [], {}
    for requirement in requirements:
        name, expected = requirement.split("==")
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            missing.append(requirement)
        else:
            if installed != expected:
                conflicts[name] = f"{name}: installed {installed}, requires {expected}"
    return missing, conflicts


def ensure_dependencies(path, install, can_update=lambda name: False):
    requirements = read_requirements(path)
    missing, conflicts = check_requirements(requirements)
    blocked = [message for name, message in conflicts.items() if not can_update(name)]
    if blocked:
        raise DependencyError(
            "Shared Python dependency conflict: "
            + "; ".join(blocked)
            + ". Resolve these versions using Binary Ninja's Extension Manager or "
            "Install python3 module action, restart, then use WinDbg MCP > Start."
        )
    if not missing and not conflicts:
        return
    # Pass all pins to constrain transitive resolution; do not use a private package path.
    if not install("\n".join(requirements)):
        raise DependencyError(
            "Dependency installation failed. See Binary Ninja's Dependency Installer log; "
            "WinDbg MCP > Start retries installation."
        )
    importlib.invalidate_caches()
    if conflicts:
        raise RestartRequired(
            "Dependencies installed. Restart Binary Ninja to use the updated Python packages."
        )
    missing, conflicts = check_requirements(requirements)
    if missing or conflicts:
        raise RestartRequired(
            "Dependencies are not visible at the required versions after installation. "
            "Restart Binary Ninja, then use WinDbg MCP > Start."
        )


def is_bundled_dependency(bn, name):
    # Binary Ninja supports shadowing bundled packages in its user site-packages. Do
    # not silently replace incompatible versions installed there by other plugins.
    location = Path(str(metadata.distribution(name).locate_file(""))).resolve()
    application = Path(bn.get_install_directory()).resolve().parent
    return location.is_relative_to(
        application / "Resources" / "bundled-python3"
    ) or location.is_relative_to(application / "Frameworks" / "Python.framework")


def install_with_binary_ninja(bn, requirements):
    # The Python wrapper has no public install method. Use the generated binding to the
    # public core entry point, which invokes the configured provider and its installer.
    from binaryninja import _binaryninjacore as core

    provider = bn.ScriptingProvider["Python"]
    return core.BNInstallScriptingProviderModules(provider.handle, requirements)


class Plugin:
    def __init__(self, bn):
        self.bn = bn
        self.listener = None
        self.job = None
        self.want_start = False
        self.restart_required = False
        self.setup_state = "stopped"
        self.requirements = Path(__file__).resolve().parents[1] / "requirements.txt"
        commands = (
            ("Start", "Start the listener, installing missing dependencies if needed", self.start),
            ("Stop", "Stop the listener and local pairing", self.stop),
            ("Status", "Show listener and dependency setup state", self.status),
            (
                "Connection Information",
                "Show the endpoint and credential file location",
                self.connection,
            ),
        )
        for name, description, callback in commands:
            bn.PluginCommand.register("WinDbg MCP\\" + name, description, callback)

    @property
    def state(self):
        return self.listener.state if self.listener else self.setup_state

    def start(self, _view=None):
        self.want_start = True
        if self.listener:
            try:
                self.listener.start()
            except Exception:
                self.bn.log_error("WinDbg MCP: " + self.listener.state)
            return
        if self.restart_required:
            self.bn.log_error("WinDbg MCP: " + self.setup_state)
            return
        if self.job:
            return
        if sys.version_info[:2] != (3, 13) or self.bn.core_version_info().build < 10601:
            self.setup_state = "Requires Binary Ninja 6.0.10601 or later with Python 3.13"
            self.bn.log_error("WinDbg MCP: " + self.setup_state)
            return
        self.setup_state = "Checking/installing dependencies with Binary Ninja's Python installer"
        self.bn.log_info("WinDbg MCP: " + self.setup_state)
        owner = self

        class Setup(self.bn.BackgroundTaskThread):
            def run(self):
                error = None
                try:
                    ensure_dependencies(
                        owner.requirements,
                        lambda requirements: install_with_binary_ninja(owner.bn, requirements),
                        lambda name: is_bundled_dependency(owner.bn, name),
                    )
                except DependencyError as exc:
                    error = exc
                except Exception as exc:
                    # Avoid logging arbitrary exception text that may contain local credentials.
                    error = DependencyError(
                        f"Dependency setup failed ({type(exc).__name__}); use Start to retry"
                    )
                owner.bn.execute_on_main_thread(lambda: owner._setup_finished(error))

        self.job = Setup("WinDbg MCP: checking/installing Python dependencies", False)
        self.job.start()

    def _setup_finished(self, error):
        self.job = None
        if error:
            self.restart_required = isinstance(error, RestartRequired)
            self.setup_state = str(error)
            self.bn.log_error("WinDbg MCP: " + self.setup_state)
            return
        self.setup_state = "stopped"
        if not self.want_start:
            return
        try:
            from .adapter import Workspace
            from .profiles import Profiles
            from .server import Listener

            profiles = Profiles(Path(self.bn.user_directory()) / "binja-windbg-mcp")
            workspace = Workspace()
            workspace.attach_ui_notifications()
            self.listener = Listener(workspace, profiles)
        except Exception as exc:
            self.setup_state = (
                f"Initialization failed ({type(exc).__name__}). Check profiles.json permissions "
                "and group settings; restart after changing installed dependencies."
            )
            self.bn.log_error("WinDbg MCP: " + self.setup_state)
            return
        self.start()

    def stop(self, _view=None):
        self.want_start = False
        if self.listener:
            self.listener.stop()
        elif self.job:
            self.setup_state = "Finishing dependency installation; listener startup cancelled"
        elif not self.restart_required:
            self.setup_state = "stopped"

    def status(self, _view=None):
        self.bn.show_message_box("WinDbg MCP", self.state)

    def connection(self, _view=None):
        path = Path(self.bn.user_directory()) / "binja-windbg-mcp" / "profiles.json"
        self.bn.show_message_box(
            "WinDbg MCP",
            f"{self.state}\nhttp://127.0.0.1:8766/mcp\nBearer credential: {path}\n"
            "The credential file is created when the listener is initialized. "
            "Use its token in the host's HTTP headers.",
        )
