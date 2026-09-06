"""Binary Ninja UI plugin entry point; one instance per Python module/process."""

try:
    import binaryninja as bn
except ModuleNotFoundError:
    bn = None


def initialize():
    import sys
    from pathlib import Path

    if sys.version_info[:2] != (3, 13) or bn.core_version_info().build < 10601:
        raise RuntimeError("This companion requires Binary Ninja 6 and Python 3.13")

    from .binja_windbg_mcp.adapter import Workspace
    from .binja_windbg_mcp.profiles import Profiles
    from .binja_windbg_mcp.server import Listener

    profiles = Profiles(Path(bn.user_directory()) / "binja-windbg-mcp")
    workspace = Workspace()
    workspace.attach_ui_notifications()
    listener = Listener(workspace, profiles)

    def start(_view):
        try:
            listener.start()
        except Exception:
            bn.show_message_box("WinDbg MCP", listener.state)

    bn.PluginCommand.register(
        "WinDbg MCP\\Start", "Start the authenticated loopback listener", start
    )
    bn.PluginCommand.register(
        "WinDbg MCP\\Stop", "Stop the listener and local pairing", lambda _view: listener.stop()
    )
    bn.PluginCommand.register(
        "WinDbg MCP\\Status",
        "Show listener state",
        lambda _view: bn.show_message_box("WinDbg MCP", listener.state),
    )
    bn.PluginCommand.register(
        "WinDbg MCP\\Connection Information",
        "Show the endpoint and credential file location",
        lambda _view: bn.show_message_box(
            "WinDbg MCP",
            f"http://127.0.0.1:8766/mcp\nBearer credential: {profiles.path}\nUse the token from this user-only file in the host's HTTP headers.",
        ),
    )
    start(None)
    return listener


if bn is not None and bn.core_ui_enabled():
    try:
        _listener = initialize()
    except Exception:
        bn.log_error(
            "binja-windbg-mcp failed to start; requires Binary Ninja 6/Python 3.13, pinned dependencies, and user-only profiles.json. Retired analysis/edit groups must be replaced with native MCP/evidence."
        )
