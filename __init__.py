"""Binary Ninja UI plugin entry point; one instance per Python module/process."""

try:
    import binaryninja as bn
except ModuleNotFoundError:
    bn = None

if bn is not None and bn.core_ui_enabled():
    from .binja_windbg_mcp.bootstrap import Plugin

    _plugin = Plugin(bn)
    # Queue startup until the current plugin-loading callback has returned.
    bn.execute_on_main_thread(_plugin.start)
