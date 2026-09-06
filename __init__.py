"""Binary Ninja UI plugin entry point; one instance per Python module/process."""

try:
    import binaryninja as bn
except ModuleNotFoundError:
    bn = None

if bn is not None and bn.core_ui_enabled():
    from .binja_windbg_mcp.bootstrap import Plugin

    _plugin = Plugin(bn)

    def _initialize_ui():
        _plugin.attach_shutdown_hooks()
        _plugin.start()

    # Register Qt hooks and start after the current plugin-loading callback returns.
    bn.execute_on_main_thread(_initialize_ui)
