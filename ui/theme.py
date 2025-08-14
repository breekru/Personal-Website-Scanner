"""Centralised theming utilities for the UI."""

try:  # pragma: no cover - optional dependency
    import ttkbootstrap as ttkb
    from ttkbootstrap.style import Style
    _HAS_TTKB = True
except Exception:  # noqa: S110 - optional import
    from tkinter import ttk
    Style = ttk.Style  # type: ignore
    _HAS_TTKB = False


class ThemeManager:
    """Apply a consistent theme across the application."""

    def __init__(self, theme: str = "litera"):
        if _HAS_TTKB:
            self.style = Style(theme=theme)
        else:
            self.style = Style()
            self.style.theme_use("clam")

    def apply(self, widget):
        """Placeholder hook for future theme customisation."""
        if hasattr(widget, "configure"):
            widget.configure(style=widget.winfo_class())
