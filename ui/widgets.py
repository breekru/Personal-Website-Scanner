"""Reusable widget helpers."""
from tkinter import ttk


class TaggedTreeview(ttk.Treeview):
    """Treeview that preconfigures colour tags for risk levels."""

    TAG_COLOURS = {
        'high_risk': 'red',
        'safe': 'green',
        'unknown': 'gray',
    }

    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        for tag, colour in self.TAG_COLOURS.items():
            self.tag_configure(tag, foreground=colour)

    def insert_with_tags(self, *args, tags=(), **kwargs):
        """Insert an item applying the given colour tags."""
        return super().insert(*args, tags=tags, **kwargs)
