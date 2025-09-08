import os
import logging
import customtkinter as ctk

logger = logging.getLogger(__name__)
ICON_PATH = os.path.join("icons", "main.ico")

def set_icon(window):
    """
    Sets the application icon for the given window.
    Works for both Tkinter and CustomTkinter windows.
    """
    try:
        if os.path.exists(ICON_PATH):
            window.iconbitmap(ICON_PATH)
    except Exception as e:
        # Using logger.warning to avoid crashing the app if the icon fails to load
        logger.warning(f"Could not set application icon: {e}")

class ThemedToplevel(ctk.CTkToplevel):
    """
    A custom CTkToplevel window that automatically applies the main application icon.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._icon_set = False
        
        # Make the window transient for its master, if one is provided.
        if args:
            self.transient(args[0])
            
        self.bind("<FocusIn>", self._set_icon_on_focus)

    def _set_icon_on_focus(self, event=None):
        if not self._icon_set:
            try:
                set_icon(self)
                self._icon_set = True
            except Exception as e:
                logger.warning(f"Failed to set icon on focus: {e}")
