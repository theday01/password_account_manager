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
            window.iconbitmap(default=ICON_PATH)
    except Exception as e:
        # Using logger.warning to avoid crashing the app if the icon fails to load
        logger.warning(f"Could not set application icon: {e}")

class ThemedToplevel(ctk.CTkToplevel):
    """
    A custom CTkToplevel window that automatically applies the main application icon.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Defer icon setting to ensure the window is fully initialized
        self.after(10, lambda: set_icon(self))
