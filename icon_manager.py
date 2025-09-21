import os
import logging
import customtkinter as ctk

logger = logging.getLogger(__name__)
ICON_PATH = os.path.join("icons", "main.ico")

def set_icon(window):
    """
    Sets the application icon for the given window.
    """
    if not os.path.exists(ICON_PATH):
        logger.warning(f"Icon file not found at {ICON_PATH}")
        return False
        
    try:
        window.iconbitmap(ICON_PATH)
        return True
    except Exception as e:
        logger.warning(f"Could not set application icon: {e}")
        return False

class ThemedToplevel(ctk.CTkToplevel):
    """
    A custom CTkToplevel window that automatically applies the main application icon
    without flicker by hiding the window during initialization.
    """
    def __init__(self, *args, **kwargs):
        # Initialize the CustomTkinter Toplevel
        super().__init__(*args, **kwargs)
        
        # Immediately hide the window to prevent showing with wrong icon
        self.withdraw()
        
        # Set the icon while window is hidden
        self._icon_set = False
        if os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
                self._icon_set = True
            except Exception as e:
                logger.warning(f"Failed to set icon: {e}")
        
        # Make the window transient for its master, if one is provided
        if args:
            try:
                self.transient(args[0])
            except Exception as e:
                logger.warning(f"Failed to set transient: {e}")
        
        # Schedule the window to be shown after a brief moment to allow all setup to complete
        self.after(1, self._reveal_window)
    
    def _reveal_window(self):
        """Show the window after icon has been set."""
        # One more attempt to set icon if it failed initially
        if not self._icon_set and os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
                self._icon_set = True
            except Exception as e:
                logger.warning(f"Second icon attempt failed: {e}")
        
        # Now show the window with the correct icon
        self.deiconify()
        
        # Ensure window gets focus
        self.lift()
        self.focus_force()