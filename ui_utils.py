import os
import tkinter as tk
import tkinter.messagebox as messagebox
import customtkinter as ctk
from PIL import Image, ImageTk

def set_icon(window):
    """
    Sets the icon for a given tkinter window.
    It looks for 'icon.png' in the 'icons' folder and sets it for both the window and taskbar.
    """
    try:
        # Get the absolute path to the icon file
        icon_path_png = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', 'icon.png')
        
        if os.path.exists(icon_path_png):
            # Load the icon image
            img = Image.open(icon_path_png)
            
            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(img)
            
            # Set the icon for the window
            window.iconphoto(True, photo)
            
            # Store reference to prevent garbage collection
            if not hasattr(window, '_icon_photo'):
                window._icon_photo = photo
            
            # For Windows taskbar icon, also try to set iconbitmap if .ico exists
            icon_path_ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', 'icon.ico')
            if os.path.exists(icon_path_ico):
                try:
                    window.iconbitmap(icon_path_ico)
                except tk.TclError:
                    # If iconbitmap fails, iconphoto should still work for taskbar
                    pass
        else:
            print(f"Warning: Icon file not found at {icon_path_png}")
            
            # Fallback to old icon paths
            icon_path_main = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', 'main.ico')
            if os.path.exists(icon_path_main):
                try:
                    window.iconbitmap(icon_path_main)
                except tk.TclError as e:
                    print(f"Failed to set fallback icon: {e}")

    except Exception as e:
        print(f"An unexpected error occurred while setting the icon: {e}")

class ThemedToplevel(ctk.CTkToplevel):
    """
    A custom Toplevel window that automatically has the application icon.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set icon immediately
        set_icon(self)
        # Schedule icon setting after window is fully initialized
        self.after(10, lambda: set_icon(self))
        
class CustomMessageBox:
    """Wrapper class to use standard tkinter messageboxes with consistent interface"""
    
    @staticmethod
    def show_message(title, message, msg_type="info", ask=None, parent=None):
        """
        Show a message using standard tkinter messagebox
        
        Args:
            title: Window title
            message: Message text
            msg_type: Type of message ("info", "error", "warning", "success")
            ask: Type of question ("yesno", "okcancel", or None for info)
            parent: Parent window
            
        Returns:
            Boolean result for questions, True for info messages
        """
        # Ensure parent window is brought to front
        if parent:
            parent.lift()
            parent.attributes('-topmost', True)
            parent.after_idle(lambda: parent.attributes('-topmost', False))
        
        if ask == "yesno":
            if msg_type == "error":
                return messagebox.askyesno(title, message, icon="error", parent=parent)
            elif msg_type == "warning":
                return messagebox.askyesno(title, message, icon="warning", parent=parent)
            else:
                return messagebox.askyesno(title, message, icon="question", parent=parent)
        
        elif ask == "okcancel":
            if msg_type == "error":
                return messagebox.askokcancel(title, message, icon="error", parent=parent)
            elif msg_type == "warning":
                return messagebox.askokcancel(title, message, icon="warning", parent=parent)
            else:
                return messagebox.askokcancel(title, message, icon="question", parent=parent)
        
        else:
            # Info messages
            if msg_type == "error":
                messagebox.showerror(title, message, parent=parent)
            elif msg_type == "warning":
                messagebox.showwarning(title, message, parent=parent)
            elif msg_type == "success":
                messagebox.showinfo(title, message, parent=parent)
            else:
                messagebox.showinfo(title, message, parent=parent)
            
            return True
    
    def __init__(self, title="Message", message="", msg_type="info", ask="", parent=None):
        """Initialize and show the message box"""
        self.result = self.show_message(title, message, msg_type, ask, parent)
    
    def show(self):
        """Return the result"""
        return self.result

def ask_string(title, prompt, show=None, parent=None):
    """
    Show a string input dialog using tkinter.simpledialog
    """
    import tkinter.simpledialog as simpledialog
    
    # Ensure parent window is brought to front
    if parent:
        parent.lift()
        parent.attributes('-topmost', True)
        parent.after_idle(lambda: parent.attributes('-topmost', False))
    
    if show:
        # For password input, we'll create a simple custom dialog
        return _ask_password(title, prompt, parent)
    else:
        return simpledialog.askstring(title, prompt, parent=parent)

def _ask_password(title, prompt, parent=None):
    """Create a simple password input dialog"""
    dialog = ThemedToplevel(parent)
    dialog.title(title)
    dialog.geometry("350x150")
    dialog.resizable(False, False)
    dialog.grab_set()
    dialog.lift()
    dialog.attributes('-topmost', True)
    dialog.after_idle(lambda: dialog.attributes('-topmost', False))
    
    result = None

    main_frame = ctk.CTkFrame(dialog)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)
    
    label = ctk.CTkLabel(main_frame, text=prompt, font=ctk.CTkFont(size=12))
    label.pack(pady=(10, 5))
    
    entry = ctk.CTkEntry(main_frame, show="*", width=280, height=30)
    entry.pack(pady=5)
    entry.focus()

    button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
    button_frame.pack(pady=(15, 5))

    def on_ok():
        nonlocal result
        result = entry.get()
        dialog.destroy()

    def on_cancel():
        nonlocal result
        result = None
        dialog.destroy()
    
    def on_enter(event):
        on_ok()

    entry.bind('<Return>', on_enter)
    dialog.bind('<Escape>', lambda e: on_cancel())

    ok_button = ctk.CTkButton(button_frame, text="OK", command=on_ok, width=80)
    ok_button.pack(side="left", padx=5)
    cancel_button = ctk.CTkButton(button_frame, text="Cancel", command=on_cancel, width=80)
    cancel_button.pack(side="right", padx=5)

    # Center the dialog
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - (350 // 2)
    y = (dialog.winfo_screenheight() // 2) - (150 // 2)
    if parent:
        try:
            px = parent.winfo_x()
            py = parent.winfo_y()
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            x = px + (pw - 350) // 2
            y = py + (ph - 150) // 2
        except:
            pass
    dialog.geometry(f"350x150+{x}+{y}")

    dialog.wait_window()
    return result

# Convenience functions for easier usage
def show_error(title, message, parent=None):
    """Show error message"""
    return CustomMessageBox.show_message(title, message, "error", parent=parent)

def show_warning(title, message, parent=None):
    """Show warning message"""
    return CustomMessageBox.show_message(title, message, "warning", parent=parent)

def show_info(title, message, parent=None):
    """Show info message"""
    return CustomMessageBox.show_message(title, message, "info", parent=parent)

def show_success(title, message, parent=None):
    """Show success message"""
    return CustomMessageBox.show_message(title, message, "success", parent=parent)

def ask_yes_no(title, message, msg_type="question", parent=None):
    """Ask yes/no question"""
    return CustomMessageBox.show_message(title, message, msg_type, "yesno", parent)

def ask_ok_cancel(title, message, msg_type="question", parent=None):
    """Ask ok/cancel question"""
    return CustomMessageBox.show_message(title, message, msg_type, "okcancel", parent)

def show_reminder_dialog(parent_window, remaining_seconds, activation_callback):
    """
    Creates and displays the reminder dialog.
    """
    days = int(remaining_seconds // (24 * 3600))
    hours = int((remaining_seconds % (24 * 3600)) // 3600)
    minutes = int((remaining_seconds % 3600) // 60)

    time_left_str = f"{days} days, {hours} hours, {minutes} minutes"

    dialog = ThemedToplevel(parent_window)
    dialog.title("Trial Reminder")
    dialog.geometry("400x200")
    dialog.resizable(False, False)
    dialog.grab_set()

    # Center the dialog
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
    y = (dialog.winfo_screenheight() // 2) - (200 // 2)
    dialog.geometry(f"400x200+{x}+{y}")

    main_frame = ctk.CTkFrame(dialog)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    ctk.CTkLabel(main_frame, text=f"Your trial expires in {time_left_str}.",
                    font=ctk.CTkFont(size=14)).pack(pady=10)

    ctk.CTkLabel(main_frame, text="Would you like to activate now?",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)

    button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
    button_frame.pack(pady=20)

    def on_activate():
        dialog.destroy()
        if activation_callback:
            activation_callback()

    def on_later():
        dialog.destroy()

    ctk.CTkButton(button_frame, text="Activate Now", command=on_activate).pack(side="left", padx=10)
    ctk.CTkButton(button_frame, text="Later", command=on_later).pack(side="right", padx=10)

    dialog.wait_window()

