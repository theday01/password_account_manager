import os
import tkinter as tk
import tkinter.messagebox as messagebox
import customtkinter as ctk
from PIL import Image, ImageTk

def set_icon(window):
    """
    Sets the icon for a given tkinter window.
    It looks for 'main.ico' in the 'icons' folder.
    """
    try:
        # Get the absolute path to the icon file
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', 'main.ico')

        if os.path.exists(icon_path):
            window.iconbitmap(icon_path)
        else:
            print(f"Warning: Icon file not found at {icon_path}")

    except tk.TclError:
        # Fallback for systems that have trouble with .ico files
        try:
            icon_path_png = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', 'load.png')
            if os.path.exists(icon_path_png):
                img = Image.open(icon_path_png)
                photo = ImageTk.PhotoImage(img)
                window.wm_iconphoto(True, photo)
            else:
                print(f"Warning: Fallback PNG icon not found at {icon_path_png}")
        except Exception as pil_e:
            print(f"Failed to set icon using PIL: {pil_e}")
    except Exception as e:
        print(f"An unexpected error occurred while setting the icon: {e}")

class ThemedToplevel(ctk.CTkToplevel):
    """
    A custom Toplevel window that automatically has the application icon.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        set_icon(self)

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

class TfaVerificationDialog(ThemedToplevel):
    """
    A dialog for verifying a 2FA code, including brute-force protection UI.
    """
    def __init__(self, parent, lang_manager, auth_guardian, verification_callback):
        super().__init__(parent)
        self.lang_manager = lang_manager
        self.auth_guardian = auth_guardian
        self.verification_callback = verification_callback
        self.result = None  # Can be "verified", "cancelled", or "locked"

        self.title(self.lang_manager.get_string("tfa_verification_title"))
        self.geometry("450x350")
        self.resizable(False, False)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._build_ui()
        self._update_lockout_state()

    def _build_ui(self):
        main_frame = ctk.CTkFrame(self, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text=self.lang_manager.get_string("tfa_enter_code_label"),
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(20, 10))

        ctk.CTkLabel(
            main_frame,
            text=self.lang_manager.get_string("tfa_prompt_message"),
            font=ctk.CTkFont(size=12),
            text_color=("gray60", "gray40")
        ).pack(pady=(0, 20))

        self.code_entry = ctk.CTkEntry(
            main_frame,
            width=200,
            height=50,
            font=ctk.CTkFont(size=24, weight="bold"),
            justify="center"
        )
        self.code_entry.pack()
        self.code_entry.focus()
        self.code_entry.bind("<KeyRelease>", self._validate_input)
        self.code_entry.bind("<Return>", lambda e: self._on_verify())

        self.error_label = ctk.CTkLabel(
            main_frame,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="red"
        )
        self.error_label.pack(pady=(10, 0))

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        self.cancel_button = ctk.CTkButton(
            button_frame,
            text=self.lang_manager.get_string("cancel_button"),
            command=self._on_cancel,
            width=120,
            height=45
        )
        self.cancel_button.pack(side="left", padx=10)

        self.verify_button = ctk.CTkButton(
            button_frame,
            text=self.lang_manager.get_string("verify_button"),
            command=self._on_verify,
            width=120,
            height=45,
            font=ctk.CTkFont(weight="bold")
        )
        self.verify_button.pack(side="right", padx=10)

    def _validate_input(self, event=None):
        current_value = self.code_entry.get()
        new_value = "".join(filter(str.isdigit, current_value))
        if len(new_value) > 6:
            new_value = new_value[:6]
        if new_value != current_value:
            self.code_entry.delete(0, tk.END)
            self.code_entry.insert(0, new_value)

    def _on_verify(self):
        code = self.code_entry.get().strip()
        if len(code) != 6:
            self.error_label.configure(text=self.lang_manager.get_string("tfa_invalid_code_format"))
            return

        is_correct = self.verification_callback(code)
        self.auth_guardian.record_tfa_attempt(is_correct)

        if is_correct:
            self.result = "verified"
            self.destroy()
        else:
            self.code_entry.delete(0, tk.END)
            if self.auth_guardian.is_tfa_locked_out():
                self.result = "locked"
                self._update_lockout_state()
            else:
                attempts_left = self.auth_guardian.MAX_TFA_ATTEMPTS_BEFORE_LOCKOUT - self.auth_guardian.tfa_failed_attempts
                self.error_label.configure(text=self.lang_manager.get_string("tfa_incorrect_code_attempts_left", count=attempts_left))

    def _on_cancel(self):
        self.result = "cancelled"
        self.destroy()

    def _update_lockout_state(self):
        if self.auth_guardian.is_tfa_locked_out():
            self.code_entry.configure(state="disabled")
            self.verify_button.configure(state="disabled")
            remaining_time = self.auth_guardian.get_remaining_tfa_lockout_time()
            minutes, seconds = divmod(remaining_time, 60)
            lockout_message = self.lang_manager.get_string("tfa_locked_out_message", minutes=minutes, seconds=seconds)
            self.error_label.configure(text=lockout_message)
            self.after(1000, self._update_lockout_state)
        else:
            self.code_entry.configure(state="normal")
            self.verify_button.configure(state="normal")
            # Clear the lockout message if it wasn't replaced by an error
            if "locked" in self.error_label.cget("text").lower():
                self.error_label.configure(text="")
    
    def show(self):
        """Show the dialog and wait for it to close."""
        self.wait_window()
        return self.result

class SimpleTfaVerificationDialog(ThemedToplevel):
    """
    A simplified, modal 2FA dialog for re-authentication during sensitive actions.
    It does not contain complex lockout UI, only the essential input fields.
    Returns the verified code on success, None on failure/cancellation.
    """
    def __init__(self, parent, lang_manager, title):
        super().__init__(parent)
        self.lang_manager = lang_manager
        self.result = None

        self.title(title)
        self.geometry("380x220")
        self.resizable(False, False)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._build_ui()
        self.center_window()
        self.lift()
        self.attributes('-topmost', True)
        self.after_idle(lambda: self.attributes('-topmost', False))
        self.code_entry.focus()


    def _build_ui(self):
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text=self.lang_manager.get_string("tfa_enter_code_label"),
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(0, 15))

        self.code_entry = ctk.CTkEntry(
            main_frame,
            width=180,
            height=45,
            font=ctk.CTkFont(size=22, weight="bold"),
            justify="center"
        )
        self.code_entry.pack()
        self.code_entry.bind("<KeyRelease>", self._validate_input)
        self.code_entry.bind("<Return>", lambda e: self._on_verify())

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=(20, 0))

        cancel_button = ctk.CTkButton(
            button_frame,
            text=self.lang_manager.get_string("cancel_button"),
            command=self._on_cancel,
            width=100
        )
        cancel_button.pack(side="left", padx=10)

        verify_button = ctk.CTkButton(
            button_frame,
            text=self.lang_manager.get_string("verify_button"),
            command=self._on_verify,
            width=100
        )
        verify_button.pack(side="right", padx=10)

    def _validate_input(self, event=None):
        current_value = self.code_entry.get()
        new_value = "".join(filter(str.isdigit, current_value))
        if len(new_value) > 6:
            new_value = new_value[:6]
        if new_value != current_value:
            self.code_entry.delete(0, tk.END)
            self.code_entry.insert(0, new_value)

    def _on_verify(self):
        code = self.code_entry.get().strip()
        if len(code) == 6:
            self.result = code
            self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def get_code(self):
        """Show the dialog and wait for user input."""
        self.wait_window()
        return self.result
