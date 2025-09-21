import os
import tkinter as tk
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

class CustomMessageBox(ThemedToplevel):
    def __init__(self, title="Message", message="", msg_type="info", ask=""):
        super().__init__()

        self.title(title)
        self.lift()
        self.attributes("-topmost", True)
        self.grab_set()
        self.result = None

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        icon_label = ctk.CTkLabel(main_frame, text=self._get_icon(msg_type), font=ctk.CTkFont(size=36))
        icon_label.pack(pady=10)

        message_label = ctk.CTkLabel(main_frame, text=message, wraplength=350, justify="center")
        message_label.pack(pady=10, padx=10)

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        if ask == "yesno":
            yes_button = ctk.CTkButton(button_frame, text="Yes", command=self._on_yes, width=100)
            yes_button.pack(side="left", padx=10)
            no_button = ctk.CTkButton(button_frame, text="No", command=self._on_no, width=100)
            no_button.pack(side="right", padx=10)
        else:
            ok_button = ctk.CTkButton(button_frame, text="OK", command=self._on_ok, width=100)
            ok_button.pack()
        
        self.after(100, self.center_window)

    def _get_icon(self, msg_type):
        if msg_type == "error":
            return "❌"
        if msg_type == "info":
            return "ℹ️"
        return "❓"

    def _on_ok(self):
        self.result = True
        self.destroy()

    def _on_yes(self):
        self.result = True
        self.destroy()

    def _on_no(self):
        self.result = False
        self.destroy()

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def show(self):
        self.wait_window()
        return self.result

def ask_string(title, prompt, **kwargs):
    dialog = ThemedToplevel()
    dialog.title(title)
    dialog.lift()
    dialog.attributes("-topmost", True)
    dialog.grab_set()
    
    result = None

    main_frame = ctk.CTkFrame(dialog)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)
    
    label = ctk.CTkLabel(main_frame, text=prompt)
    label.pack(pady=10)
    
    entry = ctk.CTkEntry(main_frame, **kwargs)
    entry.pack(pady=10, padx=10, fill="x")
    entry.focus()

    button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
    button_frame.pack(pady=10)

    def on_ok():
        nonlocal result
        result = entry.get()
        dialog.destroy()

    def on_cancel():
        nonlocal result
        result = None
        dialog.destroy()

    ok_button = ctk.CTkButton(button_frame, text="OK", command=on_ok)
    ok_button.pack(side="left", padx=10)
    cancel_button = ctk.CTkButton(button_frame, text="Cancel", command=on_cancel)
    cancel_button.pack(side="right", padx=10)

    dialog.wait_window()
    return result
