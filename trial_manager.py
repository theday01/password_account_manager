import os
import json
from datetime import datetime, timedelta
import platform
import webbrowser
from tkinter import messagebox
import customtkinter as ctk
import hashlib
from machine_id_utils import generate_machine_id
from icon_manager import ThemedToplevel
from guardian_anchor import GuardianAnchor
from guardian_observer import GuardianObserver

class HoldButton(ctk.CTkButton):
    """A button that requires being held down to activate."""
    def __init__(self, master, hold_time_ms=5000, hold_callback=None, **kwargs):
        # The 'command' is replaced by 'hold_callback'
        self.hold_callback = hold_callback
        if 'command' in kwargs:
            del kwargs['command']

        super().__init__(master, **kwargs)
        
        self.hold_time_ms = hold_time_ms
        self.timer = None
        self.start_time = None
        self.original_text = self.cget("text")

        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _on_press(self, event):
        self.start_time = datetime.now()
        self._update_hold_text()

    def _on_release(self, event):
        if self.timer:
            self.after_cancel(self.timer)
            self.timer = None
        self.configure(text=self.original_text)

    def _update_hold_text(self):
        if not self.start_time:
            return

        elapsed_ms = (datetime.now() - self.start_time).total_seconds() * 1000
        remaining_sec = (self.hold_time_ms - elapsed_ms) / 1000

        if remaining_sec <= 0:
            if self.hold_callback:
                self.hold_callback()
            self.configure(text=self.original_text)
            self.start_time = None
        else:
            self.configure(text=f"Hold for {remaining_sec:.1f}s")
            self.timer = self.after(100, self._update_hold_text)

class TrialManager:
    """
    The Enforcer. This class determines the application's trial status by
    relying on the independent Guardian modules. It no longer manages its
    own storage, making it simpler and more secure.
    """
    _machine_id = None  # Cache for machine ID

    # def __init__(self, parent_window, restart_callback=None):
    #     self.TRIAL_PERIOD = timedelta(days=7)
    #     self.LICENSE_FILE = self._get_obfuscated_license_path()

    #     self.parent_window = parent_window
    #     self.restart_callback = restart_callback

    #     # Instantiate the guardians
    #     self.anchor = GuardianAnchor()
    #     self.observer = GuardianObserver(self.anchor)

    #     self.is_trial_active = False
    #     self.minutes_remaining = 0
    #     self.status = self.check_trial_status()

    def __init__(self, parent_window, restart_callback=None):
        self.TRIAL_PERIOD = timedelta(minutes=1)  # Changed from days=7 to minutes=1
        self.LICENSE_FILE = self._get_obfuscated_license_path()

        self.parent_window = parent_window
        self.restart_callback = restart_callback

        # Instantiate the guardians
        self.anchor = GuardianAnchor()
        self.observer = GuardianObserver(self.anchor)

        self.is_trial_active = False
        self.minutes_remaining = 0
        self.status = self.check_trial_status()

    def _get_machine_id(self):
        if TrialManager._machine_id is None:
            TrialManager._machine_id = generate_machine_id()
        return TrialManager._machine_id

    def _get_obfuscated_license_path(self):
        """Generates a unique, discoverable path for the license file."""
        machine_id = self._get_machine_id()
        # The prefix makes the file's purpose clear to the cleanup script.
        filename = f"sv-license-{hashlib.sha256(machine_id.encode()).hexdigest()[:16]}.lic"
        # Use a dot prefix on non-Windows systems to hide the file.
        if platform.system() != "Windows":
            filename = f".{filename}"
        return os.path.expanduser(f"~/{filename}")

    def check_trial_status(self):
        """
        Checks the trial status by consulting the guardians.
        This is the single point of truth for the trial state.
        """
        # 1. A valid license file always wins.
        if os.path.exists(self.LICENSE_FILE):
            return "FULL"

        # 2. Check the guardians for any signs of tampering.
        anchor_status, anchor_data = self.anchor.check()
        if "TAMPERED" in anchor_status:
            return "TAMPERED"

        observer_status = self.observer.check()
        if "TAMPERED" in observer_status:
            return "TAMPERED"

        # 3. If guardians are OK, calculate the trial period from the anchor's data.
        install_ts_str = anchor_data.get('install_ts')
        if not install_ts_str:
            # This should not happen if anchor check is OK, but as a safeguard:
            return "TAMPERED"

        install_ts = datetime.fromisoformat(install_ts_str)
        elapsed = datetime.utcnow() - install_ts

        if elapsed >= self.TRIAL_PERIOD:
            return "EXPIRED"
        
        # If we reach here, the trial is active.
        self.is_trial_active = True
        self.minutes_remaining = (self.TRIAL_PERIOD - elapsed).total_seconds() / 60
        return "TRIAL"

    def activate_full_version(self):
        """Creates the license file to permanently activate the application."""
        try:
            with open(self.LICENSE_FILE, 'w') as f:
                f.write(json.dumps({
                    'purchase_date': datetime.utcnow().isoformat(),
                    'license_key': self._get_machine_id()
                }))
            if platform.system() == 'Windows':
                os.system(f"attrib +h {self.LICENSE_FILE}")
            self.status = "FULL"
            messagebox.showinfo("Activated", "Thank you for your purchase! The application is now fully activated.")
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Activation failed. Please contact support. Error: {e}")
            return False

    def show_trial_expired_dialog(self, lockout_time_remaining=None):
        """
        Shows a dialog for expired, tampered, or locked-out states.
        """
        dialog = ThemedToplevel(self.parent_window)
        is_tampered = self.status == "TAMPERED"
        is_locked = lockout_time_remaining is not None

        if is_locked:
            title = "Account Locked"
        elif is_tampered:
            title = "Application Corrupted"
        else:
            title = "Trial Period Expired"
        
        dialog.title(title)
        
        dialog.update_idletasks()
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        window_width = 780
        window_height = 350  # Increased height for the countdown
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        dialog.grab_set()
        dialog.resizable(False, False)
        main_frame = ctk.CTkFrame(dialog, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text=title, font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        if is_locked:
            message = "Too many incorrect login attempts. For your security, access has been temporarily blocked."
            ctk.CTkLabel(main_frame, text=message, justify="center", text_color="orange").pack(pady=10)
            
            countdown_label = ctk.CTkLabel(main_frame, text="", font=ctk.CTkFont(size=16, weight="bold"))
            countdown_label.pack(pady=10)

            def update_countdown(seconds_left):
                if seconds_left > 0:
                    minutes, seconds = divmod(seconds_left, 60)
                    hours, minutes = divmod(minutes, 60)
                    if hours > 0:
                        time_str = f"{hours}h {minutes:02d}m {seconds:02d}s"
                    else:
                        time_str = f"{minutes:02d}m {seconds:02d}s"
                    countdown_label.configure(text=f"Time remaining: {time_str}")
                    dialog.after(1000, update_countdown, seconds_left - 1)
                else:
                    countdown_label.configure(text="You can now restart the application.")
            
            update_countdown(lockout_time_remaining)

        elif is_tampered:
            message = "Critical security components have been modified or corrupted, or tampering has been detected.\nThe application cannot continue.\n\nPlease contact support and provide your Machine ID to resolve this issue."
            ctk.CTkLabel(main_frame, text=message, justify="center", text_color="red").pack(pady=10)
        else: # EXPIRED
            message = "The 7-day trial period has ended. Please upgrade to the full version.\n\nAll your data is safe but cannot be accessed until you activate."
            ctk.CTkLabel(main_frame, text=message, justify="center").pack(pady=10)

        machine_id_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        machine_id_frame.pack(pady=10)
        ctk.CTkLabel(machine_id_frame, text="Your Machine ID:").pack(side="left", padx=(10, 5))
        machine_id_entry = ctk.CTkEntry(machine_id_frame, width=300)
        machine_id_entry.insert(0, self._get_machine_id())
        machine_id_entry.configure(state="readonly")
        machine_id_entry.pack(side="left")
        
        def copy_machine_id():
            dialog.clipboard_clear()
            dialog.clipboard_append(self._get_machine_id())
            dialog.update()
            copy_button.configure(text="✓ Copied!")
            dialog.after(2000, lambda: copy_button.configure(text="📋"))
        
        copy_button = ctk.CTkButton(machine_id_frame, text="📋", width=30, height=30, command=copy_machine_id, font=ctk.CTkFont(size=14))
        copy_button.pack(side="left", padx=(5, 0))

        def on_contact():
            webbrowser.open("https://wa.me/212623422858")

        def on_exit():
            self.parent_window.destroy()

        def on_activate():
            input_dialog = ctk.CTkInputDialog(text="Please enter your license key:", title="Activate Full Version")
            license_key = input_dialog.get_input()
            if not license_key: return

            machine_id = self._get_machine_id()
            SECRET_SALT = "a-very-secret-and-long-salt-that-is-hard-to-guess"
            expected_key = hashlib.sha256((machine_id + SECRET_SALT).encode()).hexdigest()

            if license_key.strip() == expected_key:
                if self.activate_full_version():
                    dialog.destroy()
                    if self.restart_callback:
                        self.restart_callback()
            else:
                messagebox.showerror("Activation Failed", "The license key is incorrect. Please verify the key and try again.")

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        if not is_locked:
            ctk.CTkButton(button_frame, text="Contact Developer", command=on_contact, width=180, height=40).pack(side="left", padx=10)
        
            if is_tampered:
                # In a real scenario, we might have a different call to action here,
                # but for now, we just show the contact button.
                activate_button = HoldButton(
                    button_frame, 
                    text="Activate", 
                    hold_callback=on_activate, 
                    width=120, 
                    height=40,
                    fg_color="#4CAF50", 
                    hover_color="#45a049"
                )
                activate_button.pack(side="left", padx=10)
            else:
                activate_button = ctk.CTkButton(button_frame, text="Activate", command=on_activate, width=120, height=40,fg_color="#4CAF50", hover_color="#45a049")
                activate_button.pack(side="left", padx=10)

        ctk.CTkButton(button_frame, text="Exit", command=on_exit, width=100, height=40, fg_color="#D32F2F", hover_color="#D10E00").pack(side="right", padx=10)
            
        dialog.wait_window()
        return self.status == "FULL"

    def show_lockout_dialog(self, remaining_seconds):
        """
        A specific method to show the lockout dialog.
        This is a wrapper around the enhanced show_trial_expired_dialog.
        """
        self.show_trial_expired_dialog(lockout_time_remaining=remaining_seconds)