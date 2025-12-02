import os
import json
from datetime import datetime, timedelta
import platform
import webbrowser
from tkinter import messagebox
import customtkinter as ctk
import hashlib
from machine_id_utils import generate_machine_id
from guardian_anchor import GuardianAnchor
from guardian_observer import GuardianObserver
from ui_utils import ThemedToplevel
import logging

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

    def __init__(self, parent_window, settings_manager, restart_callback=None):
        self.TRIAL_PERIOD = timedelta(days=7)
        self.LICENSE_FILE = self._get_obfuscated_license_path()

        self.parent_window = parent_window
        self.restart_callback = restart_callback
        self._settings_manager = settings_manager
        
        if self._settings_manager:
            self._settings = self._settings_manager.read_settings() or {}
        else:
            self._settings = {}
        
        # Load state from settings or initialize to defaults
        self.failed_activation_attempts = self._settings.get('activation_failed_attempts', 0)
        
        lockout_end_iso = self._settings.get('activation_lockout_end_time')
        self.activation_lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None

        # Instantiate the guardians
        self.anchor = GuardianAnchor()
        self.observer = GuardianObserver(self.anchor)

        self.is_trial_active = False
        self.minutes_remaining = 0
        self.status = self.check_trial_status()
        self._validate_activation_state()

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

    def _validate_activation_state(self):
        """Sanity check and cleanup of the activation lockout state."""
        if self.is_activation_locked_out():
            if datetime.now() >= self.activation_lockout_end_time:
                self.failed_activation_attempts = 0
                self.activation_lockout_end_time = None
                self._save_activation_state()

    def _save_activation_state(self):
        """Saves the current activation lockout state to the settings file."""
        self._settings['activation_failed_attempts'] = self.failed_activation_attempts
        self._settings['activation_lockout_end_time'] = self.activation_lockout_end_time.isoformat() if self.activation_lockout_end_time else None
        
        if self._settings_manager:
            self._settings_manager.write_settings(self._settings, allow_plaintext=True)

    def is_activation_locked_out(self) -> bool:
        """Checks if the activation is currently in a hard lockout state."""
        if not self.activation_lockout_end_time:
            return False
        
        if datetime.now() < self.activation_lockout_end_time:
            return True
        else:
            # Lockout has just expired, so reset and report not locked.
            self.failed_activation_attempts = 0
            self.activation_lockout_end_time = None
            self._save_activation_state()
            return False

    def get_remaining_activation_lockout_time(self) -> int:
        """Gets the remaining activation lockout time in seconds."""
        if not self.is_activation_locked_out():
            return 0
        
        remaining = self.activation_lockout_end_time - datetime.now()
        return max(0, int(remaining.total_seconds()))

    def get_remaining_seconds(self):
        """
        Calculates the remaining trial time in seconds.
        This is a real-time check and does not rely on the cached status.
        """
        if self.status != "TRIAL" and not self.is_trial_active:
            return 0

        # We need to re-check the anchor to get the most up-to-date timestamp
        # in case it was modified.
        anchor_status, anchor_data = self.anchor.check()
        install_ts_str = anchor_data.get('install_ts')
        
        if not install_ts_str or "TAMPERED" in anchor_status:
            self.status = "TAMPERED"
            self.is_trial_active = False
            return 0

        try:
            install_ts = datetime.fromisoformat(install_ts_str)
            elapsed = datetime.utcnow() - install_ts
            remaining = self.TRIAL_PERIOD - elapsed
            
            if remaining.total_seconds() <= 0:
                self.status = "EXPIRED"
                self.is_trial_active = False
                return 0
            
            return remaining.total_seconds()
        except (ValueError, TypeError):
            self.status = "TAMPERED"
            self.is_trial_active = False
            return 0

    def check_trial_status(self):
        """
        Checks the trial status by consulting the guardians.
        This is the single point of truth for the trial state.
        """
        logging.info("--- Starting Trial Status Check ---")
        # 1. A valid license file always wins.
        if os.path.exists(self.LICENSE_FILE):
            logging.info(f"License file found at {self.LICENSE_FILE}. Status: FULL")
            return "FULL"

        # 2. Check the anchor guardian for the installation timestamp and shutdown status.
        anchor_status, anchor_data = self.anchor.check()
        logging.info(f"Guardian Anchor check returned: status={anchor_status}, data={anchor_data}")

        if anchor_status == "OK_UNEXPECTED_SHUTDOWN":
            # Gracefully handle the unexpected shutdown. Log it, but don't tamper the app.
            # The observer check will be skipped because its state might be unreliable.
            logging.warning("Guardian Anchor reported an unexpected shutdown.")
            pass  # Continue to expiration check
        elif "TAMPERED" in anchor_status:
            logging.error(f"Guardian Anchor reported tampering. Status: {anchor_status}")
            return "TAMPERED"
        
        install_ts_str = anchor_data.get('install_ts')
        if not install_ts_str:
            logging.error("No installation timestamp found in anchor data. Status: TAMPERED")
            return "TAMPERED"

        # 3. Check for expiration.
        try:
            install_ts = datetime.fromisoformat(install_ts_str)
            current_time_utc = datetime.utcnow()
            elapsed = current_time_utc - install_ts
            
            logging.info(f"Installation timestamp: {install_ts}")
            logging.info(f"Current UTC time: {current_time_utc}")
            logging.info(f"Time elapsed since installation: {elapsed}")
            logging.info(f"Trial period: {self.TRIAL_PERIOD}")

            if elapsed >= self.TRIAL_PERIOD:
                logging.warning("Trial period has expired. Status: EXPIRED")
                return "EXPIRED"
        except (ValueError, TypeError) as e:
            logging.error(f"Error parsing timestamp '{install_ts_str}': {e}. Status: TAMPERED")
            return "TAMPERED"
        
        # 4. If the trial is active and shutdown was clean, check the observer.
        if anchor_status != "OK_UNEXPECTED_SHUTDOWN":
            observer_status = self.observer.check()
            logging.info(f"Guardian Observer check returned: {observer_status}")
            if "TAMPERED" in observer_status:
                logging.error(f"Guardian Observer reported tampering. Status: {observer_status}")
                return "TAMPERED"

        # 5. If we reach here, the trial is active and valid.
        self.is_trial_active = True
        self.minutes_remaining = (self.TRIAL_PERIOD - elapsed).total_seconds() / 60
        logging.info(f"Trial is active. Minutes remaining: {self.minutes_remaining:.2f}. Status: TRIAL")
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
            
            # Set a flag to show activation success message on next login
            self._settings['just_activated'] = True
            self._save_activation_state()
            
            return True
        except Exception as e:
            logging.error(f"Activation failed: {e}")
            return False

    def validate_and_activate(self, license_key):
        """
        Validates a license key and activates the application if the key is correct.
        Manages failed attempts and lockouts.
        """
        if self.is_activation_locked_out():
            return False

        machine_id = self._get_machine_id()
        SECRET_SALT = "a-very-secret-and-long-salt-that-is-hard-to-guess"
        expected_key = hashlib.sha256((machine_id + SECRET_SALT).encode()).hexdigest()

        if license_key and license_key.strip() == expected_key:
            self.failed_activation_attempts = 0
            self.activation_lockout_end_time = None
            self._save_activation_state()
            return self.activate_full_version()
        else:
            self.failed_activation_attempts += 1
            if self.failed_activation_attempts >= 3:
                if self.activation_lockout_end_time and self.activation_lockout_end_time > datetime.now():
                    self.activation_lockout_end_time += timedelta(minutes=30)
                else:
                    self.activation_lockout_end_time = datetime.now() + timedelta(minutes=15)
            self._save_activation_state()
            return False

    def show_trial_expired_dialog(self, lockout_time_remaining=None, from_runtime=False):
        """
        Shows a dialog for expired, tampered, or locked-out states.
        """
        dialog = ThemedToplevel(self.parent_window)
        is_tampered = self.status == "TAMPERED"
        is_login_locked = lockout_time_remaining is not None
        is_activation_locked = self.is_activation_locked_out()

        lockout_time = 0
        if is_login_locked:
            title = "Account Locked"
            lockout_time = lockout_time_remaining
        elif is_activation_locked:
            title = "Activation Locked"
            lockout_time = self.get_remaining_activation_lockout_time()
        elif is_tampered:
            title = "Application Corrupted"
        else:
            title = "Trial Period Expired"
        
        is_locked = is_login_locked or is_activation_locked
        
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

        title_label = ctk.CTkLabel(main_frame, text=title, font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=20)
        
        message_label = ctk.CTkLabel(main_frame, text="", justify="center")
        countdown_label = ctk.CTkLabel(main_frame, text="", font=ctk.CTkFont(size=16, weight="bold"))

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
                dialog.title("Trial Period Expired")
                message_label.configure(text="The 7-day trial period has ended. Please upgrade to the full version.\n\nAll your data is safe but cannot be accessed until you activate.", text_color="white")
                countdown_label.pack_forget()


        if is_locked:
            message = "Too many incorrect attempts. For your security, access has been temporarily blocked."
            if is_activation_locked:
                message = "Too many incorrect activation attempts. For your security, access has been temporarily blocked."
            message_label.configure(text=message, text_color="orange")
            message_label.pack(pady=10)
            countdown_label.pack(pady=10)
            update_countdown(lockout_time)

        elif is_tampered:
            message = "Critical security components have been modified or corrupted, or tampering has been detected.\nThe application cannot continue.\n\nPlease contact support and provide your APPLICATION ID to resolve this issue."
            message_label.configure(text=message, text_color="red")
            message_label.pack(pady=10)
        else: # EXPIRED
            message = "The 7-day trial period has ended. Please upgrade to the full version.\n\nAll your data is safe but cannot be accessed until you activate."
            message_label.configure(text=message)
            message_label.pack(pady=10)

        machine_id_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        machine_id_frame.pack(pady=10)
        ctk.CTkLabel(machine_id_frame, text="Your Application ID:").pack(side="left", padx=(10, 5))
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
            if self.is_activation_locked_out():
                return

            input_dialog = ctk.CTkInputDialog(text="Please enter your license key:", title="Activate Full Version")
            
            # Center the input dialog
            input_dialog.update_idletasks()
            dialog_width = input_dialog.winfo_width()
            dialog_height = input_dialog.winfo_height()
            screen_width = input_dialog.winfo_screenwidth()
            screen_height = input_dialog.winfo_screenheight()
            x = (screen_width - dialog_width) // 2
            y = (screen_height - dialog_height) // 2
            input_dialog.geometry(f"+{x}+{y}")
            
            license_key = input_dialog.get_input()
            
            if self.validate_and_activate(license_key):
                # Create centered success dialog
                success_dialog = ThemedToplevel(dialog)
                success_dialog.title("Activated")
                success_dialog.update_idletasks()
                dialog_width = 400
                dialog_height = 150
                screen_width = success_dialog.winfo_screenwidth()
                screen_height = success_dialog.winfo_screenheight()
                x = (screen_width - dialog_width) // 2
                y = (screen_height - dialog_height) // 2
                success_dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
                success_dialog.resizable(False, False)
                success_dialog.grab_set()
                
                success_frame = ctk.CTkFrame(success_dialog, corner_radius=15)
                success_frame.pack(fill="both", expand=True, padx=20, pady=20)
                
                ctk.CTkLabel(success_frame, text="Thank you for your purchase!\nThe application is now fully activated.", 
                            font=ctk.CTkFont(size=14), justify="center").pack(pady=20)
                
                def close_success():
                    success_dialog.destroy()
                    dialog.destroy()
                    if self.restart_callback:
                        self.restart_callback()
                
                ctk.CTkButton(success_frame, text="OK", command=close_success, width=100, height=35,
                             fg_color="#4CAF50", hover_color="#45a049").pack(pady=10)
                
                success_dialog.wait_window()
            else:
                if self.is_activation_locked_out():
                    new_lockout_time = self.get_remaining_activation_lockout_time()
                    dialog.title("Activation Locked")
                    message_label.configure(text="Too many incorrect activation attempts. For your security, access has been temporarily blocked.", text_color="orange")
                    if not countdown_label.winfo_ismapped():
                        countdown_label.pack(pady=10)
                    update_countdown(new_lockout_time)
                else:
                    attempts_left = 3 - self.failed_activation_attempts
                    if attempts_left == 1:
                        message = "The license key is incorrect. You have 1 attempt remaining."
                    else:
                        message = f"The license key is incorrect. You have {attempts_left} attempts remaining."
                    messagebox.showerror("Activation Failed", message)

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        if from_runtime and self.status == "EXPIRED":
            message_label.configure(text="We're sorry, but your trial period has ended.\nPlease activate the program to continue.")
            ctk.CTkButton(button_frame, text="OK", command=on_exit, width=120, height=40).pack()
        else:
            ctk.CTkButton(button_frame, text="Contact Developer", command=on_contact, width=180, height=40).pack(side="left", padx=10)
    
            if is_tampered:
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
