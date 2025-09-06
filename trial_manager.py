import os
import json
from datetime import datetime, timedelta
import base64
import platform
import subprocess
import tkinter as tk
import webbrowser
from tkinter import messagebox
import customtkinter as ctk
import hashlib

try:
    import winreg
except ImportError:
    winreg = None

class TrialManager:
    _machine_id = None  # Cache for machine ID

    def __init__(self, parent_window, secure_file_manager, restart_callback=None):
        self.TRIAL_MINUTES = 2  # Set trial duration to 2 minutes for testing
        self.LICENSE_FILE = os.path.expanduser("~/.sv_license")

        # Primary storage
        self.REGISTRY_PATH = r"Software\SecureVaultPro"
        self.REGISTRY_KEY = "InstallInfo"
        self.DOTFILE_PATH = os.path.expanduser("~/.sv_meta")

        # Tertiary storage (covert)
        self.TERTIARY_PATH = self._get_tertiary_path()

        self.secure_file_manager = secure_file_manager
        self.parent_window = parent_window
        self.restart_callback = restart_callback
        self.is_trial_active = False
        self.minutes_remaining = 0
        self.status = self.check_trial_status()

    def _get_machine_id(self):
        if TrialManager._machine_id:
            return TrialManager._machine_id

        try:
            system = platform.system()
            if system == 'Windows':
                command = "wmic csproduct get uuid"
                output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
                machine_id = output.split('\n')[1].strip()
            elif system == 'Linux':
                try:
                    with open('/sys/class/dmi/id/product_uuid', 'r') as f:
                        machine_id = f.read().strip()
                except FileNotFoundError:
                    with open('/var/lib/dbus/machine-id', 'r') as f:
                        machine_id = f.read().strip()
            elif system == 'Darwin': # macOS
                command = "ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'"
                output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
                machine_id = output.strip()
            else:
                machine_id = "unknown_platform_fallback_key"
            
            if not machine_id: # Handle cases where command returns empty string
                machine_id = "default_fallback_key_on_empty"

        except Exception:
            machine_id = "default_fallback_key_on_error"

        TrialManager._machine_id = machine_id
        return machine_id

    def _encrypt_data(self, data_dict):
        key = self._get_machine_id()
        json_data = json.dumps(data_dict)
        xored = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(json_data, key * (len(json_data) // len(key) + 1)))
        reversed_str = xored[::-1]
        return base64.b64encode(reversed_str.encode()).decode()

    def _decrypt_data(self, encrypted_str):
        key = self._get_machine_id()
        reversed_str_bytes = base64.b64decode(encrypted_str)
        reversed_str = reversed_str_bytes.decode()
        xored = reversed_str[::-1]
        json_data = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(xored, key * (len(xored) // len(key) + 1)))
        return json.loads(json_data)

    def _get_os_specific_storage_path(self):
        system = platform.system()
        if system == 'Windows' and winreg:
            return 'registry'
        else:
            return 'dotfile'

    def _read_primary_storage(self):
        storage_type = self._get_os_specific_storage_path()
        try:
            if storage_type == 'registry':
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REGISTRY_PATH, 0, winreg.KEY_READ) as key:
                    encrypted_data, _ = winreg.QueryValueEx(key, self.REGISTRY_KEY)
            else:
                if not os.path.exists(self.DOTFILE_PATH): return None
                with open(self.DOTFILE_PATH, 'r') as f: encrypted_data = f.read()
            
            decrypted_dict = self._decrypt_data(encrypted_data)
            decrypted_dict['start_date'] = datetime.fromisoformat(decrypted_dict['start_date'])
            decrypted_dict['last_run_date'] = datetime.fromisoformat(decrypted_dict['last_run_date'])
            return decrypted_dict
        except Exception:
            return None

    def _write_primary_storage(self, data_dict):
        storage_type = self._get_os_specific_storage_path()
        try:
            serializable_dict = {
                'start_date': data_dict['start_date'].isoformat(),
                'last_run_date': data_dict['last_run_date'].isoformat()
            }
            encrypted_data = self._encrypt_data(serializable_dict)
            if storage_type == 'registry':
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.REGISTRY_PATH) as key:
                    winreg.SetValueEx(key, self.REGISTRY_KEY, 0, winreg.REG_SZ, encrypted_data)
            else:
                with open(self.DOTFILE_PATH, 'w') as f: f.write(encrypted_data)
                if platform.system() == 'Windows': os.system(f"attrib +h {self.DOTFILE_PATH}")
            return True
        except Exception:
            return False

    def _read_secondary_storage(self):
        try:
            if not self.secure_file_manager: return None
            settings = self.secure_file_manager.read_settings()
            if settings and 'trial_data' in settings and settings['trial_data']:
                trial_data = settings['trial_data']
                trial_data['start_date'] = datetime.fromisoformat(trial_data['start_date'])
                trial_data['last_run_date'] = datetime.fromisoformat(trial_data['last_run_date'])
                return trial_data
            return None
        except Exception:
            return None

    def _write_secondary_storage(self, data_dict):
        try:
            if not self.secure_file_manager: return False
            settings = self.secure_file_manager.read_settings()
            if not settings: settings = {}
            serializable_dict = {
                'start_date': data_dict['start_date'].isoformat(),
                'last_run_date': data_dict['last_run_date'].isoformat()
            }
            settings['trial_data'] = serializable_dict
            self.secure_file_manager.write_settings(settings)
            return True
        except Exception:
            return False

    def _get_tertiary_path(self):
        system = platform.system()
        if system == 'Windows':
            path = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "SystemLogs")
            if not os.path.exists(path): os.makedirs(path, exist_ok=True)
            return os.path.join(path, "updater.log")
        elif system == 'Linux':
            path = os.path.expanduser("~/.config/systemd")
            if not os.path.exists(path): os.makedirs(path, exist_ok=True)
            return os.path.join(path, "user.log")
        elif system == 'Darwin':
            path = os.path.expanduser("~/Library/Application Support")
            if not os.path.exists(path): os.makedirs(path, exist_ok=True)
            return os.path.join(path, ".system_events.log")
        return None # Fallback for unsupported systems

    def _read_tertiary_storage(self):
        if not self.TERTIARY_PATH or not os.path.exists(self.TERTIARY_PATH):
            return None
        try:
            with open(self.TERTIARY_PATH, 'r') as f:
                encrypted_data = f.read()
            decrypted_dict = self._decrypt_data(encrypted_data)
            decrypted_dict['start_date'] = datetime.fromisoformat(decrypted_dict['start_date'])
            decrypted_dict['last_run_date'] = datetime.fromisoformat(decrypted_dict['last_run_date'])
            return decrypted_dict
        except Exception:
            return None

    def _write_tertiary_storage(self, data_dict):
        if not self.TERTIARY_PATH: return False
        try:
            serializable_dict = {
                'start_date': data_dict['start_date'].isoformat(),
                'last_run_date': data_dict['last_run_date'].isoformat()
            }
            encrypted_data = self._encrypt_data(serializable_dict)
            with open(self.TERTIARY_PATH, 'w') as f:
                f.write(encrypted_data)
            # Make the file hidden on systems that support it
            if platform.system() == 'Windows':
                os.system(f"attrib +h {self.TERTIARY_PATH}")
            return True
        except Exception:
            return False

    def check_trial_status(self):
        if os.path.exists(self.LICENSE_FILE):
            return "FULL"

        data1 = self._read_primary_storage()
        data2 = self._read_secondary_storage()
        data3 = self._read_tertiary_storage()
        
        all_data = [data1, data2, data3]
        existing_data = [d for d in all_data if d is not None]
        
        trial_data = None
        tampered = False

        if len(existing_data) == 3:
            # All locations exist, check for consistency
            start_dates = [d['start_date'] for d in existing_data]
            last_run_dates = [d['last_run_date'] for d in existing_data]
            if (max(start_dates) - min(start_dates)).total_seconds() > 60 or \
               (max(last_run_dates) - min(last_run_dates)).total_seconds() > 60:
                tampered = True
            trial_data = existing_data[0] # Use primary as the source of truth
        elif len(existing_data) > 0 and len(existing_data) < 3:
            # Some but not all locations exist - tampering detected
            tampered = True
            # Use the most recent valid data and restore other locations
            authoritative_data = max(existing_data, key=lambda d: d['last_run_date'])
            self._write_primary_storage(authoritative_data)
            self._write_secondary_storage(authoritative_data)
            self._write_tertiary_storage(authoritative_data)
            trial_data = authoritative_data
        else: # No data found, fresh install
            now = datetime.now()
            trial_data = {'start_date': now, 'last_run_date': now}
            self._write_primary_storage(trial_data)
            self._write_secondary_storage(trial_data)
            self._write_tertiary_storage(trial_data)

        # Clock tampering detection
        now = datetime.now()
        # Allow a 5-minute grace period for small clock adjustments
        if (trial_data['last_run_date'] - now) > timedelta(minutes=5):
            tampered = True

        if tampered:
            return "EXPIRED"

        # Trial period calculation
        elapsed = now - trial_data['start_date']
        if (elapsed.total_seconds() / 60) >= self.TRIAL_MINUTES:
            trial_data['last_run_date'] = now
            self._write_primary_storage(trial_data)
            self._write_secondary_storage(trial_data)
            self._write_tertiary_storage(trial_data)
            return "EXPIRED"
        
        # Update last_run_date for next time
        trial_data['last_run_date'] = now
        self._write_primary_storage(trial_data)
        self._write_secondary_storage(trial_data)
        self._write_tertiary_storage(trial_data)

        self.is_trial_active = True
        self.minutes_remaining = self.TRIAL_MINUTES - (elapsed.total_seconds() / 60)
        return "TRIAL"

    def activate_full_version(self):
        try:
            with open(self.LICENSE_FILE, 'w') as f:
                f.write(json.dumps({
                    'purchase_date': datetime.now().isoformat(),
                    'license_key': self._get_machine_id() # Tie license to machine
                }))
            if platform.system() == 'Windows':
                os.system(f"attrib +h {self.LICENSE_FILE}")
            self.status = "FULL"
            messagebox.showinfo("Activated", "Thank you for your purchase! The application is now fully activated.")
            return True
        except Exception:
            messagebox.showerror("Error", "Activation failed. Please contact support.")
            return False

    def show_trial_expired_dialog(self):
        dialog = ctk.CTkToplevel(self.parent_window)
        dialog.title("Trial Period Expired")
        
        dialog.update_idletasks()  # Update window geometry
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        window_width = 780
        window_height = 300
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        dialog.grab_set()
        #dialog.resizable(False, False)
        main_frame = ctk.CTkFrame(dialog, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(main_frame, text="Trial Period Expired", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        ctk.CTkLabel(main_frame, text="The 7-day trial period has ended. Please upgrade your current version to the full version.\n\n\nNote: All your accounts are saved and will not be deleted, but you will not be able to access them until you obtain the full version.\n\nContact the developer if you want the full version now.", justify="center").pack(pady=10)
        
        machine_id_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        machine_id_frame.pack(pady=10)
        ctk.CTkLabel(machine_id_frame, text="Your Machine ID:").pack(side="left", padx=(10, 5))
        machine_id_entry = ctk.CTkEntry(machine_id_frame, width=300)
        machine_id_entry.insert(0, self._get_machine_id())
        machine_id_entry.configure(state="readonly")
        machine_id_entry.pack(side="left")

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        def on_contact():
            webbrowser.open("https://wa.me/212623422858")

        def on_exit():
            self.parent_window.destroy()

        def on_activate():
            input_dialog = ctk.CTkInputDialog(text="Please enter your license key:", title="Activate Full Version")
            license_key = input_dialog.get_input()
            if not license_key:
                return

            machine_id = self._get_machine_id()
            
            # This salt must be identical to the one in generate_license.py
            SECRET_SALT = "a-very-secret-and-long-salt-that-is-hard-to-guess"
            
            expected_key = hashlib.sha256((machine_id + SECRET_SALT).encode()).hexdigest()

            if license_key.strip() == expected_key:
                if self.activate_full_version():
                    dialog.destroy()
                    if self.restart_callback:
                        self.restart_callback()
            else:
                messagebox.showerror("Activation Failed", "The license key is incorrect for this machine.")

        ctk.CTkButton(button_frame, text="Contact Developer", command=on_contact, width=180, height=40).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Activate", command=on_activate, width=120, height=40).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Exit", command=on_exit, width=100, height=40, fg_color="#D32F2F").pack(side="right", padx=10)
        dialog.wait_window()
        return self.status == "FULL"
