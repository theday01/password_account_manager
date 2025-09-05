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

try:
    import winreg
except ImportError:
    winreg = None

class TrialManager:
    _machine_id = None  # Cache for machine ID

    def __init__(self, parent_window, secure_file_manager):
        self.TRIAL_MINUTES = 2  # Set trial duration to 2 minutes for testing
        self.LICENSE_FILE = os.path.expanduser("~/.sv_license")

        # Primary storage
        self.REGISTRY_PATH = r"Software\SecureVaultPro"
        self.REGISTRY_KEY = "InstallInfo"
        self.DOTFILE_PATH = os.path.expanduser("~/.sv_meta")

        self.secure_file_manager = secure_file_manager
        self.parent_window = parent_window
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

    def check_trial_status(self):
        if os.path.exists(self.LICENSE_FILE):
            return "FULL"

        data1 = self._read_primary_storage()
        data2 = self._read_secondary_storage()
        
        trial_data = None
        tampered = False

        # Cross-validation logic
        if data1 and data2:
            if abs((data1['start_date'] - data2['start_date']).total_seconds()) > 60 or \
               abs((data1['last_run_date'] - data2['last_run_date']).total_seconds()) > 60:
                tampered = True
            trial_data = data1
        elif data1 and not data2:
            tampered = True
            self._write_secondary_storage(data1)
            trial_data = data1
        elif not data1 and data2:
            tampered = True
            self._write_primary_storage(data2)
            trial_data = data2
        else: # Both missing, fresh install
            now = datetime.now()
            trial_data = {'start_date': now, 'last_run_date': now}
            self._write_primary_storage(trial_data)
            self._write_secondary_storage(trial_data)
        
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
            # Update last run date even if expired, to prevent rolling back time to bypass
            trial_data['last_run_date'] = now
            self._write_primary_storage(trial_data)
            self._write_secondary_storage(trial_data)
            return "EXPIRED"
        
        # Update last_run_date for next time
        trial_data['last_run_date'] = now
        self._write_primary_storage(trial_data)
        self._write_secondary_storage(trial_data)

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
        dialog.title("Trial Expired")
        dialog.geometry("400x250")
        dialog.grab_set()
        dialog.resizable(False, False)
        main_frame = ctk.CTkFrame(dialog, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(main_frame, text="Trial Period Expired", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        ctk.CTkLabel(main_frame, text="The 7-day trial period has ended. Please upgrade your current version to the full version.\nContact the developer if you want the full version now.", justify="center").pack(pady=10)
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        def on_contact():
            webbrowser.open("https://wa.me/212623422858")

        def on_exit():
            self.parent_window.destroy()

        ctk.CTkButton(button_frame, text="Contact Developer", command=on_contact, width=180, height=40).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Exit", command=on_exit, width=100, height=40, fg_color="#D32F2F").pack(side="right", padx=10)
        dialog.wait_window()
        return self.status == "FULL"
