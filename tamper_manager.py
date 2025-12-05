import os
import platform
import hashlib
import json
import hmac
import base64
from datetime import datetime
import sys
from machine_id_utils import generate_machine_id

class TamperManager:
    """
    Manages advanced anti-tampering mechanisms, including watermarking and
    application integrity checks.
    """
    def __init__(self, app_files_to_monitor=None):
        self.machine_id = generate_machine_id()
        
        # If the application is frozen (e.g., by PyInstaller), monitor the executable itself.
        # Otherwise, monitor the individual source files.
        if getattr(sys, 'frozen', False):
            self.app_files = [sys.executable]
        else:
            self.app_files = app_files_to_monitor or [
                'main.py', 'tamper_manager.py',
                'machine_id_utils.py', 'secure_file_manager.py'
            ]
        
        self._watermark_cache = None
        if platform.system() == "Windows":
            self.registry_key_path = self._get_registry_key_path()
            self.registry_value_name = self._get_registry_value_name()
            self.watermark_path = None
        else:
            self.watermark_path = self._get_watermark_path()

    def _get_registry_key_path(self):
        return r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility"

    def _get_registry_value_name(self):
        return hashlib.sha256(f"sys-integrity-{self.machine_id}".encode()).hexdigest()[:16]

    def _get_watermark_path(self):
        system = platform.system()
        filename = self._get_registry_value_name()

        if system == 'Linux':
            base_path = "/var/lib"
            filename = f".{filename}"
            if not os.access(base_path, os.W_OK):
                base_path = os.path.expanduser("~/.local/share/systemd")
        elif system == 'Darwin':
            base_path = "/private/var/db"
            filename = f".{filename}"
            if not os.access(base_path, os.W_OK):
                base_path = os.path.expanduser("~/Library/Application Support/system")
        else:
            # Fallback for other non-Windows systems
            base_path = os.path.expanduser("~")
            filename = ".sys_integrity_watermark"

        os.makedirs(base_path, exist_ok=True)
        return os.path.join(base_path, filename)

    def _encrypt_data(self, data_dict):
        key = self.machine_id
        json_data = json.dumps(data_dict, sort_keys=True)
        xored = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(json_data, key * (len(json_data) // len(key) + 1)))
        return base64.b64encode(xored.encode()).decode()

    def _decrypt_data(self, encrypted_str):
        key = self.machine_id
        xored_bytes = base64.b64decode(encrypted_str)
        xored = xored_bytes.decode()
        json_data = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(xored, key * (len(xored) // len(key) + 1)))
        return json.loads(json_data)

    def _sign_data(self, data_str):
        return hmac.new(self.machine_id.encode(), data_str.encode(), hashlib.sha256).hexdigest()

    def _write_to_registry(self, payload):
        import winreg
        keys_to_try = [
            (winreg.HKEY_LOCAL_MACHINE, self.registry_key_path),
            (winreg.HKEY_CURRENT_USER, self.registry_key_path)
        ]
        for hkey, key_path in keys_to_try:
            try:
                with winreg.CreateKey(hkey, key_path) as key:
                    winreg.SetValueEx(key, self.registry_value_name, 0, winreg.REG_SZ, payload)
                return True
            except OSError:
                continue
        return False

    def _read_from_registry(self):
        import winreg
        keys_to_try = [
            (winreg.HKEY_LOCAL_MACHINE, self.registry_key_path),
            (winreg.HKEY_CURRENT_USER, self.registry_key_path)
        ]
        for hkey, key_path in keys_to_try:
            try:
                with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ) as key:
                    value, _ = winreg.QueryValueEx(key, self.registry_value_name)
                    return value
            except (FileNotFoundError, PermissionError):
                continue
            except OSError:
                return "TAMPERED"
        return None

    def _write_watermark(self, data_dict):
        try:
            self._watermark_cache = data_dict # Update cache
            encrypted_data = self._encrypt_data(data_dict)
            signature = self._sign_data(encrypted_data)
            payload = json.dumps({'data': encrypted_data, 'sig': signature})

            if platform.system() == "Windows":
                return self._write_to_registry(payload)
            
            temp_path = self.watermark_path + ".tmp"
            with open(temp_path, 'w') as f:
                f.write(payload)
            
            os.replace(temp_path, self.watermark_path)
            
            return True
        except (IOError, OSError, PermissionError):
            return False

    def _read_watermark(self):
        if self._watermark_cache:
            return self._watermark_cache

        payload = None
        if platform.system() == "Windows":
            payload_str = self._read_from_registry()
            if payload_str is None:
                return None
            if payload_str == "TAMPERED":
                return "TAMPERED"
            try:
                payload = json.loads(payload_str)
            except json.JSONDecodeError:
                return "TAMPERED"
        else:
            if not os.path.exists(self.watermark_path):
                return None
            try:
                with open(self.watermark_path, 'r') as f:
                    payload = json.load(f)
            except (IOError, OSError, json.JSONDecodeError):
                return "TAMPERED"

        if payload is None:
            return None

        try:
            encrypted_data = payload['data']
            signature = payload['sig']
            if not hmac.compare_digest(self._sign_data(encrypted_data), signature):
                return "TAMPERED"
            decrypted_data = self._decrypt_data(encrypted_data)
            if decrypted_data.get('machine_id_hash') != hashlib.sha256(self.machine_id.encode()).hexdigest():
                return "TAMPERED"
            self._watermark_cache = decrypted_data
            return decrypted_data
        except (KeyError, TypeError):
            return "TAMPERED"

    def get_or_create_watermark(self):
        watermark = self._read_watermark()
        if watermark is None:
            new_watermark = {
                'status': 'INITIALIZED',
                'timestamp': datetime.utcnow().isoformat(),
                'machine_id_hash': hashlib.sha256(self.machine_id.encode()).hexdigest(),
                'file_hashes': {},
                'start_date': None,
                'shutdown_status': 'RUNNING'
            }
            self._write_watermark(new_watermark)
            return new_watermark
        return watermark

    def update_watermark_field(self, key, value):
        data = self.get_or_create_watermark()
        if data == "TAMPERED": return
        data[key] = value
        data['timestamp'] = datetime.utcnow().isoformat()
        self._write_watermark(data)

    def _calculate_file_hash(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError:
            return None

    def _generate_and_store_hashes(self):
        watermark = self.get_or_create_watermark()
        if watermark == "TAMPERED": return
        if not watermark.get('file_hashes'):
            hashes = {}
            for filename in self.app_files:
                hash_val = self._calculate_file_hash(filename)
                if hash_val:
                    hashes[filename] = hash_val
            watermark['file_hashes'] = hashes
            self._write_watermark(watermark)

    def verify_app_integrity(self):
        watermark = self.get_or_create_watermark()
        if watermark == "TAMPERED": return False
        stored_hashes = watermark.get('file_hashes')
        if not stored_hashes:
            self._generate_and_store_hashes()
            return True
        for filename, stored_hash in stored_hashes.items():
            current_hash = self._calculate_file_hash(filename)
            if current_hash != stored_hash:
                return False
        return True

    def perform_full_check(self):
        watermark = self.get_or_create_watermark()
        if watermark == "TAMPERED" or watermark.get('status') == "TAMPERED":
            return "TAMPERED"

        # If the app was not shut down cleanly, verify integrity but don't immediately flag as tampered.
        # This allows recovery from crashes or power failures.
        if watermark.get('shutdown_status') == 'RUNNING':
            if not self.verify_app_integrity():
                self.update_watermark_field('status', 'TAMPERED')
                return "TAMPERED"
            # If integrity is fine, we assume it was a crash and proceed.
            # The status will be updated to RUNNING for the new session.
        elif not self.verify_app_integrity():
            self.update_watermark_field('status', 'TAMPERED')
            return "TAMPERED"

        # Mark the current session as running
        self.update_watermark_field('shutdown_status', 'RUNNING')
        return "OK"

    def update_shutdown_status(self, status='SHUTDOWN_CLEAN'):
        """
        Updates the shutdown status in the watermark file.
        This should be called on graceful application exit.
        """
        self.update_watermark_field('shutdown_status', status)

    def get_watermark_data(self):
        return self.get_or_create_watermark()
