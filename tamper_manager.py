import os
import platform
import hashlib
import json
import hmac
import base64
from datetime import datetime

from machine_id_utils import generate_machine_id

class TamperManager:
    """
    Manages advanced anti-tampering mechanisms, including watermarking and
    application integrity checks.
    """
    def __init__(self, app_files_to_monitor=None):
        self.machine_id = generate_machine_id()
        self.app_files = app_files_to_monitor or [
            'main.py', 'trial_manager.py', 'tamper_manager.py',
            'machine_id_utils.py', 'secure_file_manager.py'
        ]
        self.watermark_path = self._get_watermark_path()
        self._watermark_cache = None

    def _get_watermark_path(self):
        system = platform.system()
        filename = hashlib.sha256(f"sys-integrity-{self.machine_id}".encode()).hexdigest()[:16]

        if system == 'Windows':
            base_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
            if not os.path.exists(base_path) or not os.access(base_path, os.W_OK):
                base_path = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "SystemLogs")
        elif system == 'Linux':
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

    def _write_watermark(self, data_dict):
        try:
            self._watermark_cache = data_dict # Update cache
            encrypted_data = self._encrypt_data(data_dict)
            signature = self._sign_data(encrypted_data)
            payload = json.dumps({'data': encrypted_data, 'sig': signature})
            
            temp_path = self.watermark_path + ".tmp"
            with open(temp_path, 'w') as f:
                f.write(payload)
            
            os.replace(temp_path, self.watermark_path)
            
            if platform.system() == 'Windows':
                os.system(f"attrib +h +s {self.watermark_path}")
            return True
        except (IOError, OSError, PermissionError):
            return False

    def _read_watermark(self):
        if self._watermark_cache:
            return self._watermark_cache
        if not os.path.exists(self.watermark_path):
            return None
        try:
            with open(self.watermark_path, 'r') as f:
                payload = json.load(f)
            encrypted_data = payload['data']
            signature = payload['sig']
            if not hmac.compare_digest(self._sign_data(encrypted_data), signature):
                return "TAMPERED"
            decrypted_data = self._decrypt_data(encrypted_data)
            if decrypted_data.get('machine_id_hash') != hashlib.sha256(self.machine_id.encode()).hexdigest():
                return "TAMPERED"
            self._watermark_cache = decrypted_data
            return decrypted_data
        except Exception:
            return "TAMPERED"

    def get_or_create_watermark(self):
        watermark = self._read_watermark()
        if watermark is None:
            new_watermark = {
                'status': 'INITIALIZED',
                'timestamp': datetime.utcnow().isoformat(),
                'machine_id_hash': hashlib.sha256(self.machine_id.encode()).hexdigest(),
                'file_hashes': {},
                'start_date': None
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
        if not self.verify_app_integrity():
            self.update_watermark_field('status', 'TAMPERED')
            return "TAMPERED"
        return "OK"

    def get_watermark_data(self):
        return self.get_or_create_watermark()
