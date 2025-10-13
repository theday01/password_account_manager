import os
import platform
import hashlib
import json
import hmac
import base64
from datetime import datetime
from typing import Optional

from machine_id_utils import generate_machine_id

class GuardianAnchor:
    """
    The Anchor Guardian. Its sole purpose is to create and verify a single,
    persistent file in a secure location to act as the ultimate source of truth
    for the application's installation date and machine identity.
    """
    def __init__(self):
        self.machine_fp = self._get_machine_fingerprint()
        self.anchor_path = self._get_anchor_path()
        self.backup_anchor_path = self._get_backup_anchor_path()

    def _get_backup_anchor_path(self):
        """
        Determines a secondary, user-writable, and even more obscure path for the backup anchor file.
        This provides redundancy in case the primary anchor is removed.
        """
        system = platform.system()
        # Different filename to avoid conflicts and make it less obvious
        filename = f"sv-ts-validation-{hashlib.sha256(self.machine_fp.encode()).hexdigest()[:16]}.dat"

        if system == 'Windows':
            # A path within the WinSxS directory is highly obscure and unlikely to be cleared.
            # Requires admin in theory, but we're writing to a subdirectory we create.
            # Let's try a safer, user-writable but still obscure path first.
            base_path = os.path.join(os.environ.get("APPDATA"), "Microsoft", "Windows", "Caches")
        elif system == 'Linux':
            # A hidden file in a non-obvious, typically cache-related directory.
            base_path = os.path.expanduser("~/.cache/fontconfig")
            filename = f".{filename}"
        elif system == 'Darwin': # macOS
            # A user-specific cache directory that is less likely to be cleared by users.
            base_path = os.path.expanduser("~/Library/Caches/com.apple.helpd")
            filename = f".{filename}" # Hidden file
        else:
            # Fallback to a hidden directory in the user's home.
            base_path = os.path.expanduser("~/.local/state")
            filename = f".{filename}"

        os.makedirs(base_path, exist_ok=True)
        return os.path.join(base_path, filename)

    def _get_machine_fingerprint(self):
        """
        Generates a robust, unique fingerprint for the machine.
        For now, this relies on the existing utility, but could be expanded.
        """
        return generate_machine_id()

    def _get_anchor_path(self):
        """
        Determines a user-writable, OS-specific, and obscure path for the anchor file.
        This resolves permission errors when the app runs as a standard user.
        """
        system = platform.system()
        filename = f"sv-anchor-{hashlib.sha256(self.machine_fp.encode()).hexdigest()[:16]}.cfg"

        if system == 'Windows':
            # This path is user-writable and obscure.
            base_path = os.path.join(os.environ.get("LOCALAPPDATA"), "Microsoft", "Credentials")
        elif system == 'Linux':
            # A hidden, user-specific directory that looks like a system cache.
            base_path = os.path.expanduser("~/.local/share/systemd")
            filename = f".{filename}"
        elif system == 'Darwin': # macOS
            # A user-specific library path that mimics system services.
            base_path = os.path.expanduser("~/Library/Application Support/com.apple.TCC")
            filename = f".{filename}" # Hidden file
        else:
            # A generic fallback for other Unix-like systems.
            base_path = os.path.expanduser("~/.config")
            filename = f".{filename}"

        os.makedirs(base_path, exist_ok=True)
        return os.path.join(base_path, filename)

    def _encrypt(self, data_dict):
        """Encrypts data using a key derived from the machine fingerprint."""
        key = self.machine_fp
        json_data = json.dumps(data_dict, sort_keys=True)
        xored = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(json_data, key * (len(json_data) // len(key) + 1)))
        return base64.b64encode(xored.encode()).decode()

    def _decrypt(self, encrypted_str):
        """Decrypts data using a key derived from the machine fingerprint."""
        key = self.machine_fp
        xored_bytes = base64.b64decode(encrypted_str)
        xored = xored_bytes.decode()
        json_data = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(xored, key * (len(xored) // len(key) + 1)))
        return json.loads(json_data)

    def _sign(self, data_str):
        """Signs a string using HMAC-SHA256."""
        return hmac.new(self.machine_fp.encode(), data_str.encode(), hashlib.sha256).hexdigest()

    def _write_anchor(self, data_dict):
        """Encrypts, signs, and writes the anchor data atomically."""
        try:
            encrypted_data = self._encrypt(data_dict)
            signature = self._sign(encrypted_data)
            payload = json.dumps({'data': encrypted_data, 'sig': signature})
            
            temp_path = self.anchor_path + ".tmp"
            with open(temp_path, 'w') as f:
                f.write(payload)
            
            os.replace(temp_path, self.anchor_path)
            
            if platform.system() == 'Windows':
                os.system(f"attrib +h +s {self.anchor_path}")

            # Also write to the backup, but only the timestamp
            self._write_backup_anchor(data_dict['install_ts'])
            return True
        except (IOError, OSError, PermissionError):
            return False

    def _write_backup_anchor(self, install_ts: str):
        """Encrypts and writes only the installation timestamp to the backup."""
        try:
            data_to_encrypt = {'install_ts': install_ts}
            encrypted_ts = self._encrypt(data_to_encrypt)
            # No signature needed, as we verify by successful decryption and ISO format.
            with open(self.backup_anchor_path, 'w') as f:
                f.write(encrypted_ts)
            if platform.system() == 'Windows':
                os.system(f"attrib +h +s {self.backup_anchor_path}")
            return True
        except (IOError, OSError, PermissionError):
            return False

    def _read_backup_anchor(self) -> Optional[str]:
        """Reads and decrypts the installation timestamp from the backup."""
        if not os.path.exists(self.backup_anchor_path):
            return None
        try:
            with open(self.backup_anchor_path, 'r') as f:
                encrypted_ts = f.read()
            decrypted_data = self._decrypt(encrypted_ts)
            install_ts = decrypted_data.get('install_ts')
            # Verify the format to ensure it's a valid timestamp
            datetime.fromisoformat(install_ts)
            return install_ts
        except Exception:
            return None

    def check(self):
        """
        Checks the anchor file's existence and integrity. Creates it if it doesn't exist.

        :return: A tuple of (status, data).
                 Status can be "OK_EXISTS", "OK_CREATED", "OK_UNEXPECTED_SHUTDOWN",
                 "TAMPERED_FINGERPRINT", "TAMPERED_CORRUPT".
                 Data is the anchor data dictionary if status is OK, otherwise None.
        """
        if not os.path.exists(self.anchor_path):
            # If primary anchor is missing, try to restore from backup.
            backup_ts = self._read_backup_anchor()
            if backup_ts:
                anchor_data = {
                    'install_ts': backup_ts,
                    'machine_fp': self.machine_fp,
                    'shutdown_status': 'RUNNING' # Assume unexpected shutdown
                }
                if self._write_anchor(anchor_data):
                    return "OK_RESTORED_FROM_BACKUP", anchor_data
                else:
                    return "TAMPERED_CORRUPT", None

            # If no primary and no backup, this is a fresh install.
            anchor_data = {
                'install_ts': datetime.utcnow().isoformat(),
                'machine_fp': self.machine_fp,
                'shutdown_status': 'RUNNING'
            }
            if self._write_anchor(anchor_data):
                return "OK_CREATED", anchor_data
            else:
                return "TAMPERED_CORRUPT", None

        try:
            with open(self.anchor_path, 'r') as f:
                payload = json.load(f)
            
            encrypted_data = payload['data']
            signature = payload['sig']

            if not hmac.compare_digest(self._sign(encrypted_data), signature):
                return "TAMPERED_CORRUPT", None

            decrypted_data = self._decrypt(encrypted_data)
            if decrypted_data.get('machine_fp') != self.machine_fp:
                original_install_ts = decrypted_data.get('install_ts')
                if original_install_ts:
                    healed_data = {
                        'install_ts': original_install_ts,
                        'machine_fp': self.machine_fp,
                        'shutdown_status': 'RUNNING'
                    }
                    if self._write_anchor(healed_data):
                        return "OK_HEALED", healed_data
                
                return "TAMPERED_FINGERPRINT", None
            
            shutdown_status = decrypted_data.get('shutdown_status')
            if shutdown_status == 'RUNNING':
                # This indicates an unexpected shutdown.
                # We can handle this gracefully in the TrialManager.
                return "OK_UNEXPECTED_SHUTDOWN", decrypted_data

            # If shutdown was clean, update status to RUNNING for the current session.
            decrypted_data['shutdown_status'] = 'RUNNING'
            if not self._write_anchor(decrypted_data):
                return "TAMPERED_CORRUPT", None

            return "OK_EXISTS", decrypted_data
        except Exception:
            return "TAMPERED_CORRUPT", None

    def update_shutdown_status(self, status='SHUTDOWN_CLEAN'):
        """
        Updates the shutdown status in the anchor file.
        This should be called on graceful application exit.
        """
        try:
            with open(self.anchor_path, 'r') as f:
                payload = json.load(f)
            
            encrypted_data = payload['data']
            signature = payload['sig']

            if not hmac.compare_digest(self._sign(encrypted_data), signature):
                return False

            decrypted_data = self._decrypt(encrypted_data)
            if decrypted_data.get('machine_fp') != self.machine_fp:
                return False

            decrypted_data['shutdown_status'] = status
            return self._write_anchor(decrypted_data)
        except Exception:
            return False
