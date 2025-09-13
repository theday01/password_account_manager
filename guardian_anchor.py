import os
import platform
import hashlib
import json
import hmac
import base64
from datetime import datetime

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
        """Encrypts, signs, and writes the anchor data to its file."""
        try:
            encrypted_data = self._encrypt(data_dict)
            signature = self._sign(encrypted_data)
            payload = json.dumps({'data': encrypted_data, 'sig': signature})
            
            with open(self.anchor_path, 'w') as f:
                f.write(payload)
            
            if platform.system() == 'Windows':
                os.system(f"attrib +h +s {self.anchor_path}")
            return True
        except (IOError, OSError, PermissionError):
            # This is expected if running without admin/root privileges and the fallback also fails.
            # The application can still run, but the anchor won't be written.
            # The observer guardian will detect the missing anchor as a problem.
            return False

    def check(self):
        """
        Checks the anchor file's existence and integrity. Creates it if it doesn't exist.

        :return: A tuple of (status, data).
                 Status can be "OK_EXISTS", "OK_CREATED", "TAMPERED_FINGERPRINT", "TAMPERED_CORRUPT".
                 Data is the anchor data dictionary if status is OK, otherwise None.
        """
        if not os.path.exists(self.anchor_path):
            # First time running on this machine (or file was deleted).
            anchor_data = {
                'install_ts': datetime.utcnow().isoformat(),
                'machine_fp': self.machine_fp
            }
            if self._write_anchor(anchor_data):
                return "OK_CREATED", anchor_data
            else:
                # Could not write the anchor file, this is a problem.
                return "TAMPERED_CORRUPT", None

        try:
            with open(self.anchor_path, 'r') as f:
                payload = json.load(f)
            
            encrypted_data = payload['data']
            signature = payload['sig']

            # Verify signature
            if not hmac.compare_digest(self._sign(encrypted_data), signature):
                return "TAMPERED_CORRUPT", None

            # Decrypt and verify fingerprint
            decrypted_data = self._decrypt(encrypted_data)
            if decrypted_data.get('machine_fp') != self.machine_fp:
                return "TAMPERED_FINGERPRINT", None
            
            return "OK_EXISTS", decrypted_data
        except Exception:
            # Any other error in reading/parsing/decrypting is a sign of tampering.
            return "TAMPERED_CORRUPT", None
