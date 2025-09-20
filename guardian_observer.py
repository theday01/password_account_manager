import os
import platform
import hashlib
import json
import hmac
import base64
from datetime import datetime

class GuardianObserver:
    """
    The Observer Guardian. Its purpose is to watch for two things:
    1. Clock Tampering: By checking if the system time has moved backwards.
    2. Anchor Tampering: By storing a hash of the anchor's installation
       timestamp and verifying it on each run.
    It maintains its own separate, hidden file.
    """
    def __init__(self, anchor_guardian):
        self.anchor = anchor_guardian
        self.machine_fp = self.anchor.machine_fp
        self.observer_path = self._get_observer_path()
        # Use a different key for this guardian's encryption for better separation
        self.encryption_key = hashlib.sha256((self.machine_fp + "observer-secret").encode()).hexdigest()

    def _get_observer_path(self):
        """
        Determines an OS-specific, obscure path for the observer file.
        This path is intentionally different from the anchor's path.
        """
        system = platform.system()
        filename = f"sv-observer-{hashlib.sha256(self.machine_fp.encode()).hexdigest()[:16]}.dat"

        if system == 'Windows':
            # AppData is a good place for user-specific, non-roaming data.
            base_path = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Microsoft", "Windows")
        elif system == 'Linux':
            # .config is the standard for user-specific config files.
            base_path = os.path.expanduser("~/.config/fontconfig")
            filename = f".{filename}"
        elif system == 'Darwin':
            # User's preference folder.
            base_path = os.path.expanduser("~/Library/Preferences/Audio")
            filename = f"com.apple.audio.{filename}.plist"
        else:
            base_path = os.path.expanduser("~")
            filename = f".{filename}"
        
        os.makedirs(base_path, exist_ok=True)
        return os.path.join(base_path, filename)

    def _encrypt(self, data_dict):
        key = self.encryption_key
        json_data = json.dumps(data_dict, sort_keys=True)
        xored = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(json_data, key * (len(json_data) // len(key) + 1)))
        return base64.b64encode(xored.encode()).decode()

    def _decrypt(self, encrypted_str):
        key = self.encryption_key
        xored_bytes = base64.b64decode(encrypted_str)
        xored = xored_bytes.decode()
        json_data = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(xored, key * (len(xored) // len(key) + 1)))
        return json.loads(json_data)

    def _sign(self, data_str):
        return hmac.new(self.encryption_key.encode(), data_str.encode(), hashlib.sha256).hexdigest()

    def _write_observer_data(self, data_dict):
        """Encrypts, signs, and writes the observer data atomically."""
        try:
            encrypted_data = self._encrypt(data_dict)
            signature = self._sign(encrypted_data)
            payload = json.dumps({'data': encrypted_data, 'sig': signature})
            
            temp_path = self.observer_path + ".tmp"
            with open(temp_path, 'w') as f:
                f.write(payload)
            
            os.replace(temp_path, self.observer_path)
            return True
        except (IOError, OSError, PermissionError):
            return False

    def _read_observer_data(self):
        if not os.path.exists(self.observer_path):
            return None
        try:
            with open(self.observer_path, 'r') as f:
                payload = json.load(f)
            encrypted_data = payload['data']
            signature = payload['sig']
            if not hmac.compare_digest(self._sign(encrypted_data), signature):
                return "TAMPERED"
            return self._decrypt(encrypted_data)
        except Exception:
            return "TAMPERED"

    def check(self):
        """
        Performs all observer checks.

        :return: A status string: "OK", "TAMPERED_ANCHOR_INVALID",
                 "TAMPERED_ANCHOR_MISMATCH", "TAMPERED_CLOCK", "OK_UNEXPECTED_SHUTDOWN".
        """
        anchor_status, anchor_data = self.anchor.check()

        if anchor_status == "OK_UNEXPECTED_SHUTDOWN":
            # If the anchor reports an unexpected shutdown, the observer should not
            # perform its clock check, as the 'last_run_ts' could be unreliable.
            # We pass this status up to the TrialManager.
            return "OK_UNEXPECTED_SHUTDOWN"
            
        if "TAMPERED" in anchor_status:
            return "TAMPERED_ANCHOR_INVALID"
        
        install_ts = anchor_data['install_ts']
        install_ts_hash = hashlib.sha256(install_ts.encode()).hexdigest()

        observer_data = self._read_observer_data()

        if observer_data == "TAMPERED":
            return "TAMPERED_CORRUPT"

        if observer_data is None:
            new_data = {
                'install_ts_hash': install_ts_hash,
                'last_run_ts': datetime.utcnow().isoformat()
            }
            self._write_observer_data(new_data)
            return "OK"

        if observer_data.get('install_ts_hash') != install_ts_hash:
            return "TAMPERED_ANCHOR_MISMATCH"

        now = datetime.utcnow()
        last_run_ts = datetime.fromisoformat(observer_data.get('last_run_ts', now.isoformat()))
        
        if (last_run_ts - now).total_seconds() > 120:
            return "TAMPERED_CLOCK"

        observer_data['last_run_ts'] = now.isoformat()
        self._write_observer_data(observer_data)

        return "OK"
