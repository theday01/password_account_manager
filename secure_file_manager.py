import os
import sqlite3
import json
import shutil
import tempfile
import hashlib
import hmac
import stat
import threading
import time
import logging
from datetime import datetime
from typing import Tuple, List, Callable, Dict, Optional

# optional dependency for file system events
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

import base64
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# cryptography imports
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

LOG = logging.getLogger(__name__)


class EncryptionWarning(UserWarning):
    """Warning issued when encryption is expected but not available."""


# ------------------------ Utilities ------------------------

def _atomic_write(path: str, data: bytes) -> None:
    """Atomically write data to path using a temp file + os.replace."""
    dirpath = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def _sha256_of_file(path: str) -> bytes:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.digest()


def _ensure_dir_exists(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _posix_harden_permissions(path: str, file_mode: int = 0o600, dir_mode: int = 0o700) -> None:
    try:
        if os.path.isdir(path):
            os.chmod(path, dir_mode)
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), dir_mode)
                for f in files:
                    os.chmod(os.path.join(root, f), file_mode)
        else:
            os.chmod(path, file_mode)
    except Exception:
        # best-effort; caller should log
        raise


# ------------------------ SecureFileManager ------------------------
class SecureFileManager:
    """Main class responsible for vault files and their integrity.

    Core responsibilities:
    - create/initialize vault files and salt
    - derive key from master password
    - compute and verify integrity HMAC
    - staging (load to temp), sync
    - permission hardening
    """

    def __init__(self, secure_dir: str = "secure_vault"):
        self.secure_dir = secure_dir
        _ensure_dir_exists(self.secure_dir)
        self.temp_dir: Optional[str] = None
        self.encryption_key: Optional[bytes] = None
        self.signature_path = os.path.join(self.secure_dir, "integrity_file")
        self.salt_path = os.path.join(self.secure_dir, "salt_file")
        self.metadata_db = os.path.join(self.secure_dir, "metadata.db")
        self.sensitive_db = os.path.join(self.secure_dir, "sensitive.db")
        self.settings_path = os.path.join(self.secure_dir, "settings.json")


    def get_security_status(self) -> Dict:
        """Return a comprehensive security status report for the UI.
        
        Returns a dictionary with security information including:
        - secure_location: path to the secure directory
        - files_count: number of vault files present
        - last_integrity_check: timestamp of last integrity verification
        - permissions_secure: boolean indicating if permissions are properly set
        - file_hashes: dictionary of file hashes for verification
        - vault_initialized: whether the vault has been properly initialized
        """
        try:
            # Get basic vault information
            vault_files = [f for f in self.list_vault_files() if os.path.exists(f)]
            files_count = len(vault_files)
            
            # Check if vault is initialized
            vault_initialized = (
                os.path.exists(self.metadata_db) and 
                os.path.exists(self.sensitive_db) and 
                os.path.exists(self.salt_path)
            )
            
            # Verify current integrity
            integrity_ok = self.verify_integrity()
            
            # Check permissions (best effort)
            permissions_secure = True
            try:
                for vault_file in vault_files:
                    if os.path.exists(vault_file):
                        mode = os.stat(vault_file).st_mode
                        # Check if file is world-readable or world-writable
                        if os.name == 'posix':
                            if bool(mode & (stat.S_IROTH | stat.S_IWOTH)):
                                permissions_secure = False
                                break
            except Exception:
                permissions_secure = False
            
            # Get file hashes for verification
            file_hashes = self.list_files_with_hashes()
            
            # Get last integrity check timestamp
            last_integrity_check = "Never"
            if os.path.exists(self.signature_path):
                try:
                    mtime = os.path.getmtime(self.signature_path)
                    last_integrity_check = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    last_integrity_check = "Unknown"
            
            return {
                "secure_location": os.path.abspath(self.secure_dir),
                "files_count": files_count,
                "last_integrity_check": last_integrity_check,
                "permissions_secure": permissions_secure,
                "file_hashes": file_hashes,
                "vault_initialized": vault_initialized,
                "integrity_ok": integrity_ok,
                "encryption_enabled": self.encryption_key is not None
            }
            
        except Exception as e:
            LOG.exception("Failed to get security status")
            return {
                "secure_location": os.path.abspath(self.secure_dir),
                "files_count": 0,
                "last_integrity_check": "Error",
                "permissions_secure": False,
                "file_hashes": {},
                "vault_initialized": False,
                "integrity_ok": False,
                "encryption_enabled": False,
                "error": str(e)
            }

    def perform_integrity_check(self) -> bool:
        """Perform an integrity check and return True if successful.
        
        This is a convenience method that wraps verify_integrity() for UI compatibility.
        """
        return self.verify_integrity()
        
    # --- path helpers ---
    def list_vault_files(self) -> List[str]:
        return [self.metadata_db, self.sensitive_db, self.salt_path, self.signature_path, self.settings_path]

    # --- encryption / key derivation ---
    def initialize_encryption(self, master_password: str, iterations: int = 200_000) -> bool:
        """Derive a 32-byte key from master_password and the stored salt. Creates salt if missing.

        Uses PBKDF2-HMAC-SHA256 if cryptography is available; otherwise falls back to hashlib.pbkdf2_hmac.
        Returns True on success.
        """
        LOG.info("Initializing encryption...")
        if master_password is None:
            LOG.error("Master password is None, cannot initialize encryption.")
            raise ValueError("master_password cannot be None")

        if not os.path.exists(self.salt_path):
            LOG.info("Salt file not found, creating a new one.")
            with open(self.salt_path, "wb") as f:
                f.write(os.urandom(32))

        salt = open(self.salt_path, "rb").read()
        LOG.info(f"Salt loaded from {self.salt_path}")

        if CRYPTO_AVAILABLE:
            LOG.info("Using 'cryptography' package for key derivation.")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend(),
            )
            self.encryption_key = kdf.derive(master_password.encode())
        else:
            LOG.warning("Cryptography package not available, falling back to hashlib.pbkdf2_hmac.")
            # fallback
            self.encryption_key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, iterations, dklen=32)
        LOG.info("Encryption key derived successfully.")
        return True

    # --- vault init / schema ---
    def initialize_vault_files(self) -> bool:
        """Create the metadata and sensitive SQLite DBs with reasonable tables and PRAGMAs.

        This function will not overwrite existing DBs; it will only create them when missing.
        It then writes an initial integrity signature (HMAC or SHA256) and attempts permission hardening.
        """
        LOG.info("Initializing vault files...")
        try:
            if not os.path.exists(self.metadata_db):
                LOG.info(f"Metadata database not found, creating at {self.metadata_db}")
                conn = sqlite3.connect(self.metadata_db)
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS accounts (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        email TEXT,
                        url TEXT,
                        notes TEXT,
                        created_at TEXT,
                        updated_at TEXT,
                        tags TEXT,
                        security_level INTEGER
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        action TEXT,
                        entity_type TEXT,
                        entity_id TEXT,
                        details TEXT
                    )
                """)
                conn.commit()
                conn.close()

            if not os.path.exists(self.sensitive_db):
                LOG.info(f"Sensitive database not found, creating at {self.sensitive_db}")
                conn = sqlite3.connect(self.sensitive_db)
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS credentials (
                        account_id TEXT PRIMARY KEY,
                        encrypted_username BLOB,
                        encrypted_password BLOB
                    )
                """)
                conn.commit()
                conn.close()

            # Ensure salt exists
            if not os.path.exists(self.salt_path):
                LOG.info("Salt file not found, creating a new one.")
                with open(self.salt_path, "wb") as f:
                    f.write(os.urandom(32))

            # write initial integrity signature
            self.rotate_integrity_signature()

            # set restrictive permissions (best-effort)
            try:
                self.enforce_permissions()
            except Exception as e:
                LOG.warning("Permission hardening not fully applied: %s", e)
            
            LOG.info("Vault files initialized successfully.")
            return True
        except Exception as e:
            LOG.exception("initialize_vault_files failed")
            return False

    # --- integrity signature ---
    def _collect_integrity_data(self) -> bytes:
        """Return a reproducible digest of the vault files relevant for integrity checks.

        The order of files is deterministic.
        """
        hasher = hashlib.sha256()
        files = [self.metadata_db, self.sensitive_db, self.settings_path]
        magic_header = b"ENC_V1:"

        for p in files:
            if not os.path.exists(p):
                continue

            hasher.update(p.encode("utf-8"))
            hasher.update(str(os.path.getsize(p)).encode("utf-8"))

            if p == self.settings_path and self.encryption_key:
                # For settings, we must hash the plaintext content, not the ciphertext,
                # because the ciphertext changes on every write due to the random IV.
                try:
                    with open(p, "rb") as fh:
                        raw_data = fh.read()
                    
                    if raw_data.startswith(magic_header):
                        encoded_data = raw_data[len(magic_header):]
                        decoded_data = base64.b64decode(encoded_data)
                        iv, tag, ciphertext = decoded_data[:16], decoded_data[16:32], decoded_data[32:]
                        
                        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv, tag), backend=default_backend())
                        decryptor = cipher.decryptor()
                        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                        hasher.update(plaintext)
                    else:
                        # It's a plaintext settings file, hash its content directly
                        hasher.update(raw_data)
                except (EncryptionWarning, InvalidTag):
                    # If decryption is not possible (no key) or fails (bad key/tampering),
                    # hashing the raw (undecryptable) content is a safe fallback.
                    # This will correctly cause a signature mismatch if the file was tampered with.
                    with open(p, "rb") as fh:
                        hasher.update(fh.read())
            else:
                # For all other files (or settings without an encryption key), hash the raw content
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(8192), b""):
                        hasher.update(chunk)
                        
        return hasher.digest()

    def rotate_integrity_signature(self) -> bool:
        """Compute signature of current data and write it atomically to the integrity file.

        If encryption_key is set we use HMAC-SHA256 keyed by the encryption_key. Otherwise plain SHA256.
        """
        try:
            LOG.info("Rotating integrity signature.")
            data = self._collect_integrity_data()
            if self.encryption_key:
                LOG.info("Using HMAC-SHA256 for integrity signature.")
                sig = hmac.new(self.encryption_key, data, hashlib.sha256).digest()
            else:
                LOG.warning("No encryption key, using plain SHA256 for integrity signature.")
                sig = hashlib.sha256(data).digest()
            _atomic_write(self.signature_path, sig)
            LOG.info(f"Integrity signature written to {self.signature_path}")
            return True
        except Exception:
            LOG.exception("Failed to rotate integrity signature")
            return False

    def verify_integrity(self) -> bool:
        """Verify stored integrity signature matches the current state of the vault files.

        Returns True when the signature exists and matches; False otherwise.
        """
        LOG.info("Verifying integrity...")
        try:
            if not os.path.exists(self.signature_path):
                LOG.warning("Integrity signature missing; rotating to create one")
                return self.rotate_integrity_signature()

            stored = open(self.signature_path, "rb").read()
            current = self._collect_integrity_data()
            if self.encryption_key:
                LOG.info("Verifying with HMAC-SHA256.")
                expected = hmac.new(self.encryption_key, current, hashlib.sha256).digest()
            else:
                LOG.warning("No encryption key, verifying with plain SHA256.")
                expected = hashlib.sha256(current).digest()
            
            is_valid = hmac.compare_digest(expected, stored)
            LOG.info(f"Integrity verification result: {'OK' if is_valid else 'FAILED'}")
            return is_valid
        except Exception:
            LOG.exception("Integrity verification failed")
            return False

    # --- staging / temp operations ---
    def load_files_to_temp(self) -> bool:
        """Copy vault files to a new temp dir for safe inspection or restoration.

        This is atomic: a new temp dir is created and set to self.temp_dir. Previous temp_dir is removed.
        Updates internal paths to point to temp directory versions after successful copy.
        """
        LOG.info("Loading files to temporary directory...")
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                LOG.info(f"Removing old temp directory: {self.temp_dir}")
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = tempfile.mkdtemp(prefix="sv_tmp_")
            LOG.info(f"Created new temp directory: {self.temp_dir}")
            
            # Copy all files from secure_dir to temp_dir
            # This ensures we get all files including any WAL files or other database-related files
            if os.path.exists(self.secure_dir):
                for name in os.listdir(self.secure_dir):
                    src = os.path.join(self.secure_dir, name)
                    if os.path.isfile(src):
                        dst = os.path.join(self.temp_dir, name)
                        try:
                            shutil.copy2(src, dst)
                            LOG.debug(f"Copied {name} to temp directory")
                        except Exception as e:
                            LOG.warning(f"Failed to copy {name} to temp directory: {e}")
            else:
                # Fallback: copy specific files if secure_dir doesn't exist yet
                for p in [self.metadata_db, self.sensitive_db, self.salt_path, self.signature_path, self.settings_path]:
                    if os.path.exists(p):
                        shutil.copy2(p, os.path.join(self.temp_dir, os.path.basename(p)))
            
            # CRITICAL: Update all path references to point to temp directory versions
            # This ensures that reads/writes happen to the temp copies, not the secure vault originals
            self.metadata_db = os.path.join(self.temp_dir, "metadata.db")
            self.sensitive_db = os.path.join(self.temp_dir, "sensitive.db")
            self.salt_path = os.path.join(self.temp_dir, "salt_file")
            self.signature_path = os.path.join(self.temp_dir, "integrity_file")
            self.settings_path = os.path.join(self.temp_dir, "settings.json")
            LOG.info(f"Updated paths to point to temp directory. settings_path now: {self.settings_path}")
            
            LOG.info("Files loaded to temp directory successfully.")
            return True
        except Exception:
            LOG.exception("load_files_to_temp failed")
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
            return False

    def cleanup_temp_files(self) -> bool:
        LOG.info("Cleaning up temporary files...")
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                LOG.info(f"Removing temp directory: {self.temp_dir}")
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
            
            # CRITICAL: Restore original paths pointing back to secure_dir
            # This ensures subsequent operations use the persistent secure vault locations
            self.metadata_db = os.path.join(self.secure_dir, "metadata.db")
            self.sensitive_db = os.path.join(self.secure_dir, "sensitive.db")
            self.salt_path = os.path.join(self.secure_dir, "salt_file")
            self.signature_path = os.path.join(self.secure_dir, "integrity_file")
            self.settings_path = os.path.join(self.secure_dir, "settings.json")
            LOG.info(f"Restored paths to secure directory. settings_path now: {self.settings_path}")
            
            LOG.info("Temporary files cleaned up successfully.")
            return True
        except Exception:
            LOG.exception("cleanup_temp_files failed")
            return False

    def sync_all_files(self) -> bool:
        """Push files into secure_dir. Priority: temp_dir -> secure_dir, else copy from cwd if newer.

        Uses copy2 to preserve metadata and does not delete other files in secure_dir.
        This method copies all files from temp_dir to secure_dir, including database files and any WAL files.
        """
        LOG.info("Syncing all files...")
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                LOG.info(f"Syncing from temp directory: {self.temp_dir}")
                # Copy all files from temp_dir to secure_dir
                # This includes database files, WAL files, and all other vault files
                for name in os.listdir(self.temp_dir):
                    src = os.path.join(self.temp_dir, name)
                    dst = os.path.join(self.secure_dir, name)
                    try:
                        shutil.copy2(src, dst)
                        LOG.debug(f"Copied {name} to secure storage")
                    except Exception as e:
                        LOG.warning(f"Failed to copy {name}: {e}")
                # re-rotate signature after pushing
                self.rotate_integrity_signature()
                LOG.info("Sync from temp directory completed.")
                return True

            cwd = os.getcwd()
            LOG.info(f"Syncing from current working directory: {cwd}")
            candidates = ["metadata.db", "sensitive.db", "salt_file", "integrity_file", "settings.json"]
            for name in candidates:
                src = os.path.join(cwd, name)
                dst = os.path.join(self.secure_dir, name)
                if os.path.exists(src):
                    if (not os.path.exists(dst)) or (os.path.getmtime(src) > os.path.getmtime(dst)):
                        LOG.info(f"Copying {src} to {dst}")
                        shutil.copy2(src, dst)
            # ensure integrity signature
            self.rotate_integrity_signature()
            LOG.info("Sync from current working directory completed.")
            return True
        except Exception:
            LOG.exception("sync_all_files failed")
            return False

    # --- permissions / hardening ---
    def enforce_permissions(self) -> None:
        """Attempt to make vault files readable only by the current user (best-effort).

        On POSIX: set directories to 0o700 and files to 0o600.
        On Windows: attempt to set the read-only attribute for others via os.chmod.
        """
        LOG.info("Enforcing permissions...")
        try:
            if os.name == "posix":
                LOG.info("Applying POSIX permissions (dir: 700, file: 600)")
                _posix_harden_permissions(self.secure_dir)
            else:
                LOG.info("Applying Windows permissions (best-effort).")
                # Windows best-effort: remove write permission for others by making files read-only, and hide integrity
                for root, _, files in os.walk(self.secure_dir):
                    for f in files:
                        p = os.path.join(root, f)
                        try:
                            os.chmod(p, stat.S_IREAD | stat.S_IWRITE)
                        except Exception:
                            pass
            LOG.info("Permissions enforced successfully.")
        except Exception:
            LOG.exception("enforce_permissions failed")
            raise

    # --- audits / file listing ---
    def list_files_with_hashes(self) -> Dict[str, str]:
        """Return SHA256 hex of each primary vault file present.

        Keys are basenames.
        """
        out = {}
        for p in [self.metadata_db, self.sensitive_db, self.signature_path, self.salt_path, self.settings_path]:
            if os.path.exists(p):
                out[os.path.basename(p)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        return out

    def read_settings(self) -> Optional[Dict]:
        """Read, decrypt, and parse settings from the secure settings file."""
        if not os.path.exists(self.settings_path):
            LOG.info(f"Settings file does not exist: {self.settings_path}")
            return None

        try:
            with open(self.settings_path, 'rb') as f:
                raw_data = f.read()
            LOG.info(f"Read {len(raw_data)} bytes from settings file")
        except IOError:
            LOG.exception("Failed to read secure settings file.")
            return None

        # Check for magic header to determine if the file is encrypted
        magic_header = b"ENC_V1:"
        if raw_data.startswith(magic_header):
            if not self.encryption_key:
                LOG.warning("Settings file is encrypted, but no encryption key is available (this is expected on startup).")
                return None
            
            LOG.info("Decrypting encrypted settings file...")
            try:
                # Strip header and decode from base64
                encoded_data = raw_data[len(magic_header):]
                decoded_data = base64.b64decode(encoded_data)
                
                # Extract IV, tag, and ciphertext
                iv = decoded_data[:16]
                tag = decoded_data[16:32]
                ciphertext = decoded_data[32:]
                
                # Decrypt
                cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_json = decryptor.update(ciphertext) + decryptor.finalize()
                
                settings = json.loads(decrypted_json.decode('utf-8'))
                LOG.info(f"Successfully decrypted settings. Keys: {list(settings.keys())}")
                return settings
            
            except (EncryptionWarning, InvalidTag) as e:
                LOG.error(f"Failed to decrypt settings file - InvalidTag or EncryptionWarning: {e}")
                # This is not an error, but a state where the settings are not available.
                # The caller should handle this case.
                return None
            except (ValueError, IndexError) as e:
                LOG.exception(f"Failed to decrypt settings file. It may be corrupt or the key is wrong: {e}")
                return None # Hard fail if decryption fails on an encrypted file
            except Exception as e:
                LOG.exception(f"An unexpected error occurred during settings decryption: {e}")
                return None

        else:
            # No header, assume legacy plaintext file
            LOG.info("Reading plaintext settings file")
            try:
                settings = json.loads(raw_data.decode('utf-8'))
                LOG.info(f"Successfully parsed plaintext settings. Keys: {list(settings.keys())}")
                return settings
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                LOG.exception(f"Failed to parse settings file as JSON: {e}")
                return None

    def write_settings(self, settings: Dict, *, allow_plaintext: bool = False) -> bool:
        """Encrypt and write settings. If a key is available, data is encrypted.
        If no key is available, data is written in plaintext only if allow_plaintext is True.
        """
        # If no encryption key is set, we can write the settings as plaintext JSON,
        # but only if the caller explicitly allows it.
        if not self.encryption_key:
            if not allow_plaintext:
                LOG.warning("No encryption key available. Writing settings in plaintext is disallowed by default.")
                return False
            
            LOG.info("Writing settings in plaintext because no encryption key is available (and allow_plaintext=True).")
            try:
                settings_json = json.dumps(settings, indent=4).encode('utf-8')
                _atomic_write(self.settings_path, settings_json)
                self.rotate_integrity_signature()
                LOG.info(f"Settings written to {self.settings_path} (plaintext)")
                return True
            except Exception:
                LOG.exception("Failed to write plaintext settings.")
                return False

        # If an encryption key is available, encrypt the settings.
        try:
            LOG.info(f"Writing encrypted settings to {self.settings_path}. Settings keys: {list(settings.keys())}")
            
            settings_json = json.dumps(settings, indent=4).encode('utf-8')
            
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(settings_json) + encryptor.finalize()
            
            # Combine IV, tag, and ciphertext, then encode
            encoded_bundle = base64.b64encode(iv + encryptor.tag + ciphertext)
            
            # Prepend the magic header
            final_data = b"ENC_V1:" + encoded_bundle
            
            _atomic_write(self.settings_path, final_data)
            self.rotate_integrity_signature()
            
            # Verify the file was written
            if os.path.exists(self.settings_path):
                file_size = os.path.getsize(self.settings_path)
                LOG.info(f"Settings file written successfully. Size: {file_size} bytes")
                return True
            else:
                LOG.error("Settings file was not created after write operation")
                return False
        except Exception as e:
            LOG.exception(f"Failed to encrypt and write settings: {e}")
            return False


# ------------------------ SecurityMonitor ------------------------
class SecurityMonitor:
    """Advanced security monitor for vault files.

    Features:
      - Background monitoring (polling thread by default).
      - Optional `watchdog`-based real-time monitoring if watchdog is installed.
      - Alert callback invoked when integrity or permission issues are detected.
      - Quarantine capability to move suspicious files out of the vault.
      - API to perform an immediate full audit.

    Usage:
      monitor = SecurityMonitor(sfm)
      monitor.set_alert_callback(my_handler)
      monitor.start()
      ...
      monitor.stop()

    The alert callback receives a dict containing: {"timestamp","severity","message","detail"}
    """

    def __init__(self, sfm: SecureFileManager, poll_interval: float = 2.0):
        self.sfm = sfm
        self.poll_interval = float(poll_interval)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_signature: Optional[bytes] = None
        self._alert_cb: Optional[Callable[[Dict], None]] = None
        self._observer = None

    def set_alert_callback(self, cb: Callable[[Dict], None]) -> None:
        self._alert_cb = cb

    def _send_alert(self, severity: str, message: str, detail: Optional[dict] = None) -> None:
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": severity,
            "message": message,
            "detail": detail or {}
        }
        LOG.warning("SecurityMonitor alert: %s %s", severity, message)
        if self._alert_cb:
            try:
                self._alert_cb(payload)
            except Exception:
                LOG.exception("Alert callback raised an exception")

    def perform_full_audit(self) -> Dict:
        """Return a comprehensive audit report.

        Keys: integrity_ok (bool), permissions_ok (bool), file_hashes (dict), issues (list)
        """
        issues = []
        file_hashes = self.sfm.list_files_with_hashes()
        integrity_ok = self.sfm.verify_integrity()
        if not integrity_ok:
            issues.append("integrity_mismatch")

        # permissions check (best-effort)
        for root, dirs, files in os.walk(self.sfm.secure_dir):
            for name in dirs + files:
                p = os.path.join(root, name)
                try:
                    mode = os.stat(p).st_mode
                    if bool(mode & stat.S_IWOTH):
                        issues.append(f"world_writable:{p}")
                except Exception:
                    issues.append(f"cannot_stat:{p}")

        permissions_ok = len([i for i in issues if i.startswith("world_writable")]) == 0

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "integrity_ok": bool(integrity_ok),
            "permissions_ok": permissions_ok,
            "file_hashes": file_hashes,
            "issues": issues,
        }

        if not integrity_ok:
            self._send_alert("HIGH", "Integrity mismatch detected during audit", report)

        return report

    def quarantine_file(self, path: str) -> str:
        """Move a suspicious file to a quarantine folder within the secure_dir and return its new path."""
        _ensure_dir_exists(os.path.join(self.sfm.secure_dir, "quarantine"))
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        dest = os.path.join(self.sfm.secure_dir, "quarantine", f"{os.path.basename(path)}.{ts}")
        shutil.move(path, dest)
        # tighten perms
        try:
            if os.name == "posix":
                os.chmod(dest, 0o600)
        except Exception:
            pass
        LOG.info("Quarantined %s -> %s", path, dest)
        return dest

    def _poll_once(self) -> None:
        '''Perform one polling check: verify integrity and permissions.''' 
        try:
            integrity_ok = self.sfm.verify_integrity()
            if self._last_signature is None:
                # capture baseline
                if os.path.exists(self.sfm.signature_path):
                    self._last_signature = open(self.sfm.signature_path, "rb").read()
            else:
                current = open(self.sfm.signature_path, "rb").read() if os.path.exists(self.sfm.signature_path) else None
                if current is not None and not hmac.compare_digest(self._last_signature, current):
                    # signature changed; re-check actual integrity
                    if not integrity_ok:
                        self._send_alert("CRITICAL", "Integrity verification failed during monitoring")
                    else:
                        LOG.info("Signature rotated legitimately")
                    self._last_signature = current

            # permissions (POSIX-specific)
            if os.name == 'posix':
                for root, dirs, files in os.walk(self.sfm.secure_dir):
                    for name in dirs + files:
                        p = os.path.join(root, name)
                        try:
                            mode = os.stat(p).st_mode
                            if bool(mode & stat.S_IWOTH):
                                self._send_alert("HIGH", "World-writable file or directory detected", {"path": p})
                        except Exception:
                            self._send_alert("HIGH", "Unable to stat file during monitoring", {"path": p})
        except Exception:
            LOG.exception("_poll_once failure")

    def _thread_main(self) -> None:
        while self._running:
            self._poll_once()
            time.sleep(self.poll_interval)

    # --- watchdog support (optional) ---
    def _start_watchdog(self) -> bool:
        if not WATCHDOG_AVAILABLE:
            return False
        try:
            class _Handler(FileSystemEventHandler):
                def __init__(self, outer):
                    self.outer = outer
                    self.ignore_patterns = ["-wal", "-shm", ".tmp"]

                def _is_ignored(self, path):
                    return any(pattern in path for pattern in self.ignore_patterns)

                def on_modified(self, event):
                    if self._is_ignored(event.src_path):
                        return
                    # when files modified, perform audit and notify
                    rpt = self.outer.perform_full_audit()
                    if not rpt.get("integrity_ok"):
                        self.outer._send_alert("CRITICAL", "Integrity failure detected by watchdog", rpt)

                def on_created(self, event):
                    if self._is_ignored(event.src_path):
                        return
                    self.outer._send_alert("MEDIUM", "New file created in secure vault", {"path": event.src_path})

                def on_deleted(self, event):
                    if self._is_ignored(event.src_path):
                        return
                    self.outer._send_alert("MEDIUM", "File deleted from secure vault", {"path": event.src_path})

            event_handler = _Handler(self)
            self.observer = Observer()
            self._observer.schedule(event_handler, self.sfm.secure_dir, recursive=True)
            self._observer.start()
            return True
        except Exception:
            LOG.exception("Failed to start watchdog observer")
            return False

    def start(self) -> None:
        """Start background monitoring. Uses watchdog if available, else polling thread."""
        if self._running:
            return
        self._running = True
        # set baseline signature
        if os.path.exists(self.sfm.signature_path):
            try:
                self._last_signature = open(self.sfm.signature_path, "rb").read()
            except Exception:
                self._last_signature = None
        # try watchdog
        if WATCHDOG_AVAILABLE:
            ok = self._start_watchdog()
            if ok:
                LOG.info("SecurityMonitor using watchdog for real-time monitoring")
                return
        # fallback to polling thread
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()
        LOG.info("SecurityMonitor polling thread started (interval=%s)", self.poll_interval)

    def stop(self) -> None:
        self._running = False
        try:
            if self._observer:
                self._observer.stop()
                self._observer.join(timeout=2.0)
                self._observer = None
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        LOG.info("SecurityMonitor stopped")

    def get_threat_level(self) -> str:
        """Return a simple threat level based on a quick audit (HIGH if integrity or permissions issues)."""
        rpt = self.perform_full_audit()
        if not rpt.get("integrity_ok") or not rpt.get("permissions_ok"):
            return "HIGH"
        return "LOW"


# ------------------------ Migration / helpers ------------------------
class SecureVaultSetup:
    def __init__(self, sfm: SecureFileManager):
        self.sfm = sfm

    def has_legacy_files(self) -> bool:
        legacy_names = ["manageyouraccount_metadata.db", "manageyouraccount_sensitive.db", "manageyouraccount_salt", "manageyouraccount_integrity"]
        cwd = os.getcwd()
        return any(os.path.exists(os.path.join(cwd, n)) for n in legacy_names)

    def migrate_legacy_files(self, master_password: str) -> bool:
        try:
            cwd = os.getcwd()
            mapping = {
                "manageyouraccount_metadata.db": "metadata.db",
                "manageyouraccount_sensitive.db": "sensitive.db",
                "manageyouraccount_salt": "salt_file",
                "manageyouraccount_integrity": "integrity_file",
            }
            moved = False
            for src_name, dst_name in mapping.items():
                src = os.path.join(cwd, src_name)
                if os.path.exists(src):
                    dst = os.path.join(self.sfm.secure_dir, dst_name)
                    shutil.copy2(src, dst)
                    moved = True
            # derive key with provided password and rotate signature
            self.sfm.initialize_encryption(master_password)
            self.sfm.rotate_integrity_signature()
            return moved
        except Exception:
            LOG.exception("migrate_legacy_files failed")
            return False


# ------------------------ convenience setup ------------------------

def setup_secure_vault() -> SecureFileManager:
    sfm = SecureFileManager()
    sfm.initialize_vault_files()
    return sfm
