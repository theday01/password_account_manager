import os
import io
import zipfile
import time
import shutil
from datetime import datetime
from typing import List, Optional
import logging

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class BackupError(Exception):
    pass


class BackupManager:
    HEADER = b"SVBK1"  # file signature / version

    def __init__(self, metadata_db_path: str, sensitive_db_path: str, salt_path: str, integrity_path: str, backups_dir: str = "backups"):
        self.logger = logging.getLogger(__name__)
        self.metadata_db_path = metadata_db_path
        self.sensitive_db_path = sensitive_db_path
        self.salt_path = salt_path
        self.integrity_path = integrity_path
        self.backups_dir = backups_dir
        os.makedirs(self.backups_dir, exist_ok=True)
        self.backend = default_backend()

    def _derive_key(self, code: str, salt: bytes, iterations: int = 200_000) -> bytes:
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError("salt must be bytes")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend,
        )
        return kdf.derive(code.encode())

    def _gcm_encrypt(self, plaintext: bytes, key: bytes) -> (bytes, bytes, bytes):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return iv, tag, ciphertext

    def _gcm_decrypt(self, iv: bytes, tag: bytes, ciphertext: bytes, key: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _collect_files(self) -> List[str]:
        # Order matters only for reproducibility of zip contents
        candidates = [self.metadata_db_path, self.sensitive_db_path, self.salt_path, self.integrity_path]
        existing = [p for p in candidates if p and os.path.exists(p)]
        return existing

    def create_backup(self, backup_code: str, label: Optional[str] = None) -> str:
        """
        Create an encrypted backup file. Returns the path to the created backup file.
        The produced file format (binary):
          HEADER(5) | salt(32) | iv(16) | tag(16) | ciphertext(...)
        """
        self.logger.info("Creating a new backup...")
        if not backup_code or not backup_code.strip():
            self.logger.error("Backup creation failed: Backup code is required.")
            raise BackupError("Backup code is required")
        files = self._collect_files()
        if not files:
            self.logger.error("Backup creation failed: No vault files found to back up.")
            raise BackupError("No vault files found to back up")
        
        self.logger.info(f"Found {len(files)} files to back up.")

        # create in-memory zip
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in files:
                arcname = os.path.basename(path)
                zf.write(path, arcname)
            # add a manifest
            manifest = {
                "created_at": datetime.utcnow().isoformat() + "Z",
                "files": [os.path.basename(p) for p in files],
            }
            if label:
                manifest["label"] = label
            zf.writestr("backup_manifest.json", json_dumps(manifest))
        zip_bytes = zip_buffer.getvalue()

        # derive key from user-supplied backup code + random salt
        salt = os.urandom(32)
        key = self._derive_key(backup_code, salt)

        iv, tag, ciphertext = self._gcm_encrypt(zip_bytes, key)

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        filename = f"backup_{timestamp}.svbk"
        out_path = os.path.join(self.backups_dir, filename)

        with open(out_path, "wb") as f:
            f.write(self.HEADER)
            f.write(salt)
            f.write(iv)
            f.write(tag)
            f.write(ciphertext)
        
        self.logger.info(f"Backup created successfully at {out_path}")
        return out_path

    def list_backups(self) -> List[str]:
        return sorted([os.path.join(self.backups_dir, fn) for fn in os.listdir(self.backups_dir) if fn.endswith('.svbk')], reverse=True)

    def restore_backup(self, backup_file_path: str, backup_code: str, restore_to_dir: Optional[str] = None) -> List[str]:
        """
        Restore backup contents to `restore_to_dir` (if provided) or to current working dir.
        Returns list of restored file paths.
        Throws BackupError on failure (including wrong code).
        """
        self.logger.info(f"Restoring backup from {backup_file_path}...")
        if not os.path.exists(backup_file_path):
            self.logger.error(f"Restore failed: Backup file not found at {backup_file_path}")
            raise BackupError("Backup file not found")
        if not backup_code or not backup_code.strip():
            self.logger.error("Restore failed: Backup code is required.")
            raise BackupError("Backup code is required to restore")

        with open(backup_file_path, "rb") as f:
            header = f.read(len(self.HEADER))
            if header != self.HEADER:
                self.logger.error("Restore failed: Invalid backup file header.")
                raise BackupError("Invalid backup file (bad header)")
            salt = f.read(32)
            iv = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        key = self._derive_key(backup_code, salt)
        try:
            zip_bytes = self._gcm_decrypt(iv, tag, ciphertext, key)
        except Exception as e:
            self.logger.error("Failed to decrypt backup - wrong code or corrupted file.", exc_info=True)
            raise BackupError("Failed to decrypt backup - wrong code or corrupted file") from e

        restore_dir = restore_to_dir or os.getcwd()
        os.makedirs(restore_dir, exist_ok=True)
        self.logger.info(f"Restoring files to {restore_dir}")

        restored_files = []
        zip_buffer = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            for member in zf.namelist():
                # protect against zip-slip
                member_path = os.path.normpath(member)
                if member_path.startswith("..") or os.path.isabs(member_path):
                    self.logger.warning(f"Skipping potentially malicious zip member: {member}")
                    continue
                out_path = os.path.join(restore_dir, os.path.basename(member_path))
                with zf.open(member) as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                restored_files.append(out_path)
        
        self.logger.info(f"Restored {len(restored_files)} files successfully.")
        return restored_files


# helper to avoid importing json heavy object inline multiple times
def json_dumps(obj):
    import json
    return json.dumps(obj, indent=2, sort_keys=True)
