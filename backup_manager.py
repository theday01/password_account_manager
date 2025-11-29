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
    HEADER_V1 = b"SVBK1"
    HEADER_V2 = b"SVBK2"  # V2 uses 12-byte IV for GCM
    HEADER = HEADER_V2  # create new backups with latest version
    SIGNATURE_LENGTH = 32
    HEADER_LENGTH = 5

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

    def _gcm_encrypt(self, plaintext: bytes, key: bytes, iv_length: int = 12) -> (bytes, bytes, bytes):
        iv = os.urandom(iv_length)
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
          HEADER(5) | salt(32) | iv(12) | tag(16) | ciphertext(...)
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

        # Use 12-byte IV for V2 format
        iv, tag, ciphertext = self._gcm_encrypt(zip_bytes, key, iv_length=12)

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

    def get_backup_info(self, backup_file_path: str) -> dict:
        """Get information about a backup file without decrypting it."""
        if not os.path.exists(backup_file_path):
            raise BackupError("Backup file not found")
        
        file_size = os.path.getsize(backup_file_path)
        with open(backup_file_path, "rb") as f:
            header = f.read(5)
            if header == self.HEADER_V2:
                version = "V2"
                iv_len = 12
            elif header == self.HEADER_V1:
                version = "V1"
                iv_len = 16
            else:
                version = "Unknown"
                iv_len = None
        
        return {
            "path": backup_file_path,
            "version": version,
            "iv_length": iv_len,
            "file_size": file_size,
            "created": datetime.fromtimestamp(os.path.getctime(backup_file_path)).isoformat()
        }

    def _get_backup_header_and_offset(self, backup_file_path: str) -> Optional[tuple[bytes, int]]:
        """
        Validates the backup file header and determines the content start offset.
        This is non-destructive and does not modify the backup file.

        Returns a tuple of (header, offset) on success, or None on failure.
        Offset will be 0 for standard backups, or SIGNATURE_LENGTH for
        backups with a prepended signature.
        """
        if not os.path.exists(backup_file_path):
            self.logger.error(f"Backup file does not exist: {backup_file_path}")
            return None

        try:
            file_size = os.path.getsize(backup_file_path)
            self.logger.info(f"Validating backup file: {os.path.basename(backup_file_path)} (size: {file_size} bytes)")
            
            with open(backup_file_path, "rb") as f:
                buffer = f.read(self.SIGNATURE_LENGTH + self.HEADER_LENGTH)

            self.logger.debug(f"Read {len(buffer)} bytes from file")
            
            # Case 1: Standard header at the start of the file
            header = buffer[:self.HEADER_LENGTH]
            self.logger.debug(f"First 5 bytes (expected header): {header.hex() if header else 'empty'} (as string: {header!r})")
            self.logger.debug(f"Expected V1 header: {self.HEADER_V1.hex()} ({self.HEADER_V1!r})")
            self.logger.debug(f"Expected V2 header: {self.HEADER_V2.hex()} ({self.HEADER_V2!r})")
            
            if header in [self.HEADER_V1, self.HEADER_V2]:
                version = "V1" if header == self.HEADER_V1 else "V2"
                self.logger.info(f"✓ Valid {version} backup header found at offset 0")
                return header, 0

            # Case 2: Header is preceded by a signature
            if len(buffer) >= self.SIGNATURE_LENGTH + self.HEADER_LENGTH:
                header_with_sig = buffer[self.SIGNATURE_LENGTH:self.SIGNATURE_LENGTH + self.HEADER_LENGTH]
                self.logger.debug(f"Bytes at offset {self.SIGNATURE_LENGTH} (checking for header after signature): {header_with_sig.hex() if header_with_sig else 'empty'} ({header_with_sig!r})")
                
                if header_with_sig in [self.HEADER_V1, self.HEADER_V2]:
                    version = "V1" if header_with_sig == self.HEADER_V1 else "V2"
                    self.logger.info(f"✓ Valid {version} backup header found at offset {self.SIGNATURE_LENGTH} (with signature)")
                    return header_with_sig, self.SIGNATURE_LENGTH
        
        except IOError as e:
            self.logger.error(f"Could not read backup file {backup_file_path}: {e}")
            return None

        # Log detailed error information
        self.logger.error(f"❌ File '{os.path.basename(backup_file_path)}' is not a valid backup file (invalid header).")
        self.logger.error(f"   File size: {file_size} bytes")
        if len(buffer) >= 5:
            self.logger.error(f"   First 5 bytes: {buffer[:5].hex()} ({buffer[:5]!r})")
            self.logger.error(f"   This file may be:")
            self.logger.error(f"   - A corrupted backup file")
            self.logger.error(f"   - Not a SecureVault backup (.svbk) file")
            self.logger.error(f"   - Created with incompatible software")
        else:
            self.logger.error(f"   File is too small ({len(buffer)} bytes), minimum required: {self.SIGNATURE_LENGTH + self.HEADER_LENGTH}")
        
        return None

    def restore_backup(self, backup_file_path: str, backup_code: str, restore_to_dir: Optional[str] = None) -> List[str]:
        """
        Restore backup contents to `restore_to_dir` (if provided) or to current working dir.
        Returns list of restored file paths.
        Throws BackupError on failure (including wrong code).
        """
        self.logger.info(f"Restoring backup from {backup_file_path}...")
        if not backup_code or not backup_code.strip():
            self.logger.error("Restore failed: Backup code is required.")
            raise BackupError("Backup code is required to restore")

        result = self._get_backup_header_and_offset(backup_file_path)
        if not result:
            raise BackupError("Invalid backup file (bad header)")
        
        header, offset = result

        if header == self.HEADER_V2:
            iv_len = 12
            version = "V2"
        else: # HEADER_V1
            iv_len = 16
            version = "V1"
        
        self.logger.info(f"Detected backup version: {version}, content offset: {offset} bytes")
        
        with open(backup_file_path, "rb") as f:
            f.seek(offset + self.HEADER_LENGTH)
            salt = f.read(32)
            iv = f.read(iv_len)
            tag = f.read(16)
            ciphertext = f.read()
        
        self.logger.debug(f"Salt: {len(salt)} bytes, IV: {len(iv)} bytes, Tag: {len(tag)} bytes, Ciphertext: {len(ciphertext)} bytes")

        key = self._derive_key(backup_code, salt)
        
        try:
            zip_bytes = self._gcm_decrypt(iv, tag, ciphertext, key)
        except Exception as e:
            if "InvalidTag" in str(type(e).__name__):
                err_msg = (
                    f"Authentication failed for {version} backup. This usually means:\n"
                    f"1. Incorrect backup code (most common)\n"
                    f"2. Backup file is corrupted\n"
                    f"3. File was modified after creation"
                )
                self.logger.error(err_msg)
                raise BackupError("Incorrect backup code or corrupted file") from e
            else:
                err_msg = f"Failed to decrypt backup ({version}): {str(e)}"
                self.logger.error(err_msg, exc_info=True)
                raise BackupError(err_msg) from e

        restore_dir = restore_to_dir or os.getcwd()
        os.makedirs(restore_dir, exist_ok=True)
        self.logger.info(f"Restoring files to {restore_dir}")

        restored_files = []
        zip_buffer = io.BytesIO(zip_bytes)
        try:
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
        except zipfile.BadZipFile as e:
            self.logger.error("Decryption succeeded but zip file is invalid - backup may be corrupted")
            raise BackupError("Invalid zip content in backup file") from e
        
        self.logger.info(f"Restored {len(restored_files)} files successfully.")
        return restored_files


# helper to avoid importing json heavy object inline multiple times
def json_dumps(obj):
    import json
    return json.dumps(obj, indent=2, sort_keys=True)