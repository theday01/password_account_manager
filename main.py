import os
import json
import secrets
import hashlib
import hmac
import base64
import sqlite3
import threading
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
from secure_file_manager import SecureFileManager, SecureVaultSetup, SecurityMonitor, setup_secure_vault
from backup_manager import BackupManager, BackupError
from PIL import Image, ImageTk
import logging
from audit_logger import setup_logging
from two_factor_auth import TwoFactorAuthManager

logger = logging.getLogger(__name__)

restore_icon = ctk.CTkImage(
    light_image=Image.open("icons/backup.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
log = ctk.CTkImage(
    light_image=Image.open("icons/log.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
logout = ctk.CTkImage(
    light_image=Image.open("icons/logout.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
password = ctk.CTkImage(
    light_image=Image.open("icons/password.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
security = ctk.CTkImage(
    light_image=Image.open("icons/security.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
settings = ctk.CTkImage(
    light_image=Image.open("icons/settings.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
upload = ctk.CTkImage(
    light_image=Image.open("icons/upload.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
user = ctk.CTkImage(
    light_image=Image.open("icons/user.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
save = ctk.CTkImage(
    light_image=Image.open("icons/save.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
class SecurityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Account:
    id: str
    name: str
    username: str
    email: str
    url: str
    notes: str
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    security_level: SecurityLevel

@dataclass
class AuditEntry:
    timestamp: datetime
    action: str
    entity_type: str
    entity_id: str
    details: str

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()
        
    def generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  
            salt=salt,
            iterations=100000,  
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def generate_salt(self) -> bytes:
        return os.urandom(32)
    
    def encrypt_data(self, data: str, key: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    
    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> str:
        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()
    
    def generate_hmac(self, data: bytes, key: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()
    
    def verify_hmac(self, data: bytes, signature: bytes, key: bytes) -> bool:
        expected = self.generate_hmac(data, key)
        return hmac.compare_digest(expected, signature)

class PasswordGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.lowercase = "abcdefghijklmnopqrstuvwxyz"
        self.uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.digits = "0123456789"
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def generate_password(self, length: int = 16, use_uppercase: bool = True,
                         use_lowercase: bool = True, use_digits: bool = True,
                         use_symbols: bool = True, exclude_ambiguous: bool = False) -> str:
        charset = ""
        if use_lowercase:
            charset += self.lowercase
        if use_uppercase:
            charset += self.uppercase
        if use_digits:
            charset += self.digits
        if use_symbols:
            charset += self.symbols
        if exclude_ambiguous:
            ambiguous = "0O1lI"
            charset = "".join(c for c in charset if c not in ambiguous)
        if not charset:
            raise ValueError("At least one character type must be selected")
        password = []
        if use_lowercase:
            password.append(secrets.choice(self.lowercase))
        if use_uppercase:
            password.append(secrets.choice(self.uppercase))
        if use_digits:
            password.append(secrets.choice(self.digits))
        if use_symbols:
            password.append(secrets.choice(self.symbols))
        for _ in range(length - len(password)):
            password.append(secrets.choice(charset))
        secrets.SystemRandom().shuffle(password)
        self.logger.info(f"Generated a new password of length {length}.")
        return ''.join(password)

    def assess_strength(self, password: str) -> Tuple[int, str, List[str]]:
        score = 0
        recommendations = []
        password_length = len(password)
        if password_length >= 40:
            score += 50
        elif password_length >= 30:
            score += 45
        elif password_length >= 20:
            score += 40
        elif password_length >= 16:
            score += 35
        elif password_length >= 12:
            score += 25
        elif password_length >= 8:
            score += 15
        else:
            recommendations.append("Use at least 12 characters")
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in self.symbols for c in password)
        variety_score = sum([has_lower, has_upper, has_digit, has_symbol]) * 10
        score += variety_score
        if not has_lower:
            recommendations.append("Add lowercase letters")
        if not has_upper:
            recommendations.append("Add uppercase letters")
        if not has_digit:
            recommendations.append("Add numbers")
        if not has_symbol:
            recommendations.append("Add symbols")
        unique_chars = len(set(password))
        if password_length > 0:
            uniqueness_ratio = unique_chars / password_length
            if uniqueness_ratio > 0.8:
                score += 25
            elif uniqueness_ratio > 0.7:
                score += 20
            elif uniqueness_ratio > 0.5:
                score += 10
            else:
                recommendations.append("Avoid repeated characters")
        if password_length >= 32:
            score += 10
        if password_length >= 50:
            score += 10
        common_patterns = ["123", "abc", "qwerty", "password"]
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 20
            recommendations.append("Avoid common patterns")
        score = min(100, max(0, score))
        if score >= 90:
            strength = "Excellent"
        elif score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Medium"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        return score, strength, recommendations

class DatabaseManager:
    def __init__(self, db_path: str, crypto_manager: CryptoManager, secure_file_manager=None):
        self.db_path = db_path
        self.crypto = crypto_manager
        self.secure_file_manager = secure_file_manager
        if secure_file_manager:
            self.metadata_db = secure_file_manager.metadata_db
            self.sensitive_db = secure_file_manager.sensitive_db
            self.salt_path = secure_file_manager.salt_path
            self.integrity_path = secure_file_manager.signature_path
        else:
            self.metadata_db = f"{db_path}_metadata.db"
            self.sensitive_db = f"{db_path}_sensitive.db"
            self.salt_path = f"{db_path}_salt"
            self.integrity_path = f"{db_path}_integrity"
        self.integrity_key = None
        self.encryption_key = None
        self.last_integrity_error = False
        
    def initialize_database(self, master_password: str):
        logger.info("Starting database initialization...")
        salt = self.crypto.generate_salt()
        self.encryption_key = self.crypto.generate_key_from_password(master_password, salt)
        self.integrity_key = self.crypto.generate_key_from_password(master_password + "_integrity", salt)
        logger.info(f"Generated salt ({len(salt)} bytes) and encryption keys")
        try:
            with open(self.salt_path, "wb") as f:
                f.write(salt)
            logger.info(f"Salt saved to {self.salt_path}")
        except Exception as e:
            logger.error(f"Failed to save salt: {e}")
            raise
        try:
            metadata_conn = sqlite3.connect(self.metadata_db)
            metadata_conn.execute("""
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
            metadata_conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    action TEXT,
                    entity_type TEXT,
                    entity_id TEXT,
                    details TEXT
                )
            """)
            metadata_conn.commit()
            metadata_conn.close()
            logger.info("Metadata database created")
        except Exception as e:
            logger.error(f"Failed to create metadata database: {e}")
            raise
        try:
            sensitive_conn = sqlite3.connect(self.sensitive_db)
            sensitive_conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    account_id TEXT PRIMARY KEY,
                    encrypted_username BLOB,
                    encrypted_password BLOB
                )
            """)
            sensitive_conn.commit()
            sensitive_conn.close()
            logger.info("Sensitive database created")
        except Exception as e:
            logger.error(f"Failed to create sensitive database: {e}")
            raise
        try:
            logger.info("Creating master account for authentication...")
            encrypted_username = self.crypto.encrypt_data("master", self.encryption_key)
            encrypted_password = self.crypto.encrypt_data(master_password, self.encryption_key)
            metadata_conn = sqlite3.connect(self.metadata_db)
            metadata_conn.execute("""
                INSERT OR IGNORE INTO accounts (id, name, email, url, notes, created_at, updated_at, tags, security_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "master_account", 
                "Master Account", 
                "", 
                "", 
                "System account for authentication verification",
                datetime.now().isoformat(), 
                datetime.now().isoformat(),
                json.dumps([]), 
                SecurityLevel.CRITICAL.value
            ))
            metadata_conn.commit()
            metadata_conn.close()
            sensitive_conn = sqlite3.connect(self.sensitive_db)
            sensitive_conn.execute("""
                INSERT OR IGNORE INTO credentials (account_id, encrypted_username, encrypted_password)
                VALUES (?, ?, ?)
            """, ("master_account", encrypted_username, encrypted_password))
            sensitive_conn.commit()
            sensitive_conn.close()
            logger.info("Master account created successfully")
        except Exception as e:
            logger.error(f"Failed to create master account: {e}")
            raise
        try:
            self.secure_file_manager.rotate_integrity_signature()
            logger.info("Integrity signature created")
        except Exception as e:
            logger.error(f"Failed to create integrity signature: {e}")
            raise
        try:
            logger.info("Testing authentication with new password...")
            if self.authenticate(master_password):
                logger.info("Authentication test successful")
            else:
                logger.error("Authentication test failed")
                raise Exception("Authentication test failed after initialization")
        except Exception as e:
            logger.error(f"Authentication test error: {e}")
            raise
        self.log_action("CREATE", "SYSTEM", "database", "Database initialized successfully")
        logger.info("Database initialization completed successfully!")  
                
    def authenticate(self, master_password: str) -> bool:
        try:
            logger.info("Attempting authentication...")
            logger.info(f"Salt path: {self.salt_path}")
            logger.info(f"Metadata DB path: {self.metadata_db}")
            logger.info(f"Sensitive DB path: {self.sensitive_db}")
            logger.info(f"Integrity path: {self.integrity_path}")
            required_files = [self.salt_path, self.metadata_db, self.sensitive_db]
            missing_files = [f for f in required_files if not os.path.exists(f)]
            if missing_files:
                logger.error(f"Missing required files: {missing_files}")
                return False
            if not os.path.exists(self.salt_path):
                logger.error(f"Salt file not found at {self.salt_path}")
                return False
            with open(self.salt_path, "rb") as f:
                salt = f.read()
            logger.info(f"Salt loaded successfully ({len(salt)} bytes)")
            self.encryption_key = self.crypto.generate_key_from_password(master_password, salt)
            self.integrity_key = self.crypto.generate_key_from_password(master_password + "_integrity", salt)
            logger.info("Encryption keys generated")
            integrity_valid = self.secure_file_manager.verify_integrity()
            logger.info(f"Database integrity check: {'PASSED' if integrity_valid else 'FAILED'}")
            if not integrity_valid:
                logger.error("Database integrity check failed")
                self.last_integrity_error = True
                logger.info("Attempting integrity recovery...")
                try:
                    if self.secure_file_manager.rotate_integrity_signature():
                        logger.info("Integrity signature regenerated, retrying verification...")
                        integrity_valid = self.secure_file_manager.verify_integrity()
                        if integrity_valid:
                            logger.info("Integrity recovery successful")
                            self.last_integrity_error = False
                        else:
                            logger.error("Integrity recovery failed")
                            return False
                    else:
                        logger.error("Failed to regenerate integrity signature")
                        return False
                except Exception as recovery_error:
                    logger.error(f"Integrity recovery error: {recovery_error}")
                    return False
            try:
                sensitive_conn = sqlite3.connect(self.sensitive_db)
                cursor = sensitive_conn.execute("""
                    SELECT encrypted_username, encrypted_password 
                    FROM credentials 
                    WHERE account_id = 'master_account'
                    LIMIT 1
                """)
                test_row = cursor.fetchone()
                sensitive_conn.close()
                if test_row:
                    try:
                        test_username = self.crypto.decrypt_data(test_row[0], self.encryption_key)
                        test_password = self.crypto.decrypt_data(test_row[1], self.encryption_key)
                        logger.info("Test decryption successful")
                    except Exception as decrypt_error:
                        logger.error(f"Test decryption failed: {decrypt_error}")
                        return False
                else:
                    logger.warning("No master account found for test decryption")
            except Exception as test_error:
                logger.error(f"Database test failed: {test_error}")
                return False
            logger.info("Authentication successful!")
            return True
        except FileNotFoundError as e:
            logger.error(f"Required file not found: {e}")
            return False
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return False
                
    def force_integrity_reset(self):
        try:
            logger.warning("Force resetting integrity signature...")
            if os.path.exists(self.integrity_path):
                os.remove(self.integrity_path)
                logger.info("Old integrity file removed")
            if self.integrity_key:
                success = self.secure_file_manager.rotate_integrity_signature()
                if success:
                    logger.info("New integrity signature created")
                    return True
                else:
                    logger.error("Failed to create new integrity signature")
                    return False
            else:
                logger.error("No integrity key available for reset")
                return False
        except Exception as e:
            logger.error(f"Force reset failed: {e}")
            return False
    
    def add_account(self, account: Account, username: str, password: str):
        metadata_conn = None
        sensitive_conn = None
        try:
            metadata_conn = sqlite3.connect(self.metadata_db)
            cursor = metadata_conn.execute("SELECT id FROM accounts WHERE id = ?", (account.id,))
            if cursor.fetchone():
                raise ValueError(f"Account with ID '{account.id}' already exists")
            metadata_conn.execute("""
                INSERT INTO accounts (id, name, email, url, notes, created_at, updated_at, tags, security_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                account.id, account.name, account.email, account.url, account.notes,
                account.created_at.isoformat(), account.updated_at.isoformat(),
                json.dumps(account.tags), account.security_level.value
            ))
            metadata_conn.commit()
            sensitive_conn = sqlite3.connect(self.sensitive_db)
            if cursor.fetchone():
                metadata_conn.execute("DELETE FROM accounts WHERE id = ?", (account.id,))
                metadata_conn.commit()
                raise ValueError(f"Credentials for account ID '{account.id}' already exist")
            encrypted_username = self.crypto.encrypt_data(username, self.encryption_key)
            encrypted_password = self.crypto.encrypt_data(password, self.encryption_key)
            sensitive_conn.execute("""
                INSERT INTO credentials (account_id, encrypted_username, encrypted_password)
                VALUES (?, ?, ?)
            """, (account.id, encrypted_username, encrypted_password))
            sensitive_conn.commit()
            self.log_action("CREATE", "ACCOUNT", account.id, f"Created account: {account.name}")
            self.secure_file_manager.rotate_integrity_signature()
            logger.info(f"Account '{account.name}' created successfully with ID: {account.id}")
            
        except sqlite3.IntegrityError as e:
            logger.error(f"Integrity error while creating account: {e}")
            try:
                if metadata_conn:
                    metadata_conn.execute("DELETE FROM accounts WHERE id = ?", (account.id,))
                    metadata_conn.commit()
                if sensitive_conn:
                    sensitive_conn.execute("DELETE FROM credentials WHERE account_id = ?", (account.id,))
                    sensitive_conn.commit()
            except Exception as cleanup_error:
                logger.error(f"Error during cleanup: {cleanup_error}")
            raise e
        except Exception as e:
            logger.error(f"Error creating account: {e}")
            try:
                if metadata_conn:
                    metadata_conn.execute("DELETE FROM accounts WHERE id = ?", (account.id,))
                    metadata_conn.commit()
                if sensitive_conn:
                    sensitive_conn.execute("DELETE FROM credentials WHERE account_id = ?", (account.id,))
                    sensitive_conn.commit()
            except Exception as cleanup_error:
                logger.error(f"Error during cleanup: {cleanup_error}")
            raise e
        finally:
            if metadata_conn:
                metadata_conn.close()
            if sensitive_conn:
                sensitive_conn.close()
                    
    def get_account_credentials(self, account_id: str) -> Tuple[str, str]:
        sensitive_conn = sqlite3.connect(self.sensitive_db)
        cursor = sensitive_conn.execute("""
            SELECT encrypted_username, encrypted_password
            FROM credentials WHERE account_id = ?
        """, (account_id,))
        row = cursor.fetchone()
        sensitive_conn.close()
        if row:
            username = self.crypto.decrypt_data(row[0], self.encryption_key)
            password = self.crypto.decrypt_data(row[1], self.encryption_key)
            return username, password
        return None, None
    
    def update_account(self, account_id: str, name: str, email: str, url: str, notes: str, username: str, password: str):
        metadata_conn = sqlite3.connect(self.metadata_db)
        metadata_conn.execute("""
            UPDATE accounts 
            SET name=?, email=?, url=?, notes=?, updated_at=?
            WHERE id=?
        """, (name, email, url, notes, datetime.now().isoformat(), account_id))
        metadata_conn.commit()
        metadata_conn.close()
        sensitive_conn = sqlite3.connect(self.sensitive_db)
        encrypted_username = self.crypto.encrypt_data(username, self.encryption_key)
        encrypted_password = self.crypto.encrypt_data(password, self.encryption_key)
        sensitive_conn.execute("""
            UPDATE credentials 
            SET encrypted_username=?, encrypted_password=?
            WHERE account_id=?
        """, (encrypted_username, encrypted_password, account_id))
        sensitive_conn.commit()
        sensitive_conn.close()
        self.log_action("UPDATE", "ACCOUNT", account_id, f"Updated account: {name}")
        self.secure_file_manager.rotate_integrity_signature()
    
    def delete_account(self, account_id: str):
        metadata_conn = sqlite3.connect(self.metadata_db)
        cursor = metadata_conn.execute("SELECT name FROM accounts WHERE id=?", (account_id,))
        row = cursor.fetchone()
        account_name = row[0] if row else "Unknown"
        metadata_conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        metadata_conn.commit()
        metadata_conn.close()
        sensitive_conn = sqlite3.connect(self.sensitive_db)
        sensitive_conn.execute("DELETE FROM credentials WHERE account_id=?", (account_id,))
        sensitive_conn.commit()
        sensitive_conn.close()
        self.log_action("DELETE", "ACCOUNT", account_id, f"Deleted account: {account_name}")
        self.secure_file_manager.rotate_integrity_signature()
    
    def change_master_password(self, current_password: str, new_password: str):
        if not self.authenticate(current_password):
            raise ValueError("Current password is incorrect")
        logger.info("Starting master password change process...")
        new_salt = self.crypto.generate_salt()
        new_encryption_key = self.crypto.generate_key_from_password(new_password, new_salt)
        new_integrity_key = self.crypto.generate_key_from_password(new_password + "_integrity", new_salt)
        logger.info("Generated new encryption keys")
        sensitive_conn = sqlite3.connect(self.sensitive_db)
        cursor = sensitive_conn.execute("SELECT account_id, encrypted_username, encrypted_password FROM credentials")
        credentials = cursor.fetchall()
        logger.info(f"Found {len(credentials)} accounts to re-encrypt")
        for account_id, enc_username, enc_password in credentials:
            try:
                username = self.crypto.decrypt_data(enc_username, self.encryption_key)
                password = self.crypto.decrypt_data(enc_password, self.encryption_key)
                new_enc_username = self.crypto.encrypt_data(username, new_encryption_key)
                new_enc_password = self.crypto.encrypt_data(password, new_encryption_key)
                sensitive_conn.execute("""
                    UPDATE credentials 
                    SET encrypted_username=?, encrypted_password=?
                    WHERE account_id=?
                """, (new_enc_username, new_enc_password, account_id))
                
                logger.info(f"Re-encrypted credentials for account {account_id}")
            except Exception as e:
                logger.error(f"Failed to re-encrypt account {account_id}: {e}")
                sensitive_conn.close()
                raise ValueError(f"Failed to re-encrypt account {account_id}: {e}")
        sensitive_conn.commit()
        sensitive_conn.close()
        logger.info("All credentials re-encrypted successfully")
        self.encryption_key = new_encryption_key
        self.integrity_key = new_integrity_key
        try:
            with open(self.salt_path, "wb") as f:
                f.write(new_salt)
            logger.info(f"New salt written to {self.salt_path}")
        except Exception as e:
            logger.error(f"Failed to write salt file: {e}")
            raise ValueError(f"Failed to write salt file: {e}")
        try:
            self.secure_file_manager.rotate_integrity_signature()
            logger.info("Integrity signature updated")
        except Exception as e:
            logger.error(f"Failed to update integrity signature: {e}")
            raise ValueError(f"Failed to update integrity signature: {e}")
        self.log_action("UPDATE", "SYSTEM", "master_password", "Master password changed successfully")
        if self.secure_file_manager:
            try:
                self.secure_file_manager.sync_all_files()
                logger.info("Changes synced to secure storage")
            except Exception as e:
                logger.warning(f"Failed to sync to secure storage: {e}")
        logger.info("Master password change completed successfully!")
        try:
            test_encryption_key = self.crypto.generate_key_from_password(new_password, new_salt)
            if test_encryption_key == self.encryption_key:
                logger.info("New password verification successful")
            else:
                logger.error("New password verification failed")
                raise ValueError("Password change verification failed")
        except Exception as e:
            logger.error(f"Verification error: {e}")
            raise ValueError(f"Password change verification failed: {e}")    

    def log_action(self, action: str, entity_type: str, entity_id: str, details: str):
        logger.info(f"DB Action: {action}, Type: {entity_type}, ID: {entity_id}, Details: {details}")
        metadata_conn = sqlite3.connect(self.metadata_db)
        metadata_conn.execute("""
            INSERT INTO audit_log (timestamp, action, entity_type, entity_id, details)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), action, entity_type, entity_id, details))
        metadata_conn.commit()
        metadata_conn.close()
class ModernPasswordManagerGUI:
    def __init__(self):
        self.crypto = CryptoManager()
        self.password_generator = PasswordGenerator()
        self.tfa_manager = TwoFactorAuthManager()
        self.database = None
        self.secure_file_manager = None
        self.security_monitor = None
        ctk.set_appearance_mode("dark")  
        self.root = ctk.CTk()
        self.root.title("Secure Password Manager")
        self.root.geometry("1200x800")
        self.authenticated = False
        self.accounts = []
        self.failed_attempts = 0
        self.lockout_until = None
        self.settings = {}
        self.consecutive_lockouts = 0
        self.inactivity_timer = None
        self.INACTIVITY_TIMEOUT = 3 * 60 * 1000  # 3 minutes in milliseconds
        self._setup_secure_file_manager()
        self.load_settings()
        self.validate_lockout_integrity()
        self.setup_ui()
        self.start_lockout_validation_timer()

    def _setup_secure_file_manager(self):
        try:
            logger.info("Initializing secure file management system...")
            self.secure_file_manager = SecureFileManager()
            logger.info("Secure file manager initialized")
        except Exception as e:
            logger.error(f"Failed to initialize secure file manager: {e}")
            self.secure_file_manager = None

    def load_settings(self):
        default_settings = {
            'theme': 'dark',
            'font_size': 12,
            'lockout_until': None,
            'failed_attempts': 0,
            'consecutive_lockouts': 0,
            'last_modified': None,
            'secure_storage_enabled': True,
            'tfa_secret': None
        }
        if self.secure_file_manager:
            try:
                loaded_settings = self.secure_file_manager.read_settings()
                if loaded_settings:
                    self.settings = {**default_settings, **loaded_settings}
                    self.restore_lockout_state()
                    return
            except Exception as e:
                logger.error(f"Failed to load secure settings: {e}")
        settings_file = "vault_settings.json"
        try:
            if os.path.exists(settings_file):
                current_file_time = os.path.getmtime(settings_file)
                with open(settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    if 'last_modified' in loaded_settings and loaded_settings['last_modified']:
                        try:
                            stored_time = float(loaded_settings['last_modified'])
                            if abs(current_file_time - stored_time) > 1:
                                logger.warning("Settings file modification time mismatch detected")
                                loaded_settings['lockout_until'] = None
                                loaded_settings['failed_attempts'] = 0
                                loaded_settings['consecutive_lockouts'] = 0
                        except (ValueError, TypeError):
                            logger.warning("Invalid modification time in settings")
                            loaded_settings['lockout_until'] = None
                            loaded_settings['failed_attempts'] = 0
                            loaded_settings['consecutive_lockouts'] = 0
                    self.settings = {**default_settings, **loaded_settings}
                    self.restore_lockout_state()
            else:
                self.settings = default_settings
                self.save_settings_to_file()
        except Exception as e:
            logger.error(f"Error loading settings: {e}")
            self.settings = default_settings

    def restore_lockout_state(self):
        if 'lockout_until' in self.settings and self.settings['lockout_until']:
            try:
                lockout_time = datetime.fromisoformat(self.settings['lockout_until'])
                current_time = datetime.now()
                if current_time < lockout_time:
                    self.lockout_until = lockout_time
                    self.failed_attempts = self.settings.get('failed_attempts', 0)
                    self.consecutive_lockouts = self.settings.get('consecutive_lockouts', 0)
                    remaining_seconds = int((lockout_time - current_time).total_seconds())
                    lockout_minutes = remaining_seconds // 60
                    logger.info(f"Lockout state restored - {lockout_minutes} minutes remaining")
                else:
                    self.clear_lockout_state()
                    logger.info("Lockout period expired, state cleared")
            except Exception as e:
                logger.error(f"Error parsing lockout time: {e}")
                self.clear_lockout_state()
        else:
            self.failed_attempts = self.settings.get('failed_attempts', 0)
            self.consecutive_lockouts = self.settings.get('consecutive_lockouts', 0)

    def clear_lockout_state(self):
        logger.info("Clearing lockout state")
        self.lockout_until = None
        self.failed_attempts = 0
        self.consecutive_lockouts = 0
        self.settings['lockout_until'] = None
        self.settings['failed_attempts'] = 0
        self.settings['consecutive_lockouts'] = 0
        self.save_settings_to_file()

    def save_lockout_state(self):
        if self.lockout_until:
            self.settings['lockout_until'] = self.lockout_until.isoformat()
            remaining_time = self.get_remaining_lockout_time()
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            logger.info(f"Saving lockout state - {minutes:02d}:{seconds:02d} remaining")
        else:
            self.settings['lockout_until'] = None
        self.settings['failed_attempts'] = self.failed_attempts
        self.settings['consecutive_lockouts'] = self.consecutive_lockouts
        self.save_settings_to_file()

    def save_settings_to_file(self):
        self.settings['last_modified'] = time.time()
        if self.secure_file_manager and self.secure_file_manager.temp_dir:
            try:
                temp_settings_path = os.path.join(self.secure_file_manager.temp_dir, "settings.json")
                with open(temp_settings_path, 'w') as f:
                    json.dump(self.settings, f, indent=4)
            except Exception as e:
                logger.warning(f"Could not save settings to temp dir: {e}")
        if self.secure_file_manager:
            try:
                if self.secure_file_manager.write_settings(self.settings):
                    return
            except Exception as e:
                logger.error(f"Failed to save secure settings: {e}")
        try:
            settings_file = "vault_settings.json"
            with open(settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving settings: {e}")

    def validate_lockout_integrity(self):
        logger.info("Validating lockout state integrity...")
        if self.lockout_until:
            current_time = datetime.now()
            if current_time >= self.lockout_until:
                logger.info("Lockout period has expired, clearing state")
                self.clear_lockout_state()
            else:
                if self.failed_attempts < 0:
                    self.failed_attempts = 0
                if self.consecutive_lockouts < 0:
                    self.consecutive_lockouts = 0
                max_lockout_duration = timedelta(hours=24)
                if self.lockout_until - current_time > max_lockout_duration:
                    logger.warning("Lockout time exceeds maximum duration, resetting")
                    self.clear_lockout_state()
                    return
        else:
            if self.failed_attempts < 0:
                self.failed_attempts = 0
            if self.consecutive_lockouts < 0:
                self.consecutive_lockouts = 0

    def log_security_event(self, event_type: str, details: str):
        logger.info(f"SECURITY EVENT: {event_type} - {details}")

    def start_lockout_validation_timer(self):
        def validate_periodically():
            if self.lockout_until:
                current_time = datetime.now()
                if current_time >= self.lockout_until:
                    logger.info("Periodic check - lockout period expired")
                    self.clear_lockout_state()
                    if hasattr(self, 'lockout_countdown_label'):
                        self.root.after(0, self.show_login_screen)
                else:
                    self.root.after(30000, validate_periodically)
            else:
                self.root.after(60000, validate_periodically)
        self.root.after(30000, validate_periodically)

    def is_vault_initialized(self):
        legacy_exists = os.path.exists("manageyouraccount_salt")
        if self.secure_file_manager:
            secure_exists = os.path.exists(self.secure_file_manager.salt_path)
            return legacy_exists or secure_exists
        return legacy_exists

    def setup_ui(self):
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        if self.check_startup_lockout():
            return
        if not self.authenticated:
            self.show_login_screen()
            self.update_login_button_states()
        else:
            self.show_main_interface()

    def show_login_screen(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        login_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        login_container.place(relx=0.5, rely=0.5, anchor="center")
        login_card = ctk.CTkFrame(login_container, corner_radius=15)
        login_card.pack(padx=20, pady=20)
        self.root.resizable(False, False)
        self.root.update_idletasks()
        width = 1000
        height = 600
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        title = ctk.CTkLabel(
            login_card, 
            text="🔒 Secure Password Manager", 
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(30, 20), padx=40)
        subtitle = ctk.CTkLabel(
            login_card,
            text="Secure Password Management",
            font=ctk.CTkFont(size=16),
            text_color="#888888"
        )
        subtitle.pack(pady=(0, 30), padx=40)
        self.master_password_entry = ctk.CTkEntry(
            login_card, 
            placeholder_text="Enter Master Password", 
            show="*", 
            width=350,
            height=45,
            font=ctk.CTkFont(size=16)
        )
        self.master_password_entry.pack(pady=15, padx=40)
        button_frame = ctk.CTkFrame(login_card, fg_color="transparent")
        button_frame.pack(pady=30, padx=40)
        self.login_btn = ctk.CTkButton(
            button_frame, 
            text="🔓 Login", 
            command=self.authenticate_user,
            width=250,
            height=55,
            font=ctk.CTkFont(size=18, weight="bold"),
            corner_radius=12,
            state="disabled" if not self.is_vault_initialized() else "normal"
        )
        self.login_btn.pack(pady=15)
        self.setup_btn = ctk.CTkButton(
            button_frame, 
            text="⚙️ First Time Setup", 
            command=self.show_setup_wizard,
            width=250,
            height=55,
            font=ctk.CTkFont(size=18),
            corner_radius=12,
            state="disabled" if self.is_vault_initialized() else "normal"
        )
        self.setup_btn.pack(pady=8)
        self.master_password_entry.bind('<Return>', lambda e: self.authenticate_user())
        if self.lockout_until and datetime.now() < self.lockout_until:
            self.update_lockout_countdown()
        self.update_login_button_states()

    def authenticate_user(self):
        master_password = self.master_password_entry.get().strip()
        if not master_password:
            messagebox.showerror("Error", "Please enter your master password")
            return
        if not self.is_vault_initialized():
            messagebox.showerror("Error", "Vault is not initialized. Please run first time setup.")
            return
        if self.secure_file_manager:
            legacy_setup = SecureVaultSetup(self.secure_file_manager)
            if legacy_setup.has_legacy_files():
                logger.info("Legacy files detected, starting migration...")
                if not legacy_setup.migrate_legacy_files(master_password):
                    messagebox.showerror("Migration Error", "Failed to migrate legacy files")
                    return
        if self.secure_file_manager:
            if not self.secure_file_manager.initialize_encryption(master_password):
                messagebox.showerror("Error", "Failed to initialize secure storage")
                return
            logger.info("Loading files from secure storage...")
            if not self.secure_file_manager.load_files_to_temp():
                diagnostic_report = self.diagnose_secure_storage_issues()
                error_msg = "Failed to load files from secure storage.\n\n"
                error_msg += "🔍 Diagnostic Report:\n" + diagnostic_report
                self.show_secure_storage_error_dialog(error_msg)
                return
        db_path = "manageyouraccount"
        self.database = DatabaseManager(db_path, self.crypto, self.secure_file_manager)
        if self.database.authenticate(master_password):
            if self.settings.get('tfa_secret'):
                self.prompt_for_tfa()
            else:
                self.authenticated = True
                self.failed_attempts = 0
                self.consecutive_lockouts = 0
                self.clear_lockout_state()
                if self.secure_file_manager:
                    self.security_monitor = SecurityMonitor(self.secure_file_manager)
                    self.security_monitor.set_alert_callback(self.handle_security_alert)
                    self._start_security_monitoring()
                self.show_main_interface()
        else:
            if hasattr(self.database, 'last_integrity_error') and self.database.last_integrity_error:
                result = messagebox.askyesno(
                    "Integrity Error", 
                    "Database integrity check failed. This usually happens when:\n\n"
                    "• Database files were modified outside the application\n"
                    "• The application was not properly closed\n"
                    "• There was a system crash\n\n"
                    "Would you like to attempt to fix this automatically?"
                )
                
                if result:
                    try:
                        if self.database.force_integrity_reset():
                            messagebox.showinfo("Success", 
                                            "Integrity issue fixed! Please try logging in again.")
                            self.database.last_integrity_error = False
                            return
                        else:
                            messagebox.showerror("Error", "Failed to fix integrity issue automatically.")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to fix integrity issue: {str(e)}")
            
            self.failed_attempts += 1
            if self.failed_attempts >= 3:
                self.consecutive_lockouts += 1
                lockout_minutes = 3 * self.consecutive_lockouts
                self.lockout_until = datetime.now() + timedelta(minutes=lockout_minutes)
                self.save_lockout_state()
                messagebox.showerror("Account Locked", 
                            f"Too many failed attempts. Account locked for {lockout_minutes} minutes.")
                self.failed_attempts = 0
                self.disable_login_button_with_countdown(lockout_minutes)
            else:
                messagebox.showerror("Error", f"Invalid master password. {3 - self.failed_attempts} attempts remaining.")

    def _start_security_monitoring(self):
        if self.security_monitor:
            self.security_monitor.start()

    def handle_security_alert(self, alert):
        severity = alert.get("severity", "UNKNOWN")
        message = alert.get("message", "An unspecified security alert was triggered.")
        details = alert.get("detail", {})
        
        title = f"Security Alert: {severity}"
        full_message = f"{message}\n\nDetails: {details}"
        
        if severity == "CRITICAL":
            messagebox.showerror(title, full_message)
            # Consider more drastic action for critical alerts, like locking the vault
            self.lock_vault()
        elif severity == "HIGH":
            messagebox.showwarning(title, full_message)
        else:
            messagebox.showinfo(title, full_message)

    def disable_login_button_with_countdown(self, lockout_minutes):
        if hasattr(self, 'login_btn'):
            self.login_btn.configure(state="disabled")
            self.update_lockout_countdown()

    def update_lockout_countdown(self):
        if self.lockout_until and datetime.now() < self.lockout_until:
            remaining_time = int((self.lockout_until - datetime.now()).total_seconds())
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            
            if hasattr(self, 'login_btn'):
                self.login_btn.configure(
                    text=f"🔒 Locked ({minutes:02d}:{seconds:02d})",
                    state="disabled"
                )
            if hasattr(self, 'lockout_countdown_label'):
                self.lockout_countdown_label.configure(
                    text=f"Time remaining: {minutes:02d}:{seconds:02d}"
                )
            self.root.after(1000, self.update_lockout_countdown)
        else:
            if hasattr(self, 'login_btn'):
                self.login_btn.configure(
                    text="🔓 Login",
                    state="normal"
                )
            self.lockout_until = None
            self.clear_lockout_state()
            if hasattr(self, 'lockout_countdown_label'):
                self.show_login_screen()

    def update_login_button_states(self):
        if hasattr(self, 'login_btn') and hasattr(self, 'setup_btn'):
            if self.is_vault_initialized():
                self.login_btn.configure(state="normal")
                self.setup_btn.configure(state="disabled")
            else:
                self.login_btn.configure(state="disabled")
                self.setup_btn.configure(state="normal")

    def verify_master_password_dialog(self):
        if self.enforce_lockout():
            return False
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Verify Master Password")
        dialog.geometry("400x230")
        dialog.grab_set()
        dialog.resizable(False, False)
        result = {"password": None, "confirmed": False}
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🔐 Authentication Required",
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        password_entry = ctk.CTkEntry(main_frame, width=300, height=40, show="*",
                                    placeholder_text="Master Password")
        password_entry.pack(pady=15)
        password_entry.focus()
        
        def on_ok():
            result["password"] = password_entry.get()
            result["confirmed"] = True
            dialog.destroy()
        
        def on_cancel():
            result["confirmed"] = False
            dialog.destroy()
        
        password_entry.bind('<Return>', lambda e: on_ok())
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=10)
        
        ctk.CTkButton(button_frame, text="Cancel", command=on_cancel, width=100).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="OK", command=on_ok, width=100).pack(side="right", padx=10)
        
        dialog.wait_window()
        
        if not result["confirmed"] or not result["password"]:
            return False
        
        try:
            temp_db = DatabaseManager(self.database.db_path, self.crypto, self.secure_file_manager)
            if temp_db.authenticate(result["password"]):
                return True
            else:
                self.failed_attempts += 1
                if self.failed_attempts >= 3:
                    self.consecutive_lockouts += 1
                    lockout_minutes = 3 * self.consecutive_lockouts
                    self.lockout_until = datetime.now() + timedelta(minutes=lockout_minutes)
                    self.save_lockout_state()
                    messagebox.showerror("Account Locked", 
                                    f"Too many failed attempts. Account locked for {lockout_minutes} minutes.")
                    self.failed_attempts = 0
                else:
                    messagebox.showerror("Error", "Invalid master password")
                return False
        except Exception:
            messagebox.showerror("Error", "Authentication failed")
            return False

    def show_setup_wizard(self):
        if self.is_vault_initialized():
            messagebox.showinfo("Already Set Up", "Vault is already initialized.")
            return
        
        self.update_login_button_states()
        setup_window = ctk.CTkToplevel(self.root)
        setup_window.title("SecureVault Setup Wizard")
        setup_window.geometry("600x400")
        setup_window.grab_set()
        main_frame = ctk.CTkFrame(setup_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="Create Your Master Password", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        self.setup_master_password = ctk.CTkEntry(main_frame, placeholder_text="Master Password", 
                                                  show="*", width=300, height=40)
        self.setup_master_password.pack(pady=10)
        self.setup_confirm_password = ctk.CTkEntry(main_frame, placeholder_text="Confirm Password", 
                                                   show="*", width=300, height=40)
        self.setup_confirm_password.pack(pady=10)
        self.strength_label = ctk.CTkLabel(main_frame, text="")
        self.strength_label.pack(pady=10)
        self.setup_master_password.bind("<KeyRelease>", self.update_password_strength)
        
        finish_btn = ctk.CTkButton(main_frame, text="Complete Setup", 
                                   command=lambda: self.complete_setup(setup_window),
                                   height=45, font=ctk.CTkFont(size=16))
        finish_btn.pack(pady=20)

    def update_password_strength(self, event):
        password = self.setup_master_password.get()
        if password:
            score, strength, recommendations = self.password_generator.assess_strength(password)
            color_map = {
                "Excellent": "#00FF00", "Very Strong": "#00FF00", "Strong": "#44FF44",
                "Medium": "#FFAA44", "Weak": "#FF8844", "Very Weak": "#FF4444"
            }
            color = color_map.get(strength, "#888888")
            self.strength_label.configure(
                text=f"Length: {len(password)} chars | Strength: {strength} ({score}/100)", 
                text_color=color
            )

    def complete_setup(self, setup_window):
        master_password = self.setup_master_password.get()
        confirm_password = self.setup_confirm_password.get()
        if not master_password or master_password != confirm_password:
            messagebox.showerror("Error", "Passwords don't match or are empty")
            return
        try:
            if self.secure_file_manager:
                if not self.secure_file_manager.initialize_encryption(master_password):
                    messagebox.showerror("Error", "Failed to initialize secure storage")
                    return
                if not self.secure_file_manager.initialize_vault_files():
                    messagebox.showerror("Error", "Failed to create secure vault files")
                    return
                self.secure_file_manager.load_files_to_temp()
            
            db_path = "manageyouraccount"
            self.database = DatabaseManager(db_path, self.crypto, self.secure_file_manager)
            self.database.initialize_database(master_password)
            
            if self.secure_file_manager:
                self.secure_file_manager.sync_all_files()
            messagebox.showinfo("Success", "SecureVault has been set up successfully!")
            setup_window.destroy()
            self.show_login_screen()
        except Exception as e:
            messagebox.showerror("Error", f"Setup failed: {str(e)}")

    def show_main_interface(self):
        self.root.state('zoomed')
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        self.reset_inactivity_timer()
        self.root.bind("<KeyPress>", self.reset_inactivity_timer)
        self.root.bind("<Motion>", self.reset_inactivity_timer)
        self.root.bind("<Button-1>", self.reset_inactivity_timer)

        toolbar = ctk.CTkFrame(self.main_frame, height=70)
        toolbar.pack(fill="x", padx=10, pady=10)
        toolbar.pack_propagate(False)
        
        ctk.CTkLabel(
            toolbar, 
            text="🔒 Secure Password Manager", 
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(side="left", padx=25, pady=20)
        
        ctk.CTkButton(
            toolbar, 
            text="Logout", 
            width=100, 
            height=55,
            image=logout,
            compound="left",  # icon on the left, text on the right
            command=self.lock_vault,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)
        
        ctk.CTkButton(
            toolbar, 
            text="Settings", 
            width=120, 
            height=55,
            image=settings,
            compound="left",  # icon on the left, text on the right
            command=self.show_settings,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)

        ctk.CTkButton(
            toolbar,
            text="Backup",
            width=120,
            height=55,
            image=save,
            compound="left",  # icon on the left, text on the right            
            command=self.show_backup_dialog,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)

        ctk.CTkButton(
            toolbar,
            text="Restore old backup",
            width=160,
            height=55,
            image=restore_icon,
            compound="left",  # icon on the left, text on the right
            command=self.show_restore_dialog,
            font=ctk.CTkFont(size=16)
        ).pack(side="right", padx=8, pady=8)
        
        content_frame = ctk.CTkFrame(self.main_frame)
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.create_sidebar(content_frame)
        self.main_panel = ctk.CTkFrame(content_frame)
        self.main_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        self.show_passwords()

    def show_restore_dialog(self):
        import glob, os, tempfile, shutil, json, sys
        from datetime import datetime
        import tkinter as tk
        import tkinter.simpledialog as simpledialog
        from tkinter import messagebox
        from backup_manager import BackupManager, BackupError

        if not getattr(self, "database", None):
            messagebox.showerror("Error", "Database not available. Please log in first.")
            return

        backup_folder = os.path.join(os.getcwd(), "backups")
        os.makedirs(backup_folder, exist_ok=True)
        backups = sorted(glob.glob(os.path.join(backup_folder, "*.svbk")), reverse=True)

        if not backups:
            messagebox.showinfo("No backups found", "No backup files were found in ./backups/")
            return

        win = tk.Toplevel(self.root)
        win.title("Restore Backup")
        win.geometry("820x480")
        win.resizable(True, True)

        top_frame = tk.Frame(win)
        top_frame.pack(fill="x", padx=12, pady=(12,6))

        tk.Label(top_frame, text="Available backups (most recent first):", anchor="w", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")

        info_label = tk.Label(top_frame, text="Select a backup to see details", anchor="w", justify="left")
        info_label.pack(fill="x", pady=(6,0))

        listbox_frame = tk.Frame(win)
        listbox_frame.pack(fill="both", expand=False, padx=12, pady=(8,6))

        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side="right", fill="y")

        listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set, width=120, height=10)
        for i, path in enumerate(backups):
            fname = os.path.basename(path)
            listbox.insert("end", f"{i+1}. {fname}")
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=listbox.yview)

        preview_lbl = tk.Label(win, text="Preview / Manifest (enter code to view):", anchor="w")
        preview_lbl.pack(fill="x", padx=12)
        preview_text = tk.Text(win, height=10, wrap="word")
        preview_text.pack(fill="both", padx=12, pady=(4,8), expand=True)
        preview_text.configure(state="disabled")

        btn_frame = tk.Frame(win)
        btn_frame.pack(fill="x", padx=12, pady=(6,12))

        status_var = tk.StringVar(value="")
        status_label = tk.Label(win, textvariable=status_var, anchor="w", fg="blue")
        status_label.pack(fill="x", padx=12, pady=(0,8))

        def on_selection(event=None):
            sel = listbox.curselection()
            if not sel:
                info_label.config(text="Select a backup to see details")
                return
            idx = sel[0]
            path = backups[idx]
            try:
                size = os.path.getsize(path)
                mtime = datetime.utcfromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%SZ")
                info_text = f"File: {os.path.basename(path)}\nPath: {path}\nSize: {size:,} bytes\nLast modified (UTC): {mtime}\n\nTip: Use 'Preview contents' to view the manifest (requires backup code)."
                info_label.config(text=info_text)
            except Exception as e:
                info_label.config(text=f"Error reading file info: {e}")

        listbox.bind("<<ListboxSelect>>", on_selection)
        on_selection()

        def preview_contents():
            sel = listbox.curselection()
            if not sel:
                messagebox.showerror("No selection", "Please select a backup to preview.")
                return
            idx = sel[0]
            backup_path = backups[idx]

            code = simpledialog.askstring("Backup Code", "Enter the backup code to preview this backup:", parent=win, show="*")
            if code is None:
                return

            status_var.set("Previewing backup (decrypting)... this may take a moment")
            win.update_idletasks()
            tempdir = tempfile.mkdtemp(prefix="sv_preview_")
            try:
                bm = BackupManager(
                    metadata_db_path=getattr(self.database, "metadata_db", os.path.join(os.getcwd(), "metadata.db")),
                    sensitive_db_path=getattr(self.database, "sensitive_db", os.path.join(os.getcwd(), "sensitive.db")),
                    salt_path=getattr(self.database, "salt_path", os.path.join(os.getcwd(), "salt_file")),
                    integrity_path=getattr(self.database, "integrity_path", os.path.join(os.getcwd(), "integrity_file")),
                    backups_dir=backup_folder
                )
                try:
                    restored = bm.restore_backup(backup_path, code, restore_to_dir=tempdir)
                except BackupError as be:
                    messagebox.showerror("Preview failed", f"Failed to decrypt/preview backup: {be}")
                    return
                except Exception as e:
                    messagebox.showerror("Preview failed", f"Unexpected error during preview: {e}")
                    return

                manifest_path = os.path.join(tempdir, "backup_manifest.json")
                preview_text.configure(state="normal")
                preview_text.delete("1.0", "end")
                if os.path.exists(manifest_path):
                    try:
                        with open(manifest_path, "r", encoding="utf-8") as mf:
                            manifest = json.load(mf)
                        pretty = json.dumps(manifest, indent=2, ensure_ascii=False)
                        preview_text.insert("1.0", pretty)
                    except Exception as e:
                        preview_text.insert("1.0", f"Failed to read manifest: {e}\n\nFiles restored to temp dir:\n" + "\n".join(os.path.basename(p) for p in restored))
                else:
                    preview_text.insert("1.0", "No manifest found. Files contained:\n" + "\n".join(os.path.basename(p) for p in restored))

                preview_text.configure(state="disabled")
            finally:
                try:
                    shutil.rmtree(tempdir)
                except Exception:
                    pass
                status_var.set("Preview complete")

        def perform_restore():
            sel = listbox.curselection()
            if not sel:
                messagebox.showerror("No selection", "Please select a backup to restore.")
                return
            idx = sel[0]
            backup_path = backups[idx]

            code = simpledialog.askstring("Backup Code", "Enter the backup code for this file:", parent=win, show="*")
            if code is None:
                return

            proceed = messagebox.askyesno(
                "Confirm restore",
                "Restoring will overwrite the active vault files. A backup of existing files will be created (suffix .bak.TIMESTAMP). Proceed?"
            )
            if not proceed:
                return

            status_var.set("Restoring backup... please wait")
            win.update_idletasks()
            tempdir = tempfile.mkdtemp(prefix="sv_restore_")
            try:
                bm = BackupManager(
                    metadata_db_path=getattr(self.database, "metadata_db", os.path.join(os.getcwd(), "metadata.db")),
                    sensitive_db_path=getattr(self.database, "sensitive_db", os.path.join(os.getcwd(), "sensitive.db")),
                    salt_path=getattr(self.database, "salt_path", os.path.join(os.getcwd(), "salt_file")),
                    integrity_path=getattr(self.database, "integrity_path", os.path.join(os.getcwd(), "integrity_file")),
                    backups_dir=backup_folder
                )

                try:
                    restored = bm.restore_backup(backup_path, code, restore_to_dir=tempdir)
                except BackupError as be:
                    shutil.rmtree(tempdir, ignore_errors=True)
                    messagebox.showerror("Restore failed", f"Failed to decrypt/restore backup: {be}")
                    status_var.set("")
                    return
                except Exception as e:
                    shutil.rmtree(tempdir, ignore_errors=True)
                    messagebox.showerror("Restore failed", f"Unexpected error while restoring: {e}")
                    status_var.set("")
                    return

                metadata_db_path = getattr(self.database, "metadata_db", None)
                if metadata_db_path:
                    vault_dir = os.path.dirname(metadata_db_path) or os.getcwd()
                else:
                    vault_dir = os.path.join(os.getcwd(), "secure_vault")
                os.makedirs(vault_dir, exist_ok=True)

                timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                backups_created = []
                moved = []

                for fpath in restored:
                    base = os.path.basename(fpath)
                    if base == "backup_manifest.json":
                        continue
                    dest = os.path.join(vault_dir, base)
                    if os.path.exists(dest):
                        bak_name = f"{dest}.bak.{timestamp}"
                        shutil.move(dest, bak_name)
                        backups_created.append(bak_name)
                    shutil.move(fpath, dest)
                    moved.append(dest)

                shutil.rmtree(tempdir, ignore_errors=True)
                status_var.set("Restore complete")
                message = f"Restore complete.\n\nRestored files:\n" + "\n".join(os.path.basename(p) for p in moved)
                if backups_created:
                    message += "\n\nBackups of previous files:\n" + "\n".join(backups_created)
                message += ("\n\nIMPORTANT: The program must be restarted for changes to take full effect.\n"
                            "Please save your work. Do you want to exit the program now?")

                if messagebox.askyesno("Restore complete - Exit now?", message):
                    try:
                        try:
                            self.root.destroy()
                        except Exception:
                            pass
                        sys.exit(0)
                    except SystemExit:
                        raise
                    except Exception as e:
                        messagebox.showinfo("Exit failed", f"Automatic exit failed: {e}\nPlease close the program manually.")
                else:
                    messagebox.showinfo("Restore complete", "Restore complete. Please restart the program later for changes to take effect.")
                win.destroy()
            except Exception as e:
                messagebox.showerror("Restore error", f"An error occurred during restore: {e}")
                status_var.set("")
                try:
                    shutil.rmtree(tempdir, ignore_errors=True)
                except Exception:
                    pass

        preview_btn = tk.Button(btn_frame, text="Preview contents", command=preview_contents, width=18)
        preview_btn.pack(side="left", padx=(0,8))

        restore_btn = tk.Button(btn_frame, text="Restore Selected Backup", command=perform_restore, width=22)
        restore_btn.pack(side="left", padx=(0,8))

        close_btn = tk.Button(btn_frame, text="Close", command=win.destroy, width=12)
        close_btn.pack(side="right")

        win.transient(self.root)
        win.grab_set()
        win.focus_force()

    def show_backup_dialog(self):
        import tkinter.simpledialog as simpledialog
        if not self.database:
            messagebox.showerror("Error", "Database is not available (not authenticated).")
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("🛡️ Create Secure Backup")
        dialog.geometry("630x730")
        dialog.grab_set()
        dialog.resizable(False, False)

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="🔐 Create Encrypted Backup", 
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(20, 10))

        warning_frame = ctk.CTkFrame(main_frame, fg_color="#2b1515")  # Dark red background
        warning_frame.pack(fill="x", padx=10, pady=15)

        ctk.CTkLabel(warning_frame, text="⚠️ CRITICAL SECURITY WARNINGS", 
                    font=ctk.CTkFont(size=18, weight="bold"), 
                    text_color="#ff4444").pack(pady=(15, 10))

        warnings_text = """🚨 BACKUP CODE IS EXTREMELY IMPORTANT:
    • If you LOSE your backup code, your backup is PERMANENTLY UNUSABLE
    • Write down your backup code on PAPER and store it SAFELY
    • DO NOT store the backup code digitally on the same device
    • Consider storing the code in multiple SECURE physical locations

    🔒 BACKUP SECURITY BEST PRACTICES:
    • Use a STRONG, UNIQUE backup code (minimum 12 characters)
    • Include uppercase, lowercase, numbers, and symbols
    • NEVER share your backup code with anyone
    • Store backups and codes in SEPARATE secure locations

    💾 BACKUP FILE SAFETY:
    • Store backup files (.svbk) in secure, encrypted storage
    • Make multiple copies in different safe locations
    • Test your backup restoration periodically
    • Keep backup codes separate from backup files"""

        warning_label = ctk.CTkLabel(warning_frame, text=warnings_text, 
                                    font=ctk.CTkFont(size=12), 
                                    text_color="#ff6666",
                                    justify="left")
        warning_label.pack(padx=15, pady=(0, 15))

        code_frame = ctk.CTkFrame(main_frame)
        code_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(code_frame, text="Enter Backup Code:", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 5))

        ctk.CTkLabel(code_frame, text="⚠️ Remember: This code is required to restore your backup!", 
                    font=ctk.CTkFont(size=12), 
                    text_color="#ff4444").pack(pady=(0, 10))

        code_entry = ctk.CTkEntry(code_frame, width=400, height=40, show="*",
                                placeholder_text="Enter a strong backup code...")
        code_entry.pack(pady=(0, 10))

        def toggle_code_visibility():
            if code_entry.cget("show") == "*":
                code_entry.configure(show="")
                show_btn.configure(text="🙈 Hide")
            else:
                code_entry.configure(show="*")
                show_btn.configure(text="👁️ Show")

        show_btn = ctk.CTkButton(code_frame, text="👁️ Show", width=80, height=30,
                                command=toggle_code_visibility)
        show_btn.pack(pady=(0, 15))

        def create_backup():
            code = code_entry.get().strip()
            if not code:
                messagebox.showerror("Error", "⚠️ Backup code is required!")
                return

            if len(code) < 8:
                messagebox.showerror("Error", "⚠️ Backup code must be at least 8 characters long!")
                return
            confirm_msg = f"""⚠️ FINAL CONFIRMATION ⚠️

    You are about to create an encrypted backup with the code you entered.

    🚨 CRITICAL REMINDERS:
    • Have you written down your backup code on PAPER?
    • Have you stored it in a SAFE, SECURE location?
    • Do you understand that WITHOUT this code, your backup is USELESS?

    Backup code length: {len(code)} characters

    Are you absolutely sure you want to proceed?"""

            if not messagebox.askyesno("🔐 Final Backup Confirmation", confirm_msg):
                return
            try:
                if self.secure_file_manager:
                    self.secure_file_manager.sync_all_files()

                bm = BackupManager(
                    metadata_db_path=self.database.metadata_db,
                    sensitive_db_path=self.database.sensitive_db,
                    salt_path=self.database.salt_path,
                    integrity_path=self.database.integrity_path,
                    backups_dir="backups"
                )
                out_path = bm.create_backup(code)
                
                success_msg = f"""✅ Backup Created Successfully!

    📁 Backup saved to: {out_path}

    🚨 IMPORTANT NEXT STEPS:
    1. ✍️ Write your backup code on PAPER immediately
    2. 🏦 Store the code in a SECURE location (safe, bank vault, etc.)
    3. 💾 Copy the backup file to MULTIPLE secure locations
    4. 🧪 Test your backup by attempting to restore it
    5. 🔄 Create regular backups and update storage locations

    ⚠️ Remember: Your backup is only as secure as your backup code storage!"""
                
                messagebox.showinfo("🎉 Backup Complete", success_msg)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("❌ Backup Failed", 
                                f"Failed to create backup:\n\n{str(e)}\n\n"
                                f"Please check your permissions and try again.")

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        ctk.CTkButton(button_frame, text="Cancel", 
                    command=dialog.destroy, 
                    width=120, height=45).pack(side="left", padx=15)
        ctk.CTkButton(button_frame, text="🔐 Create Backup", 
                    command=create_backup,
                    width=180, height=45, 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(side="right", padx=15)
        code_entry.focus()
        
    def create_sidebar(self, parent):
        self.sidebar = ctk.CTkFrame(parent, width=280)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        self.sidebar.pack_propagate(False)
        ctk.CTkLabel(
            self.sidebar, 
            text="Navigation", 
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(20, 15), padx=15)
        self.sidebar_buttons = []
        self.active_button = None
        icon_accounts   = ctk.CTkImage(Image.open("icons/user.png"), size=(24, 24))
        icon_generator  = ctk.CTkImage(Image.open("icons/password.png"), size=(24, 24))
        icon_report     = ctk.CTkImage(Image.open("icons/security.png"), size=(24, 24))
        icon_audit      = ctk.CTkImage(Image.open("icons/log.png"), size=(24, 24))

        sidebar_configs = [
            ("Your Accounts", icon_accounts, self.show_passwords),
            ("Password Generator", icon_generator, self.show_password_generator),
            ("Security Report", icon_report, self.show_security_report),
        ]
        for text, icon, command in sidebar_configs:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                image=icon,
                compound="left",         # show icon + text
                anchor="w",              # left-align content
                command=lambda cmd=command, txt=text: self.handle_sidebar_click(cmd, txt),
                height=60,
                font=ctk.CTkFont(size=18),
                corner_radius=10,
                fg_color=("gray75", "gray25"),
                hover_color=("gray70", "gray30")
            )
            btn.pack(fill="x", padx=15, pady=10)
            self.sidebar_buttons.append(btn)
        if self.sidebar_buttons:
            self.set_active_button(self.sidebar_buttons[0])
    
    def handle_sidebar_click(self, command, button_text):
        clicked_button = next((btn for btn in self.sidebar_buttons if btn.cget("text") == button_text), None)
        if clicked_button:
            self.set_active_button(clicked_button)
        command()

    def set_active_button(self, active_button):
        for btn in self.sidebar_buttons:
            btn.configure(
                fg_color=("gray75", "gray25"),
                hover_color=("gray70", "gray30"),
                text_color=("gray10", "gray90")
            )
        if active_button:
            active_button.configure(
                fg_color=("#3B82F6", "#1E40AF"),
                hover_color=("#2563EB", "#1D4ED8"),
                text_color=("white", "white")
            )
            self.active_button = active_button

    def lock_vault(self):
        try:
            if self.secure_file_manager and self.authenticated:
                logger.info("Syncing files to secure storage before lock...")
                self.secure_file_manager.sync_all_files()
                
                if not self.secure_file_manager.perform_integrity_check():
                    logger.error("Integrity check failed during vault lock")
                    messagebox.showwarning("Security Warning", 
                                        "File integrity check failed.")
                
                self.secure_file_manager.cleanup_temp_files()
                logger.info("Temporary files cleaned up")
            self.authenticated = False
            self.database = None
            self.security_monitor = None
            self.show_login_screen()
            
            logger.info("Vault locked successfully")
            
        except Exception as e:
            logger.error(f"Error during vault lock: {e}")
            self.authenticated = False
            self.database = None
            self.show_login_screen()

    def reset_inactivity_timer(self, event=None):
        if self.inactivity_timer:
            self.root.after_cancel(self.inactivity_timer)
        self.inactivity_timer = self.root.after(self.INACTIVITY_TIMEOUT, self.force_logout)

    def force_logout(self):
        logger.info("Logging out due to inactivity.")
        self.lock_vault()
        self.root.quit()
    
    def run(self):
        try:
            self.root.mainloop()
        finally:
            if self.secure_file_manager:
                logger.info("Performing final sync and cleanup...")
                try:
                    if self.authenticated:
                        self.secure_file_manager.sync_all_files()
                    self.secure_file_manager.cleanup_temp_files()
                    logger.info("Secure cleanup completed")
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")

    def create_desktop_integration():
        try:
            import sys
            import subprocess
            from pathlib import Path
            
            if getattr(sys, 'frozen', False):
                app_path = sys.executable
                app_dir = Path(sys.executable).parent
            else:
                app_path = sys.argv[0]
                app_dir = Path(__file__).parent
            desktop_path = Path.home() / "Desktop"
            if not desktop_path.exists():
                desktop_path = Path.home() / "OneDrive" / "Desktop"
                if not desktop_path.exists():
                    desktop_path = Path.home()
            
            if sys.platform == "win32":
                try:
                    import win32com.client
                    shell = win32com.client.Dispatch("WScript.Shell")
                    shortcut = shell.CreateShortCut(str(desktop_path / "SecureVault Password Manager.lnk"))
                    shortcut.Targetpath = str(app_path)
                    shortcut.WorkingDirectory = str(app_dir)
                    shortcut.Description = "SecureVault Password Manager - Secure Password Storage"
                    shortcut.save()
                    logger.info("Windows desktop shortcut created")
                except ImportError:
                    batch_content = f"""@echo off
    cd /d "{app_dir}"
    "{app_path}"
    pause
    """
                    with open(desktop_path / "SecureVault Password Manager.bat", "w") as f:
                        f.write(batch_content)
                    logger.info("Windows batch file created")
                    
            elif sys.platform == "darwin":  # macOS
                try:
                    script = f'''
                    tell application "Finder"
                        make alias file to file POSIX file "{app_path}" at desktop
                        set name of result to "SecureVault Password Manager"
                    end tell
                    '''
                    subprocess.run(["osascript", "-e", script], check=True)
                    logger.info("macOS alias created")
                except:
                    logger.warning("Could not create macOS shortcut automatically")
            else:  # Linux and other Unix-like systems
                desktop_file_content = f"""[Desktop Entry]
    Version=1.0
    Type=Application
    Name=SecureVault Password Manager
    Comment=Secure Password Storage and Management
    Exec="{app_path}"
    Icon=application-x-executable
    Terminal=false
    StartupNotify=true
    Categories=Utility;Security;
    """
                desktop_file_path = desktop_path / "SecureVault Password Manager.desktop"
                with open(desktop_file_path, "w") as f:
                    f.write(desktop_file_content)
                desktop_file_path.chmod(0o755)
                logger.info("Linux desktop file created")
            return True
        except Exception as e:
            logger.warning(f"Could not create desktop integration: {e}")
            return False

    def show_settings(self):
        settings_window = ctk.CTkToplevel(self.root)
        settings_window.title("Password Vault Settings")
        settings_window.geometry("500x500")
        settings_window.grab_set()
        settings_window.resizable(False, False)
        
        main_frame = ctk.CTkFrame(settings_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🔐 Security Settings", 
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)
        
        password_frame = ctk.CTkFrame(main_frame)
        password_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(password_frame, text="Master Password", 
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        ctk.CTkButton(password_frame, text="Change Master Password",
                    command=self.change_master_password_dialog,
                    height=40).pack(pady=10)

        tfa_frame = ctk.CTkFrame(main_frame)
        tfa_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(tfa_frame, text="Two-Factor Authentication",
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        tfa_enabled = self.settings.get('tfa_secret') is not None
        tfa_button_text = "Disable 2FA" if tfa_enabled else "Enable 2FA"
        tfa_button = ctk.CTkButton(tfa_frame, text=tfa_button_text,
                                   command=self.show_tfa_dialog,
                                   height=40)
        tfa_button.pack(pady=10)


        timeout_frame = ctk.CTkFrame(main_frame)
        timeout_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(timeout_frame, text="Automatic Logout",
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        ctk.CTkLabel(timeout_frame, text="For your security, the application will automatically\nlock and close after 3 minutes of inactivity.",
                    font=ctk.CTkFont(size=12)).pack(pady=10)

    def show_tfa_dialog(self):
        tfa_enabled = self.settings.get('tfa_secret') is not None
        if tfa_enabled:
            self.disable_tfa_dialog()
        else:
            self.enable_tfa_dialog()

    def enable_tfa_dialog(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Enable Two-Factor Authentication")
        dialog.geometry("380x550")
        dialog.resizable(False, False)
        dialog.grab_set()
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="Scan QR Code with your Authenticator App",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        secret = self.tfa_manager.generate_secret()
        uri = self.tfa_manager.get_provisioning_uri(secret, "user@securevault")
        qr_image_data = self.tfa_manager.generate_qr_code(uri)
        qr_image = Image.open(qr_image_data)
        qr_photo = ImageTk.PhotoImage(qr_image)
        
        qr_label = ctk.CTkLabel(main_frame, image=qr_photo, text="")
        qr_label.image = qr_photo
        qr_label.pack(pady=10)

        ctk.CTkLabel(main_frame, text="Enter the 6-digit code to verify:",
                     font=ctk.CTkFont(size=14)).pack(pady=10)
        
        code_entry = ctk.CTkEntry(main_frame, width=200)
        code_entry.pack(pady=5)

        def verify_and_enable():
            code = code_entry.get().strip()
            if self.tfa_manager.verify_code(secret, code):
                encrypted_secret = self.crypto.encrypt_data(secret, self.database.encryption_key)
                self.settings['tfa_secret'] = base64.b64encode(encrypted_secret).decode('utf-8')
                self.save_settings_to_file()
                messagebox.showinfo("Success", "2FA enabled successfully!")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Invalid code. Please try again.")

        verify_button = ctk.CTkButton(main_frame, text="Verify and Enable", command=verify_and_enable)
        verify_button.pack(pady=20)

    def disable_tfa_dialog(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Disable Two-Factor Authentication")
        dialog.geometry("400x250")
        dialog.grab_set()

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="Enter a 6-digit code to disable 2FA:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        
        code_entry = ctk.CTkEntry(main_frame, width=200)
        code_entry.pack(pady=10)

        def verify_and_disable():
            code = code_entry.get().strip()
            encrypted_secret_b64 = self.settings.get('tfa_secret')
            encrypted_secret = base64.b64decode(encrypted_secret_b64)
            secret = self.crypto.decrypt_data(encrypted_secret, self.database.encryption_key)
            if self.tfa_manager.verify_code(secret, code):
                self.settings['tfa_secret'] = None
                self.save_settings_to_file()
                messagebox.showinfo("Success", "2FA disabled successfully!")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Invalid code.")

        verify_button = ctk.CTkButton(main_frame, text="Verify and Disable", command=verify_and_disable)
        verify_button.pack(pady=20)

    def prompt_for_tfa(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Two-Factor Authentication")
        dialog.geometry("400x250")
        dialog.grab_set()

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="Enter your 6-digit 2FA code:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        
        code_entry = ctk.CTkEntry(main_frame, width=200)
        code_entry.pack(pady=10)

        def verify_tfa():
            code = code_entry.get().strip()
            encrypted_secret_b64 = self.settings.get('tfa_secret')
            encrypted_secret = base64.b64decode(encrypted_secret_b64)
            secret = self.crypto.decrypt_data(encrypted_secret, self.database.encryption_key)
            if self.tfa_manager.verify_code(secret, code):
                self.authenticated = True
                self.failed_attempts = 0
                self.consecutive_lockouts = 0
                self.clear_lockout_state()
                if self.secure_file_manager:
                    self.security_monitor = SecurityMonitor(self.secure_file_manager)
                    self.security_monitor.set_alert_callback(self.handle_security_alert)
                    self._start_security_monitoring()
                dialog.destroy()
                self.show_main_interface()
            else:
                messagebox.showerror("Error", "Invalid 2FA code.")
                self.failed_attempts += 1
                if self.failed_attempts >= 3:
                    self.consecutive_lockouts += 1
                    lockout_minutes = 3 * self.consecutive_lockouts
                    self.lockout_until = datetime.now() + timedelta(minutes=lockout_minutes)
                    self.save_lockout_state()
                    messagebox.showerror("Account Locked", 
                                f"Too many failed attempts. Account locked for {lockout_minutes} minutes.")
                    self.failed_attempts = 0
                    dialog.destroy()
                    self.lock_vault()

        verify_button = ctk.CTkButton(main_frame, text="Verify", command=verify_tfa)
        verify_button.pack(pady=20)

    def change_master_password_dialog(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Change Master Password")
        dialog.geometry("450x530")
        dialog.resizable(False, False)
        dialog.grab_set()
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🔒 Change Master Password",
                    font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        ctk.CTkLabel(main_frame, text="Current Password:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        current_entry = ctk.CTkEntry(main_frame, placeholder_text="Enter current password", 
                                    show="*", width=350, height=40)
        current_entry.pack(padx=20, pady=(0, 10))
        
        ctk.CTkLabel(main_frame, text="New Password:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        new_entry = ctk.CTkEntry(main_frame, placeholder_text="Enter new password", 
                                show="*", width=350, height=40)
        new_entry.pack(padx=20, pady=(0, 10))
        
        ctk.CTkLabel(main_frame, text="Confirm New Password:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        confirm_entry = ctk.CTkEntry(main_frame, placeholder_text="Confirm new password", 
                                    show="*", width=350, height=40)
        confirm_entry.pack(padx=20, pady=(0, 15))
        progress_label = ctk.CTkLabel(main_frame, text="", font=ctk.CTkFont(size=12))
        progress_label.pack(pady=5)
        
        def validate_and_change_password():
            try:
                progress_label.configure(text="", text_color="white")
            except:
                return
            current = current_entry.get().strip()
            new = new_entry.get().strip()
            confirm = confirm_entry.get().strip()
            if not current:
                try:
                    progress_label.configure(text="❌ Current password is required", text_color="#FF4444")
                except:
                    messagebox.showerror("Error", "Current password is required")
                    return
                current_entry.focus()
                return
            if not new:
                try:
                    progress_label.configure(text="❌ New password is required", text_color="#FF4444")
                except:
                    messagebox.showerror("Error", "New password is required")
                    return
                new_entry.focus()
                return
            if len(new) < 8:
                try:
                    progress_label.configure(text="❌ New password must be at least 8 characters", text_color="#FF4444")
                except:
                    messagebox.showerror("Error", "New password must be at least 8 characters")
                    return
                new_entry.focus()
                return
            if new != confirm:
                try:
                    progress_label.configure(text="❌ New passwords don't match", text_color="#FF4444")
                except:
                    messagebox.showerror("Error", "New passwords don't match")
                    return
                confirm_entry.focus()
                return
            if current == new:
                try:
                    progress_label.configure(text="❌ New password must be different from current", text_color="#FF4444")
                except:
                    messagebox.showerror("Error", "New password must be different from current")
                    return
                new_entry.focus()
                return
            try:
                progress_label.configure(text="🔄 Changing password...", text_color="#FFAA44")
                dialog.update()
            except:
                pass
            
            try:
                self.database.change_master_password(current, new)
                try:
                    progress_label.configure(text="✅ Password changed successfully!", text_color="#00FF00")
                    dialog.update()
                except:
                    pass
                restart_result = messagebox.showinfo("Password Changed Successfully", 
                                "Master password changed successfully!\n\n"
                                "🔄 The program will now restart to ensure all changes take effect.\n\n"
                                "Please wait while the application restarts...")
                dialog.destroy()
                self.restart_program()
                
            except ValueError as ve:
                error_msg = str(ve)
                if "Current password is incorrect" in error_msg:
                    try:
                        progress_label.configure(text="❌ Current password is incorrect", text_color="#FF4444")
                    except:
                        messagebox.showerror("Error", "Current password is incorrect")
                    current_entry.focus()
                    current_entry.select_range(0, tk.END)
                else:
                    try:
                        progress_label.configure(text=f"❌ {error_msg}", text_color="#FF4444")
                    except:
                        messagebox.showerror("Error", error_msg)
            except Exception as e:
                error_msg = f"Password change failed: {str(e)}"
                logger.error(f"PASSWORD CHANGE ERROR: {error_msg}")
                try:
                    progress_label.configure(text="❌ Password change failed", text_color="#FF4444")
                except:
                    messagebox.showerror("Error", "Password change failed")
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", 
                                command=dialog.destroy, width=120, height=45)
        cancel_btn.pack(side="left", padx=15)
        
        change_btn = ctk.CTkButton(button_frame, text="Change Password", 
                                command=validate_and_change_password,
                                width=150, height=45, 
                                font=ctk.CTkFont(size=16, weight="bold"))
        change_btn.pack(side="right", padx=15)
        
        def on_enter(event):
            validate_and_change_password()
        
        current_entry.bind('<Return>', on_enter)
        new_entry.bind('<Return>', on_enter)
        confirm_entry.bind('<Return>', on_enter)
        current_entry.focus()

    def restart_program(self):
        import sys
        import subprocess
        try:
            logger.info("Initiating secure program restart...")
            if self.secure_file_manager and self.authenticated:
                logger.info("Syncing files to secure storage...")
                self.secure_file_manager.sync_all_files()
                if not self.secure_file_manager.perform_integrity_check():
                    logger.warning("Integrity check failed during restart")
                    messagebox.showwarning("Security Warning", 
                                        "File integrity check failed during restart.")
                self.secure_file_manager.cleanup_temp_files()
                logger.info("Temporary files cleaned up")
            
            self.authenticated = False
            self.database = None
            self.security_monitor = None
            
            logger.info("Secure shutdown completed")
            if getattr(sys, 'frozen', False):
                script_path = sys.executable
            else:
                script_path = sys.argv[0]
            
            logger.info(f"Restarting program: {script_path}")
            
            self.root.destroy()
            
            if getattr(sys, 'frozen', False):
                subprocess.Popen([script_path])
            else:
                subprocess.Popen([sys.executable, script_path])
            
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error during program restart: {e}")
            messagebox.showerror("Restart Error", 
                            f"Failed to restart program automatically: {str(e)}\n\n"
                            "Please manually restart the application.")
            try:
                self.root.quit()
            except:
                sys.exit(1)
                
    def verify_new_password(self, new_password):
        try:
            logger.info("Verifying new password works...")
            temp_db = DatabaseManager(self.database.db_path, self.crypto, self.secure_file_manager)
            if temp_db.authenticate(new_password):
                logger.info("New password verification successful")
                messagebox.showinfo("Verification", 
                                "Password change verified successfully!\n"
                                "Your new password is working correctly.")
            else:
                logger.warning("New password verification failed")
                messagebox.showwarning("Verification Warning", 
                                    "Password was changed but verification failed.\n"
                                    "Please try logging in again.")
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            messagebox.showwarning("Verification Warning", 
                                f"Password was changed but couldn't verify: {str(e)}")
                                        
    def show_passwords(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text="🔑 Your Accounts", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        
        ctk.CTkButton(header, text="➕ Add New Account", 
                      command=self.show_account_dialog,
                      width=180, height=55, font=ctk.CTkFont(size=20, weight="bold")).pack(side="right", padx=25, pady=15)
        
        search_frame = ctk.CTkFrame(self.main_panel)
        search_frame.pack(fill="x", padx=15, pady=10)
        
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="🔍 Search Account ...", 
                                         width=400, height=45)
        self.search_entry.pack(side="left", padx=25, pady=15)
        self.passwords_container = ctk.CTkScrollableFrame(self.main_panel)
        self.passwords_container.pack(fill="both", expand=True, padx=15, pady=15)
        self.load_password_cards()

    def load_password_cards(self):
        for widget in self.passwords_container.winfo_children():
            widget.destroy()
        if not self.database:
            return
        try:
            metadata_conn = sqlite3.connect(self.database.metadata_db)
            cursor = metadata_conn.execute("""
                SELECT id, name, email, url, notes, created_at, updated_at, tags, security_level
                FROM accounts 
                WHERE id != 'master_account'
                ORDER BY updated_at DESC
            """)
            accounts = cursor.fetchall()
            metadata_conn.close()
            if not accounts:
                self.show_no_accounts_message()
                return
            for account_row in accounts:
                self.create_account_card(account_row)
        except Exception as e:
            self.show_error_message(f"Error loading accounts: {str(e)}")

    def show_no_accounts_message(self):
        frame = ctk.CTkFrame(self.passwords_container)
        frame.pack(fill="x", padx=10, pady=20)
        ctk.CTkLabel(frame, text="📝 No accounts found", 
                     font=ctk.CTkFont(size=18, weight="bold"), 
                     text_color="#888888").pack(pady=20)
        ctk.CTkLabel(frame, text="Click 'Add New Account' to get started", 
                     font=ctk.CTkFont(size=14), 
                     text_color="#666666").pack(pady=(0, 20))

    def show_error_message(self, message):
        frame = ctk.CTkFrame(self.passwords_container)
        frame.pack(fill="x", padx=10, pady=20)
        ctk.CTkLabel(frame, text=f"❌ {message}", 
                     font=ctk.CTkFont(size=14), 
                     text_color="#FF4444").pack(pady=20)

    def create_account_card(self, account_row):
        account_id, name, email, url, notes, created_at, updated_at, tags, security_level = account_row
        username, password = self.database.get_account_credentials(account_id)
        
        if password:
            score, strength, _ = self.password_generator.assess_strength(password)
        else:
            score, strength = 0, "Unknown"
        
        account_data = {
            "id": account_id,
            "name": name,
            "username": username or email or "No username",
            "email": email or "",
            "url": url or "No URL",
            "notes": notes or "",
            "strength": strength,
            "score": score
        }
        
        card = ctk.CTkFrame(self.passwords_container, corner_radius=10)
        card.pack(fill="x", padx=10, pady=8)
        
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=20, pady=20)
        
        left_frame = ctk.CTkFrame(content, fg_color="transparent")
        left_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(left_frame, text=name, 
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        ctk.CTkLabel(left_frame, text=f"👤 {account_data['username']}", 
                     text_color="#888888", font=ctk.CTkFont(size=14)).pack(anchor="w", pady=2)
        if url and url != "No URL":
            ctk.CTkLabel(left_frame, text=f"🌐 {url}", 
                         text_color="#888888", font=ctk.CTkFont(size=14)).pack(anchor="w", pady=2)
        right_frame = ctk.CTkFrame(content, fg_color="transparent")
        right_frame.pack(side="right")
        strength_color = self.get_strength_color(strength)
        ctk.CTkLabel(right_frame, text=f"🛡️ {strength}", 
                     text_color=strength_color, font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(0, 10))
        
        self.create_action_buttons(right_frame, account_data)

    def get_strength_color(self, strength):
        colors = {
            "Excellent": "#00FF00", "Very Strong": "#00FF00", "Strong": "#44FF44",
            "Medium": "#FFAA44", "Weak": "#FF8844", "Very Weak": "#FF4444", "Unknown": "#888888"
        }
        return colors.get(strength, "#888888")

    def create_action_buttons(self, parent, account):
        button_frame = ctk.CTkFrame(parent, fg_color="transparent")
        button_frame.pack()
        buttons = [
            ("👁️ View", lambda: self.view_account_details(account)),
            ("📋 Copy Password", lambda: self.copy_password_to_clipboard(account)),
            ("✏️ Edit Data", lambda: self.show_account_dialog(account)),
            ("🗑️ Delete Account", lambda: self.delete_account(account))
        ]
        if account['url'] and account['url'] != "No URL":
            buttons.insert(2, ("🌐 Open", lambda: self.open_website(account)))
        for text, command in buttons:
            color = "#FF4444" if "Delete" in text else None
            ctk.CTkButton(button_frame, text=text, width=100, height=45,
                          command=command, font=ctk.CTkFont(size=16),
                          fg_color=color).pack(side="left", padx=5)

    def delete_account(self, account):
        result = messagebox.askyesno("Confirm Delete", 
                                     f"Are you sure you want to delete '{account['name']}'?\n\nThis action cannot be undone!")
        if result:
            try:
                self.database.delete_account(account['id'])
                messagebox.showinfo("Deleted", f"Account '{account['name']}' has been deleted.")
                self.load_password_cards()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete account: {str(e)}")

    def view_account_details(self, account):
        if not self.verify_master_password_dialog():
            return
        username, password = self.database.get_account_credentials(account["id"])
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"Account Details - {account['name']}")
        dialog.geometry("500x600")
        dialog.grab_set()
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=f"🔍 {account['name']}",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=15)
        
        details = [
            ("Account Name:", account['name']),
            ("Username:", username or "Not set"),
            ("Email:", account.get('email', 'Not set')),
            ("Website:", account.get('url', 'Not set')),
            ("Password:", password or "Not available")
        ]
        
        for label, value in details:
            self.create_detail_field(main_frame, label, value, is_password="Password" in label)
        
        self.create_detail_field(main_frame, "Notes:", account.get('notes', 'No notes available'))
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text="📋 Copy Password",
                      command=lambda: self.copy_password_to_clipboard(account), width=150).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Close", command=dialog.destroy, width=100).pack(side="right", padx=10)

    def create_detail_field(self, parent, label, value, is_password=False):
        detail_frame = ctk.CTkFrame(parent)
        detail_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(detail_frame, text=label, 
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        if is_password:
            password_frame = ctk.CTkFrame(detail_frame, fg_color="transparent")
            password_frame.pack(fill="x", padx=15, pady=(0, 10))
            
            entry = ctk.CTkEntry(password_frame, width=350, height=35, show="*", 
                                 font=ctk.CTkFont(size=12, family="monospace"))
            entry.pack(side="left", padx=(0, 10))
            entry.insert(0, value)
            entry.configure(state="readonly")
            
            def toggle_visibility():
                if entry.cget("show") == "*":
                    entry.configure(show="")
                    toggle_btn.configure(text="🙈")
                else:
                    entry.configure(show="*")
                    toggle_btn.configure(text="👁️")
            
            toggle_btn = ctk.CTkButton(password_frame, text="👁️", width=40, height=35, 
                                       command=toggle_visibility)
            toggle_btn.pack(side="right")
        else:
            entry = ctk.CTkEntry(detail_frame, width=400, height=35)
            entry.pack(padx=15, pady=(0, 10))
            entry.insert(0, value)
            entry.configure(state="readonly")

    def copy_password_to_clipboard(self, account):
        if not self.verify_master_password_dialog():
            return
        try:
            username, password = self.database.get_account_credentials(account["id"])
            if password:
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                messagebox.showinfo("Copied", f"Password for {account['name']} copied to clipboard!")
                self.root.after(30000, lambda: self.root.clipboard_clear())
            else:
                messagebox.showerror("Error", "Password not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")

    def open_website(self, account):
        messagebox.showinfo("Info", "Website opening functionality has been disabled for security.")

    def show_account_dialog(self, account=None):
        is_edit = account is not None
        title = f"Edit Account - {account['name']}" if is_edit else "Add New Account"
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(title)
        dialog.geometry("550x720")
        dialog.grab_set()
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        icon = "✏️" if is_edit else "➕"
        ctk.CTkLabel(main_frame, text=f"{icon} {title.split(' - ')[0]}", 
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=15)
        entries = self.create_account_form(main_frame, account)
        self.create_account_dialog_buttons(main_frame, dialog, entries, account)

    def create_account_form(self, parent, account=None):
        entries = {}
        if account:
            username, password = self.database.get_account_credentials(account["id"])
        else:
            username = password = ""
        
        fields = [
            ("name", "Account Name:", account['name'] if account else ""),
            ("username", "Username / Email:", username),
            ("url", "Website URL:", account.get('url', '') if account else ""),
            ("password", "Password:", password),
            ("notes", "Notes:", account.get('notes', '') if account else "")
        ]
        
        for field_name, label, default_value in fields:
            ctk.CTkLabel(parent, text=label, 
                         font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=25, pady=(10, 5))
            
            if field_name == "password":
                entries[field_name] = self.create_password_field(parent, default_value)
            elif field_name == "notes":
                entry = ctk.CTkTextbox(parent, width=450, height=80)
                entry.pack(padx=25, pady=(0, 15))
                if default_value:
                    entry.insert("1.0", default_value)
                entries[field_name] = entry
            else:
                entry = ctk.CTkEntry(parent, width=450, height=40)
                entry.pack(padx=25, pady=(0, 15))
                if default_value:
                    entry.insert(0, default_value)
                entries[field_name] = entry
        
        return entries

    def create_password_field(self, parent, default_value=""):
        password_frame = ctk.CTkFrame(parent, fg_color="transparent")
        password_frame.pack(padx=25, pady=(0, 15))
        password_entry = ctk.CTkEntry(password_frame, width=320, height=40, show="*")
        password_entry.pack(side="left", padx=(0, 10))
        if default_value:
            password_entry.insert(0, default_value)
        
        def toggle_password():
            if password_entry.cget("show") == "*":
                password_entry.configure(show="")
                eye_btn.configure(text="🙈")
            else:
                password_entry.configure(show="*")
                eye_btn.configure(text="👁️")
        eye_btn = ctk.CTkButton(password_frame, text="👁️", width=40, height=40, 
                                command=toggle_password)
        eye_btn.pack(side="left", padx=(0, 10))
        
        def generate_password():
            new_password = self.password_generator.generate_password(length=16)
            password_entry.delete(0, tk.END)
            password_entry.insert(0, new_password)
        gen_btn = ctk.CTkButton(password_frame, text="🎲", width=40, height=40, 
                                command=generate_password)
        gen_btn.pack(side="left")
        return password_entry

    def create_account_dialog_buttons(self, parent, dialog, entries, account):
        button_frame = ctk.CTkFrame(parent, fg_color="transparent")
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text="Cancel", 
                      command=dialog.destroy, width=120, height=45).pack(side="left", padx=15)
        
        save_text = "Update Account" if account else "Add Account"
        ctk.CTkButton(button_frame, text=save_text, 
                      command=lambda: self.save_account(dialog, entries, account),
                      width=150, height=45, font=ctk.CTkFont(size=16, weight="bold")).pack(side="right", padx=15)

    def save_account(self, dialog, entries, account=None):
        try:
            name = entries["name"].get().strip()
            username = entries["username"].get().strip()
            url = entries["url"].get().strip()
            password = entries["password"].get()
            notes = entries["notes"].get("1.0", tk.END).strip()
            
            if not name:
                messagebox.showerror("Error", "Account name is required")
                return
            if not password:
                messagebox.showerror("Error", "Password is required")
                return
            if account:  # Update existing account
                self.database.update_account(account["id"], name, username, url, notes, username, password)
                messagebox.showinfo("Success", f"Account '{name}' updated successfully!")
            else:  # Create new account
                max_attempts = 10
                account_id = None
                
                for attempt in range(max_attempts):
                    potential_id = secrets.token_urlsafe(16)
                    try:
                        metadata_conn = sqlite3.connect(self.database.metadata_db)
                        cursor = metadata_conn.execute("SELECT id FROM accounts WHERE id = ?", (potential_id,))
                        existing = cursor.fetchone()
                        metadata_conn.close()
                        if not existing:
                            account_id = potential_id
                            break
                    except Exception as e:
                        logger.error(f"Error checking account ID uniqueness: {e}")
                        continue
                if not account_id:
                    messagebox.showerror("Error", "Failed to generate unique account ID. Please try again.")
                    return
                try:
                    metadata_conn = sqlite3.connect(self.database.metadata_db)
                    cursor = metadata_conn.execute("SELECT name FROM accounts WHERE name = ? AND id != 'master_account'", (name,))
                    existing_name = cursor.fetchone()
                    metadata_conn.close()
                    
                    if existing_name:
                        result = messagebox.askyesno("Duplicate Name", 
                            f"An account with the name '{name}' already exists.\n\nDo you want to create it anyway?")
                        if not result:
                            return
                except Exception as e:
                    logger.error(f"Error checking account name uniqueness: {e}")
                
                try:
                    new_account = Account(
                        id=account_id,
                        name=name,
                        username=username,
                        email=username if "@" in username else "",
                        url=url,
                        notes=notes,
                        created_at=datetime.now(),
                        updated_at=datetime.now(),
                        tags=[],
                        security_level=SecurityLevel.MEDIUM
                    )
                    
                    self.database.add_account(new_account, username, password)
                    messagebox.showinfo("Success", f"Account '{name}' added successfully!")
                    
                except sqlite3.IntegrityError as e:
                    if "UNIQUE constraint failed" in str(e):
                        messagebox.showerror("Error", f"An account with this information already exists.\n\nError: {str(e)}")
                    else:
                        messagebox.showerror("Error", f"Database error: {str(e)}")
                    return
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to create account: {str(e)}")
                    return
            
            dialog.destroy()
            self.load_password_cards()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save account: {str(e)}")
            logger.error(f"Full error details: {e}")
            import traceback
            traceback.print_exc()
            
    def show_password_generator(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text="🛠️ Password Generator", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        
        content = ctk.CTkFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        settings_frame = ctk.CTkFrame(content)
        settings_frame.pack(side="left", fill="both", expand=True, padx=(20, 10), pady=20)
        
        ctk.CTkLabel(settings_frame, text="Generator Settings", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        length_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        length_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(length_frame, text="Password Length:", 
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        
        self.length_var = tk.IntVar(value=16)
        self.length_slider = ctk.CTkSlider(length_frame, from_=8, to=64, 
                                           variable=self.length_var, width=300)
        self.length_slider.pack(fill="x", pady=5)
        self.length_label = ctk.CTkLabel(length_frame, text="16 characters")
        self.length_label.pack(anchor="w")
        
        def update_length_label(value):
            self.length_label.configure(text=f"{int(float(value))} characters")
        
        self.length_slider.configure(command=update_length_label)
        
        options_frame = ctk.CTkFrame(settings_frame)
        options_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(options_frame, text="Character Types:", 
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        
        checkbox_options = [
            ("Include Uppercase (A-Z)", self.use_uppercase),
            ("Include Lowercase (a-z)", self.use_lowercase),
            ("Include Digits (0-9)", self.use_digits),
            ("Include Symbols (!@#$...)", self.use_symbols),
            ("Exclude Ambiguous (0, O, 1, l, I)", self.exclude_ambiguous)
        ]
        for text, var in checkbox_options:
            ctk.CTkCheckBox(options_frame, text=text, variable=var).pack(anchor="w", padx=15, pady=5)
        
        ctk.CTkButton(settings_frame, text="🎲 Generate Password", 
                      command=self.generate_password_gui, height=50,
                      font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        result_frame = ctk.CTkFrame(content)
        result_frame.pack(side="right", fill="both", expand=True, padx=(10, 20), pady=20)
        
        ctk.CTkLabel(result_frame, text="Generated Password", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        password_display_frame = ctk.CTkFrame(result_frame, fg_color="transparent")
        password_display_frame.pack(fill="x", padx=20, pady=10)
        self.generated_password_entry = ctk.CTkEntry(password_display_frame, width=350, height=50,
                                                     font=ctk.CTkFont(size=16, family="monospace"))
        self.generated_password_entry.pack(fill="x", pady=(0, 10))
        button_frame = ctk.CTkFrame(password_display_frame, fg_color="transparent")
        button_frame.pack(fill="x")
        
        ctk.CTkButton(button_frame, text="📋 Copy", width=120, height=40,
                      command=self.copy_generated_password).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(button_frame, text="🔄 Regenerate", width=120, height=40,
                      command=self.generate_password_gui).pack(side="right")
        
        self.strength_frame = ctk.CTkFrame(result_frame)
        self.strength_frame.pack(fill="x", padx=20, pady=15)
        self.strength_title = ctk.CTkLabel(self.strength_frame, text="Password Strength Analysis", 
                                           font=ctk.CTkFont(size=16, weight="bold"))
        self.strength_title.pack(pady=10)
        self.strength_details = ctk.CTkLabel(self.strength_frame, text="Generate a password to see analysis")
        self.strength_details.pack(pady=10)
        self.generate_password_gui()

    def generate_password_gui(self):
        try:
            password = self.password_generator.generate_password(
                length=self.length_var.get(),
                use_uppercase=self.use_uppercase.get(),
                use_lowercase=self.use_lowercase.get(),
                use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(),
                exclude_ambiguous=self.exclude_ambiguous.get()
            )
            self.generated_password_entry.delete(0, tk.END)
            self.generated_password_entry.insert(0, password)
            self.update_strength_analysis(password)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")

    def update_strength_analysis(self, password):
        score, strength, recommendations = self.password_generator.assess_strength(password)
        strength_color = self.get_strength_color(strength)
        self.strength_details.configure(
            text=f"Strength: {strength} ({score}/100)\nLength: {len(password)} characters\nUnique characters: {len(set(password))}",
            text_color=strength_color
        )

    def copy_generated_password(self):
        password = self.generated_password_entry.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showerror("Error", "No password to copy")

    def show_security_report(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text="🛡️ Security Report", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        content = ctk.CTkScrollableFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        
        stats_frame = ctk.CTkFrame(content)
        stats_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(stats_frame, text="📊 Overall Statistics", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        try:
            metadata_conn = sqlite3.connect(self.database.metadata_db)
            cursor = metadata_conn.execute("SELECT id, name FROM accounts WHERE id != 'master_account'")
            accounts = cursor.fetchall()
            metadata_conn.close()
            
            total_accounts = len(accounts)
            weak_passwords = 0
            strong_passwords = 0
            duplicate_passwords = []
            password_counts = {}
            
            for account_id, name in accounts:
                username, password = self.database.get_account_credentials(account_id)
                if password:
                    score, strength, _ = self.password_generator.assess_strength(password)
                    if score < 60:
                        weak_passwords += 1
                    elif score >= 80:
                        strong_passwords += 1
                    if password in password_counts:
                        password_counts[password].append(name)
                    else:
                        password_counts[password] = [name]
            
            for password, names in password_counts.items():
                if len(names) > 1:
                    duplicate_passwords.extend(names)
            
            stats_text = f"""
Total Accounts: {total_accounts}
Strong Passwords: {strong_passwords}
Weak Passwords: {weak_passwords}
Duplicate Passwords: {len(duplicate_passwords)}
            """
            ctk.CTkLabel(stats_frame, text=stats_text, 
                         font=ctk.CTkFont(size=14)).pack(pady=10)
            if weak_passwords > 0:
                weak_frame = ctk.CTkFrame(content)
                weak_frame.pack(fill="x", padx=20, pady=15)
                
                ctk.CTkLabel(weak_frame, text="⚠️ Accounts with Weak Passwords", 
                             font=ctk.CTkFont(size=16, weight="bold"), 
                             text_color="#FF8844").pack(pady=15)
                
                for account_id, name in accounts:
                    username, password = self.database.get_account_credentials(account_id)
                    if password:
                        score, strength, _ = self.password_generator.assess_strength(password)
                        if score < 60:
                            account_frame = ctk.CTkFrame(weak_frame)
                            account_frame.pack(fill="x", padx=15, pady=5)
                            
                            ctk.CTkLabel(account_frame, text=f"{name}: {strength} ({score}/100)", 
                                         text_color=self.get_strength_color(strength)).pack(side="left", padx=15, pady=10)
            if duplicate_passwords:
                dup_frame = ctk.CTkFrame(content)
                dup_frame.pack(fill="x", padx=20, pady=15)
                
                ctk.CTkLabel(dup_frame, text="🔄 Accounts with Duplicate Passwords", 
                             font=ctk.CTkFont(size=16, weight="bold"), 
                             text_color="#FF4444").pack(pady=15)
                for password, names in password_counts.items():
                    if len(names) > 1:
                        dup_account_frame = ctk.CTkFrame(dup_frame)
                        dup_account_frame.pack(fill="x", padx=15, pady=5)
                        
                        ctk.CTkLabel(dup_account_frame, text=f"Shared by: {', '.join(names)}", 
                                     text_color="#FF4444").pack(side="left", padx=15, pady=10)
        except Exception as e:
            ctk.CTkLabel(content, text=f"Error generating security report: {str(e)}", 
                         text_color="#FF4444").pack(pady=20)

    def get_remaining_lockout_time(self) -> int:
        if self.lockout_until and datetime.now() < self.lockout_until:
            return int((self.lockout_until - datetime.now()).total_seconds())
        return 0

    def enforce_lockout(self):
        if self.is_currently_locked_out():
            remaining_time = self.get_remaining_lockout_time()
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            messagebox.showerror("Account Locked", 
                               f"Account is locked for {minutes:02d}:{seconds:02d} due to failed attempts.")
            self.log_security_event("LOCKOUT_ENFORCED", "Login attempt blocked - user locked out")
            return True
        return False

    def is_currently_locked_out(self) -> bool:
        if self.lockout_until and datetime.now() < self.lockout_until:
            return True
        return False

    def check_startup_lockout(self):
        if self.is_currently_locked_out():
            remaining_time = self.get_remaining_lockout_time()
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            logger.info(f"User is locked out on startup - {minutes:02d}:{seconds:02d} remaining")
            self.show_lockout_screen()
            return True
        return False

    def show_lockout_screen(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        lockout_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        lockout_container.place(relx=0.5, rely=0.5, anchor="center")
        lockout_card = ctk.CTkFrame(lockout_container, corner_radius=15)
        lockout_card.pack(padx=20, pady=20)
        self.root.resizable(False, False)
        self.root.update_idletasks()
        width = 800
        height = 500
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        title = ctk.CTkLabel(
            lockout_card, 
            text="🔒 Account Locked", 
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#ff4444"
        )
        title.pack(pady=(30, 20), padx=40)
        subtitle = ctk.CTkLabel(
            lockout_card,
            text="Too many failed login attempts",
            font=ctk.CTkFont(size=16),
            text_color="#888888"
        )
        subtitle.pack(pady=(0, 30), padx=40)
        self.lockout_countdown_label = ctk.CTkLabel(
            lockout_card,
            text="",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#ff4444"
        )
        self.lockout_countdown_label.pack(pady=20, padx=40)
        self.update_lockout_countdown()
        
        info_text = ctk.CTkLabel(
            lockout_card,
            text="Please wait until the lockout period expires.\nThe program will automatically unlock when ready.",
            font=ctk.CTkFont(size=14),
            text_color="#888888",
            justify="center"
        )
        info_text.pack(pady=20, padx=40)
        exit_btn = ctk.CTkButton(
            lockout_card,
            text="Exit Program",
            command=self.root.quit,
            width=200,
            height=45,
            font=ctk.CTkFont(size=16),
            fg_color="#666666",
            hover_color="#555555"
        )
        exit_btn.pack(pady=20)

    def diagnose_secure_storage_issues(self) -> str:
        if not self.secure_file_manager:
            return "Secure file manager is not initialized"
        try:
            is_accessible, issues = self.secure_file_manager.is_secure_storage_accessible()
            if is_accessible:
                return "✅ Secure storage is accessible and properly configured"
            report = "❌ Secure storage issues detected:\n\n"
            for i, issue in enumerate(issues, 1):
                report += f"{i}. {issue}\n"
            report += "\n🔧 Troubleshooting steps:\n"
            report += "1. Ensure you have proper permissions to access the secure storage directory\n"
            report += "2. Check if the secure storage was properly initialized\n"
            report += "3. Verify that all required files exist and are readable\n"
            report += "4. Try running first-time setup again\n"
            report += "5. Check system logs for additional error information"
            return report
        except Exception as e:
            return f"❌ Error during diagnosis: {e}"

    def show_secure_storage_error_dialog(self, error_msg):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Secure Storage Error")
        dialog.geometry("600x400")
        dialog.grab_set()
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🚨 Secure Storage Error", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)
        
        error_text = ctk.CTkTextbox(main_frame, height=200)
        error_text.pack(fill="both", expand=True, padx=10, pady=10)
        error_text.insert("1.0", error_msg)
        error_text.configure(state="disabled")
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkButton(button_frame, text="Close", 
                      command=dialog.destroy,
                      width=100).pack(side="right")

    def run(self):
        try:
            self.root.mainloop()
        finally:
            if self.secure_file_manager:
                logger.info("Performing final sync and cleanup...")
                try:
                    if self.authenticated:
                        self.secure_file_manager.sync_all_files()
                    self.secure_file_manager.cleanup_temp_files()
                    logger.info("Secure cleanup completed")
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")

def main():
    try:
        setup_logging()
        logger.info("Starting SecureVault Password Manager...")
        ModernPasswordManagerGUI.create_desktop_integration()
        app = ModernPasswordManagerGUI()
        logger.info("Application initialized successfully")
        app.run()
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        logger.info("Please ensure all required dependencies are installed:")
        logger.info("pip install customtkinter cryptography pillow")
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Startup Error", 
                           f"Failed to start SecureVault:\n\n{str(e)}\n\n"
                           f"Please check the console for more details.")
        except:
            pass

if __name__ == "__main__":
    main()