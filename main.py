import os
import json
import re
import secrets
import hashlib
import hmac
import base64
import sqlite3
import time
import webbrowser
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
from dataclasses import dataclass 
from enum import Enum
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from secure_file_manager import SecureFileManager, SecureVaultSetup, SecurityMonitor, setup_secure_vault
from backup_manager import BackupManager
from PIL import Image, ImageTk
import logging
from audit_logger import setup_logging
from two_factor_auth import TwoFactorAuthManager
from tutorial import TutorialManager
from localization import LanguageManager
import threading
from notification_manager import start_notification_loop
from trial_manager import TrialManager
from icon_manager import set_icon, ThemedToplevel
from auth_guardian import AuthGuardian
from typing import List
import secrets

logger = logging.getLogger(__name__)

restore_icon = ctk.CTkImage(
    light_image=Image.open("icons/backup.png"),   # path to your icon
    size=(24, 24)  # adjust size
)
log = ctk.CTkImage(
    light_image=Image.open("icons/load.png"),   # path to your icon
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
info = ctk.CTkImage(
    light_image=Image.open("icons/info.png"),   # path to your icon
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
    def __init__(self, lang_manager):
        self.lang_manager = lang_manager
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
            recommendations.append(self.lang_manager.get_string("use_at_least_12_chars"))
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in self.symbols for c in password)
        variety_score = sum([has_lower, has_upper, has_digit, has_symbol]) * 10
        score += variety_score
        if not has_lower:
            recommendations.append(self.lang_manager.get_string("add_lowercase"))
        if not has_upper:
            recommendations.append(self.lang_manager.get_string("add_uppercase"))
        if not has_digit:
            recommendations.append(self.lang_manager.get_string("add_numbers"))
        if not has_symbol:
            recommendations.append(self.lang_manager.get_string("add_symbols"))
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
                recommendations.append(self.lang_manager.get_string("avoid_repeated_chars"))
        if password_length >= 32:
            score += 10
        if password_length >= 50:
            score += 10
        common_patterns = ["123", "abc", "qwerty", "password"]
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 20
            recommendations.append(self.lang_manager.get_string("avoid_common_patterns"))
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
        
    def initialize_database(self, master_password: str, email: str, full_name: str):
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
            metadata_conn.execute("""
                CREATE TABLE IF NOT EXISTS security_questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    question TEXT NOT NULL,
                    answer_hash TEXT NOT NULL
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
                full_name, 
                email, 
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
                        if test_username == "master" and test_password == master_password:
                            logger.info("Test decryption and password verification successful")
                        else:
                            logger.error("Master password verification failed. Decrypted password does not match provided password.")
                            return False
                    except InvalidTag:
                        logger.error("Test decryption failed: Invalid authentication tag. This almost certainly means the password is wrong.")
                        return False
                    except Exception as decrypt_error:
                        logger.error(f"An unexpected error occurred during test decryption: {decrypt_error}")
                        return False
                else:
                    logger.error("No master account found for test decryption. Authentication cannot proceed.")
                    return False
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
            encrypted_username = self.crypto.encrypt_data(username, self.encryption_key)
            encrypted_password = self.crypto.encrypt_data(password, self.encryption_key)
            sensitive_conn.execute("""
                INSERT INTO credentials (account_id, encrypted_username, encrypted_password)
                VALUES (?, ?, ?)
            """, (account.id, encrypted_username, encrypted_password))
            sensitive_conn.commit()

            # Close connections to ensure data is flushed to disk before rotating signature
            if metadata_conn:
                metadata_conn.close()
                metadata_conn = None
            if sensitive_conn:
                sensitive_conn.close()
                sensitive_conn = None
            
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
    
    def get_master_account_email(self) -> Optional[str]:
        metadata_conn = sqlite3.connect(self.metadata_db)
        cursor = metadata_conn.execute("SELECT email FROM accounts WHERE id = 'master_account'")
        row = cursor.fetchone()
        metadata_conn.close()
        if row:
            return row[0]
        return None

    def get_master_account_details(self) -> Optional[Tuple[str, str]]:
        metadata_conn = sqlite3.connect(self.metadata_db)
        cursor = metadata_conn.execute("SELECT name, email FROM accounts WHERE id = 'master_account'")
        row = cursor.fetchone()
        metadata_conn.close()
        if row:
            return row[0], row[1]
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

    def update_master_account_email(self, email: str):
        metadata_conn = sqlite3.connect(self.metadata_db)
        metadata_conn.execute("UPDATE accounts SET email = ? WHERE id = 'master_account'", (email,))
        metadata_conn.commit()
        metadata_conn.close()
        self.log_action("UPDATE", "ACCOUNT", "master_account", f"Updated master account email to {email}")
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
                new_enc_username = self.crypto.encrypt_data(username, new_encryption_key)

                if account_id == 'master_account':
                    # For the master account, encrypt the new password
                    new_enc_password = self.crypto.encrypt_data(new_password, new_encryption_key)
                else:
                    # For all other accounts, re-encrypt their existing password
                    password = self.crypto.decrypt_data(enc_password, self.encryption_key)
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

    def save_security_questions(self, questions: List[Tuple[str, str]]):
        metadata_conn = sqlite3.connect(self.metadata_db)
        try:
            for question, answer_hash in questions:
                metadata_conn.execute("""
                    INSERT INTO security_questions (question, answer_hash)
                    VALUES (?, ?)
                """, (question, answer_hash))
            metadata_conn.commit()
            logger.info("Security questions saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save security questions: {e}")
            metadata_conn.rollback()
            raise
        finally:
            metadata_conn.close()

    def get_security_questions(self) -> List[Tuple[str, str]]:
        metadata_conn = sqlite3.connect(self.metadata_db)
        try:
            cursor = metadata_conn.execute("SELECT question, answer_hash FROM security_questions")
            questions = cursor.fetchall()
            return questions
        except Exception as e:
            logger.error(f"Failed to get security questions: {e}")
            return []
        finally:
            metadata_conn.close()

class SecurityQuestionsDialog(ThemedToplevel):
    def __init__(self, parent, db_manager, crypto_manager, lang_manager):
        super().__init__(parent)
        self.db_manager = db_manager
        self.crypto_manager = crypto_manager
        self.lang_manager = lang_manager
        self.result = False

        self.title(self.lang_manager.get_string("security_questions_title"))
        self.geometry("500x400")
        self.grab_set()
        self.resizable(False, False)

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.questions = self.db_manager.get_security_questions()
        if not self.questions or len(self.questions) != 3:
            self.destroy()
            return
        
        self.answer_entries = []
        for question, answer_hash in self.questions:
            question_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
            question_frame.pack(fill="x", padx=20, pady=10)

            ctk.CTkLabel(
                question_frame,
                text=question,
                font=ctk.CTkFont(size=14, weight="bold")
            ).pack(anchor="w")

            answer_entry = SecureEntry(
                question_frame,
                placeholder_text=self.lang_manager.get_string("answer_placeholder"),
                width=400,
                height=30
            )
            answer_entry.pack(anchor="w")
            self.answer_entries.append(answer_entry)

        verify_btn = ctk.CTkButton(
            main_frame,
            text=self.lang_manager.get_string("verify_button"),
            command=self.verify_answers,
            height=45,
            font=ctk.CTkFont(size=16)
        )
        verify_btn.pack(pady=20)

    def verify_answers(self):
        all_correct = True
        for i, (question, answer_hash) in enumerate(self.questions):
            answer = self.answer_entries[i].get().strip()
            if not answer:
                all_correct = False
                break

            try:
                salt_and_hash = base64.b64decode(answer_hash)
                salt = salt_and_hash[:32]
                stored_hash = salt_and_hash[32:]
                
                new_answer_hash = self.crypto_manager.generate_key_from_password(answer, salt)
                
                if not hmac.compare_digest(new_answer_hash, stored_hash):
                    all_correct = False
                    break
            except Exception as e:
                logger.error(f"Error verifying security question: {e}")
                all_correct = False
                break
        
        self.result = all_correct
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result
class SecureEntry(ctk.CTkEntry):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bind("<Control-c>", lambda e: "break")
        self.bind("<Control-x>", lambda e: "break")
        self.bind("<Control-v>", lambda e: "break")
        self.bind("<Button-3>", lambda e: "break")

        self.tooltip = None
        self.bind("<Enter>", self.show_tooltip)
        self.bind("<Leave>", self.hide_tooltip)
        self.bind("<KeyRelease>", self._on_key_release)

    def show_tooltip(self, event):
        self.tooltip = tk.Toplevel(self)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
        label = tk.Label(self.tooltip, text="Copy/Paste is disabled for this field.", background="#FFFFE0", relief="solid", borderwidth=1)
        label.pack()

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def _on_key_release(self, event):
        text = self.get()
        cleaned_text = self._remove_arabic(text)

        if text != cleaned_text:
            cursor_pos = self.index("insert")
            # Count removed characters before the cursor to adjust its position
            removed_count = len(re.findall("[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]", text[:cursor_pos]))
            
            self.delete(0, "end")
            self.insert(0, cleaned_text)
            self.icursor(max(0, cursor_pos - removed_count))

    def _remove_arabic(self, text):
        arabic_pattern = re.compile("[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]+")
        return arabic_pattern.sub("", text)

class NonArabicEntry(ctk.CTkEntry):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bind("<KeyRelease>", self._on_key_release)

    def _on_key_release(self, event):
        text = self.get()
        cleaned_text = self._remove_arabic(text)

        if text != cleaned_text:
            cursor_pos = self.index("insert")
            # Count removed characters before the cursor to adjust its position
            removed_count = len(re.findall("[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]", text[:cursor_pos]))
            
            self.delete(0, "end")
            self.insert(0, cleaned_text)
            self.icursor(max(0, cursor_pos - removed_count))

    def _remove_arabic(self, text):
        arabic_pattern = re.compile("[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]+")
        return arabic_pattern.sub("", text)

class ModernPasswordManagerGUI:
    def __init__(self):
        self.lang_manager = LanguageManager()
        self.crypto = CryptoManager()
        self.password_generator = PasswordGenerator(self.lang_manager)
        self.tfa_manager = TwoFactorAuthManager()
        self.database = None
        self.secure_file_manager = None
        self.trial_manager = None
        self.authenticated = False  # Initialize here to prevent cleanup error
        ctk.set_appearance_mode("dark")  
        self.root = ctk.CTk()
        self.root.withdraw()
        self.root.title(self.lang_manager.get_string("app_title"))
        self.root.geometry("1200x800")
        set_icon(self.root)
        
        self.show_loading_screen()

    def show_message(self, title_key: str, message_key: str, msg_type: str = "info", ask: str = None, **kwargs) -> bool:
        current_lang = self.lang_manager.language
        self.lang_manager.set_language("English")

        title = self.lang_manager.get_string(title_key)
        message = self.lang_manager.get_string(message_key, **kwargs)

        result = None
        if ask == "yesno":
            result = messagebox.askyesno(title, message)
        elif msg_type == "info":
            messagebox.showinfo(title, message)
        elif msg_type == "error":
            messagebox.showerror(title, message)
        
        self.lang_manager.set_language(current_lang)

        return result if result is not None else False

    def _initialize_app(self):
        self.authenticated = False
        self.accounts = []
        self.auth_guardian = AuthGuardian(self.secure_file_manager)
        self.settings = self.auth_guardian._settings
        self.inactivity_timer = None
        self.INACTIVITY_TIMEOUT = 2 * 60 * 1000  # 2 minutes in milliseconds
        self.load_settings()
        self.setup_ui()
        self.start_lockout_validation_timer()

    def show_welcome_dialog(self):
        welcome_window = ThemedToplevel(self.root)
        welcome_window.title("Welcome")
        welcome_window.geometry("500x350")
        welcome_window.resizable(False, False)
        welcome_window.grab_set()  # Make the window modal

        # Center the window
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (500 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (250 // 2)
        welcome_window.geometry(f"+{x}+{y}")

        main_frame = ctk.CTkFrame(welcome_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="Welcome to SecureVault Pro",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=(10, 15))

        welcome_message = (
            "It looks like this is your first time using the application.\n\n"
            "Please click the 'First Time Setup' button on the main screen  \n"
            "to create your account and secure your vault. \n\n\n"
            "If you encounter any problems, please contact the developer directly.\n\n"
            "Enjoy your time with SecureVault Pro!"
        )
        ctk.CTkLabel(
            main_frame,
            text=welcome_message,
            font=ctk.CTkFont(size=14),
            justify="left"
        ).pack(pady=10, padx=10)

        close_button = ctk.CTkButton(
            main_frame,
            text="Okay, thanks!",
            command=welcome_window.destroy,
            width=120,
            height=50
        )
        close_button.pack(pady=20)

        # Wait for the window to be closed before returning
        welcome_window.wait_window()

    def show_loading_screen(self): 
        bg_color = "#f5f5f5"      # light gray background
        accent_color = "#2b6cb0"  # deep blue
        slogan_color = "#1a202c"  # dark gray/black
        subtext_color = "#4a5568" # softer gray
        
        width, height = 550, 220   # wider for side-by-side layout
        loading_window = ThemedToplevel(self.root, fg_color=bg_color)
        loading_window.title(self.lang_manager.get_string("loading"))
        loading_window.geometry(f"{width}x{height}")
        loading_window.resizable(False, False)
        loading_window.overrideredirect(True)
        loading_window.grab_set()
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        loading_window.geometry(f"{width}x{height}+{x}+{y}")

        main_frame = ctk.CTkFrame(loading_window, fg_color=bg_color, corner_radius=0)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        main_frame.columnconfigure(0, weight=1)  # image column
        main_frame.columnconfigure(1, weight=2)  # text column

        try:
            load_icon_path = os.path.join("icons", "load.png")
            if os.path.exists(load_icon_path):
                load_image = Image.open(load_icon_path)
                load_icon = ctk.CTkImage(light_image=load_image, size=(200, 150))  
                icon_label = ctk.CTkLabel(main_frame, image=load_icon, text="", fg_color=bg_color)
                icon_label.grid(row=0, column=0, rowspan=5, padx=(10, 20), pady=10, sticky="n")
        except Exception as e:
            logger.warning(f"Could not display loading icon: {e}")

        ctk.CTkLabel(
            main_frame,
            text=self.lang_manager.get_string("app_title"),
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=accent_color
        ).grid(row=0, column=1, pady=(5, 3), sticky="w")

        ctk.CTkLabel(
            main_frame,
            text=self.lang_manager.get_string("app_slogan"),
            font=ctk.CTkFont(size=11),
            text_color=slogan_color
        ).grid(row=1, column=1, pady=(0, 15), sticky="w")

        progress_bar = ctk.CTkProgressBar(
            main_frame,
            width=300,
            height=12,
            progress_color=accent_color,
            corner_radius=10
        )
        progress_bar.grid(row=2, column=1, pady=10, sticky="w")
        progress_bar.set(0)

        status_label = ctk.CTkLabel(
            main_frame,
            text=self.lang_manager.get_string("initializing"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=accent_color
        )
        status_label.grid(row=3, column=1, pady=(15, 5), sticky="w")

        details_label = ctk.CTkLabel(
            main_frame,
            text=self.lang_manager.get_string("starting_engine"),
            font=ctk.CTkFont(size=10),
            text_color=subtext_color
        )
        details_label.grid(row=4, column=1, sticky="w")

        def update_loading(step):
            if step == 1:
                progress_bar.set(0.25)
                status_label.configure(text=self.lang_manager.get_string("loading_components"))
                details_label.configure(text=self.lang_manager.get_string("loading_gui"))
                loading_window.after(700, lambda: update_loading(2))
            elif step == 2:
                progress_bar.set(0.55)
                status_label.configure(text=self.lang_manager.get_string("verifying_security"))
                details_label.configure(text=self.lang_manager.get_string("checking_vault"))
                loading_window.after(1000, lambda: update_loading(3))
            elif step == 3:
                progress_bar.set(0.85)
                status_label.configure(text=self.lang_manager.get_string("preparing_workspace"))
                details_label.configure(text=self.lang_manager.get_string("setting_up_main_interface"))
                loading_window.after(600, lambda: update_loading(4))
            elif step == 4:
                progress_bar.set(1.0)
                status_label.configure(text=self.lang_manager.get_string("done"))
                details_label.configure(text=self.lang_manager.get_string("launching_application"))
                loading_window.after(600, lambda: finish_loading())

        def finish_loading():
            loading_window.destroy()
            self.root.deiconify()

            # Initialize SFM early for trial manager
            self._setup_secure_file_manager()
            
            self.trial_manager = TrialManager(self.root, self.secure_file_manager, restart_callback=self.restart_program)
            if self.trial_manager.status in ["EXPIRED", "TAMPERED"]:
                if not self.trial_manager.show_trial_expired_dialog():
                    self.root.quit()
                    return

            self._initialize_app()

        loading_window.after(200, lambda: update_loading(1))

    def _setup_secure_file_manager(self):
        try:
            logger.info("Initializing secure file management system...")
            self.secure_file_manager = SecureFileManager()
            logger.info("Secure file manager initialized")
        except Exception as e:
            logger.error(f"Failed to initialize secure file manager: {e}")
            self.secure_file_manager = None

    def load_settings(self):
        # Most settings are now managed by AuthGuardian via SecureFileManager.
        # This method is for settings not related to auth state.
        default_settings = {
            'theme': 'dark',
            'font_size': 12,
            'secure_storage_enabled': True,
            'tfa_secret': None,
            'tutorial_completed': False,
            'language': 'English',
            'last_login_timestamp': 0.0,
            'consecutive_logins': 0
        }
        
        # The AuthGuardian already loaded the settings. We just ensure defaults.
        self.settings = {**default_settings, **self.settings}
        
        if 'language' in self.settings:
            self.lang_manager.set_language(self.settings['language'])

    def save_settings_to_file(self):
        # This method now just saves the current state of self.settings.
        # AuthGuardian is responsible for saving its own state.
        if self.secure_file_manager:
            try:
                self.secure_file_manager.write_settings(self.settings)
            except Exception as e:
                logger.error(f"Error saving settings: {e}")
        else:
            # Fallback for when secure manager isn't available
            try:
                with open("vault_settings.json", 'w') as f:
                    json.dump(self.settings, f, indent=4)
            except Exception as e:
                logger.error(f"Error saving settings to fallback file: {e}")

    def log_security_event(self, event_type: str, details: str):
        logger.info(f"SECURITY EVENT: {event_type} - {details}")

    def start_lockout_validation_timer(self):
        def validate_periodically():
            if self.auth_guardian.is_locked_out():
                # The UI update is handled by update_lockout_countdown
                self.root.after(1000, validate_periodically)
            else:
                # Check less frequently when not locked out
                self.root.after(30000, validate_periodically)
        self.root.after(1000, validate_periodically)

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

        if not self.is_vault_initialized():
            self.root.after(100, self.show_welcome_dialog)

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
            text="🔒 " + self.lang_manager.get_string("app_title"),
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(30, 20), padx=40)
        subtitle = ctk.CTkLabel(
            login_card,
            text=self.lang_manager.get_string("app_slogan"),
            font=ctk.CTkFont(size=16),
            text_color="#888888"
        )
        subtitle.pack(pady=(0, 30), padx=40)
        password_frame = ctk.CTkFrame(login_card, fg_color="transparent")
        password_frame.pack(pady=15, padx=40)
        self.master_password_entry = SecureEntry(
            password_frame,
            placeholder_text=self.lang_manager.get_string("enter_master_password"),
            show="*",
            width=300,
            height=45,
            font=ctk.CTkFont(size=16)
        )
        self.master_password_entry.pack(side="left", padx=(0, 5))
        def toggle_password_visibility():
            if self.master_password_entry.cget("show") == "*":
                self.master_password_entry.configure(show="")
                toggle_btn.configure(text="🙈")
            else:
                self.master_password_entry.configure(show="*")
                toggle_btn.configure(text="👁️")
        toggle_btn = ctk.CTkButton(
            password_frame,
            text="👁️",
            width=45,
            height=45,
            command=toggle_password_visibility
        )
        toggle_btn.pack(side="left")
        button_frame = ctk.CTkFrame(login_card, fg_color="transparent")
        button_frame.pack(pady=30, padx=40)
        self.login_btn = ctk.CTkButton(
            button_frame, 
            text=self.lang_manager.get_string("login"),
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
            text=self.lang_manager.get_string("first_time_setup"),
            command=self.show_setup_wizard,
            width=250,
            height=55,
            font=ctk.CTkFont(size=18),
            corner_radius=12,
            fg_color="#1E9E7A",
            hover_color="#187A61",
            state="disabled" if self.is_vault_initialized() else "normal"
        )
        self.setup_btn.pack(pady=8)
        if self.auth_guardian.is_locked_out():
            self.update_lockout_countdown()
        self.update_login_button_states()

    def authenticate_user(self):
        if self.enforce_lockout(show_error=True):
            return

        master_password = self.master_password_entry.get().strip()
        if not master_password:
            self.show_message("error", "enter_master_password_error", msg_type="error")
            return

        if not self.is_vault_initialized():
            self.show_message("error", "vault_not_initialized_error", msg_type="error")
            return
        
        if self.secure_file_manager:
            legacy_setup = SecureVaultSetup(self.secure_file_manager)
            if legacy_setup.has_legacy_files():
                logger.info("Legacy files detected, starting migration...")
                if not legacy_setup.migrate_legacy_files(master_password):
                    self.show_message("migration_error_title", "migration_error_body", msg_type="error")
                    return
        
        if self.secure_file_manager:
            if not self.secure_file_manager.initialize_encryption(master_password):
                self.show_message("error", "secure_storage_init_error", msg_type="error")
                return
            logger.info("Loading files from secure storage...")
            if not self.secure_file_manager.load_files_to_temp():
                diagnostic_report = self.diagnose_secure_storage_issues()
                error_msg = self.lang_manager.get_string("secure_storage_load_error") + "\n\n"
                error_msg += self.lang_manager.get_string("diagnostic_report") + "\n" + diagnostic_report
                self.show_secure_storage_error_dialog(error_msg)
                return

        db_path = "manageyouraccount"
        self.database = DatabaseManager(db_path, self.crypto, self.secure_file_manager)
        auth_success = self.database.authenticate(master_password)
        self.auth_guardian.record_login_attempt(success=auth_success)

        if auth_success:
            if self.settings.get('tfa_secret'):
                self.prompt_for_tfa()
            else:
                self.authenticated = True
                now = datetime.now().timestamp()
                last_login = self.settings.get('last_login_timestamp', 0.0)
                consecutive_logins = self.settings.get('consecutive_logins', 0)
                if (now - last_login) > 3600:
                    consecutive_logins = 1
                else:
                    consecutive_logins += 1
                self.settings['last_login_timestamp'] = now
                self.settings['consecutive_logins'] = consecutive_logins
                self.save_settings_to_file()
                notification_thread = threading.Thread(target=start_notification_loop, daemon=True)
                notification_thread.start()
                self.show_main_interface()
        else:
            if hasattr(self.database, 'last_integrity_error') and self.database.last_integrity_error:
                result = self.show_message("integrity_error_title", "integrity_error_body", ask="yesno")
                if result:
                    try:
                        if self.database.force_integrity_reset():
                            self.show_message("success", "integrity_fix_success")
                            self.database.last_integrity_error = False
                        else:
                            self.show_message("error", "integrity_fix_fail", msg_type="error")
                    except Exception as e:
                        self.show_message("error", "integrity_fix_error", msg_type="error", error=str(e))
                return

            if self.auth_guardian.is_locked_out():
                self.trial_manager.show_lockout_dialog(self.auth_guardian.get_remaining_lockout_time())
                self.root.quit()
            else:
                remaining_attempts = self.auth_guardian.MAX_ATTEMPTS_BEFORE_LOCKOUT - self.auth_guardian.failed_attempts
                self.show_message("error", "invalid_master_password_error", msg_type="error", attempts=remaining_attempts)
                if self.auth_guardian.is_locked_out(): # Re-check after message
                    self.trial_manager.show_lockout_dialog(self.auth_guardian.get_remaining_lockout_time())
                    self.root.quit()

    def disable_login_button_with_countdown(self):
        if hasattr(self, 'login_btn'):
            self.login_btn.configure(state="disabled")
            self.update_lockout_countdown()

    def update_lockout_countdown(self):
        if self.auth_guardian.is_locked_out():
            remaining_time = self.auth_guardian.get_remaining_lockout_time()
            minutes, seconds = divmod(remaining_time, 60)
            
            lockout_text = f"🔒 Locked ({minutes:02d}:{seconds:02d})"
            if hasattr(self, 'login_btn'):
                self.login_btn.configure(text=lockout_text, state="disabled")
            if hasattr(self, 'lockout_countdown_label'):
                self.lockout_countdown_label.configure(text=f"Time remaining: {minutes:02d}:{seconds:02d}")
            
            self.root.after(1000, self.update_lockout_countdown)
        else:
            if hasattr(self, 'lockout_countdown_label'): # If we were on the lockout screen
                self.show_login_screen()
            elif hasattr(self, 'login_btn'):
                self.login_btn.configure(text="🔓 Login", state="normal")

    def update_login_button_states(self):
        if hasattr(self, 'login_btn') and hasattr(self, 'setup_btn'):
            is_init = self.is_vault_initialized()
            self.login_btn.configure(state="normal" if is_init else "disabled")
            self.setup_btn.configure(state="disabled" if is_init else "normal")

    def verify_master_password_dialog(self):
        if self.enforce_lockout(show_error=True):
            return False

        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("verify_master_password_title"))
        dialog.geometry("400x230")
        dialog.grab_set()
        dialog.resizable(False, False)
        result = {"password": None, "confirmed": False}
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("auth_required"),
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        password_entry = SecureEntry(main_frame, width=300, height=40, show="*",
                                    placeholder_text=self.lang_manager.get_string("master_password_placeholder"))
        password_entry.pack(pady=15)
        password_entry.focus()
        
        def on_ok():
            result["password"] = password_entry.get()
            result["confirmed"] = True
            dialog.destroy()
        
        def on_cancel():
            result["confirmed"] = False
            dialog.destroy()
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=10)
        
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("cancel_button"), command=on_cancel, width=100).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("ok_button"), command=on_ok, width=100).pack(side="right", padx=10)
        
        dialog.wait_window()
        
        if not result["confirmed"] or not result["password"]:
            return False
        
        try:
            temp_db = DatabaseManager(self.database.db_path, self.crypto, self.secure_file_manager)
            auth_success = temp_db.authenticate(result["password"])
            self.auth_guardian.record_login_attempt(auth_success)
            if auth_success:
                return True
            else:
                self.show_message("error", "invalid_master_password", msg_type="error")
                if self.auth_guardian.is_locked_out():
                    self.lock_vault() # Force lock and show screen
                return False
        except Exception:
            self.show_message("error", "auth_failed", msg_type="error")
            return False

    def show_setup_wizard(self):
        if self.is_vault_initialized():
            self.show_message("setup_wizard_title", "vault_not_initialized_error")
            return
        
        self.update_login_button_states()
        self.setup_window = ThemedToplevel(self.root)
        self.setup_window.title(self.lang_manager.get_string("setup_wizard_title"))
        
        width, height = 700, 500
        x = (self.setup_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.setup_window.winfo_screenheight() // 2) - (height // 2)
        self.setup_window.geometry(f"{width}x{height}+{x}+{y}")

        self.setup_window.resizable(0, 0)
        self.setup_window.grab_set()

        self.wizard_step = 0
        self.wizard_frames = []

        # Step 1: Master Password
        step1_frame = ctk.CTkFrame(self.setup_window)
        step1_frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.wizard_frames.append(step1_frame)
        
        ctk.CTkLabel(
            step1_frame, 
            text=self.lang_manager.get_string("create_master_password_title"), 
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=20)
        
        self.setup_full_name_entry = NonArabicEntry(
            step1_frame, 
            placeholder_text="Full Name Ex. Hamza Saadi", 
            width=300, height=40
        )
        self.setup_full_name_entry.pack(pady=10)

        self.setup_email_entry = NonArabicEntry(
            step1_frame, 
            placeholder_text=self.lang_manager.get_string("email_placeholder"), 
            width=300, height=40
        )
        self.setup_email_entry.pack(pady=10)
        
        self.setup_master_password = SecureEntry(
            step1_frame, 
            placeholder_text=self.lang_manager.get_string("master_password_placeholder"),
            show="*", width=300, height=40
        )
        self.setup_master_password.pack(pady=10)

        self.setup_confirm_password = SecureEntry(
            step1_frame, 
            placeholder_text=self.lang_manager.get_string("confirm_password_placeholder"),
            show="*", width=300, height=40
        )
        self.setup_confirm_password.pack(pady=10)

        self.strength_label = ctk.CTkLabel(step1_frame, text="")
        self.strength_label.pack(pady=10)
        self.setup_master_password.bind("<KeyRelease>", self.update_password_strength)

        # Step 2: Security Questions
        step2_frame = ctk.CTkFrame(self.setup_window)
        # Don't pack it yet, it will be shown later
        self.wizard_frames.append(step2_frame)

        ctk.CTkLabel(
            step2_frame,
            text=self.lang_manager.get_string("security_questions_title"),
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=20)

        ctk.CTkLabel(
            step2_frame,
            text=self.lang_manager.get_string("security_questions_instruction"),
            font=ctk.CTkFont(size=14)
        ).pack(pady=10)

        self.security_questions = []
        self.security_questions_vars = []
        self.security_questions_entries = []

        questions = [
            self.lang_manager.get_string("security_question_1"),
            self.lang_manager.get_string("security_question_2"),
            self.lang_manager.get_string("security_question_3"),
            self.lang_manager.get_string("security_question_4"),
            self.lang_manager.get_string("security_question_5"),
        ]

        for i, question_text in enumerate(questions):
            var = tk.BooleanVar()
            self.security_questions_vars.append(var)
            
            question_frame = ctk.CTkFrame(step2_frame, fg_color="transparent")
            question_frame.pack(fill="x", padx=20, pady=5)

            chk = ctk.CTkCheckBox(question_frame, text=question_text, variable=var)
            chk.pack(side="left")

            entry = SecureEntry(
                question_frame,
                placeholder_text=self.lang_manager.get_string("answer_placeholder"),
                width=300,
                height=30
            )
            entry.pack(side="right")
            self.security_questions_entries.append(entry)
            self.security_questions.append({"question": question_text, "var": var, "entry": entry})

        # Navigation buttons
        self.navigation_frame = ctk.CTkFrame(self.setup_window)
        self.navigation_frame.pack(fill="x", padx=20, pady=20)

        self.back_btn = ctk.CTkButton(
            self.navigation_frame,
            text="Back",
            command=self.prev_step,
            height=45, font=ctk.CTkFont(size=16)
        )
        self.back_btn.pack(side="left", padx=10)

        self.next_btn = ctk.CTkButton(
            self.navigation_frame,
            text="Next",
            command=self.next_step,
            height=45, font=ctk.CTkFont(size=16)
        )
        self.next_btn.pack(side="right", padx=10)

        self.finish_btn = ctk.CTkButton(
            self.navigation_frame,
            text=self.lang_manager.get_string("complete_setup_button"),
            command=lambda: self.complete_setup(self.setup_window),
            height=45, font=ctk.CTkFont(size=16)
        )
        # Don't pack finish_btn yet

        self.show_step()

    def show_step(self):
        for frame in self.wizard_frames:
            frame.pack_forget()
        
        self.wizard_frames[self.wizard_step].pack(fill="both", expand=True, padx=20, pady=20)

        if self.wizard_step == 0:
            self.back_btn.pack_forget()
            self.next_btn.pack(side="right", padx=10)
            self.finish_btn.pack_forget()
        elif self.wizard_step == len(self.wizard_frames) - 1:
            self.back_btn.pack(side="left", padx=10)
            self.next_btn.pack_forget()
            self.finish_btn.pack(side="right", padx=10)
        else:
            self.back_btn.pack(side="left", padx=10)
            self.next_btn.pack(side="right", padx=10)
            self.finish_btn.pack_forget()

    def next_step(self):
        validation_passed = True
        if self.wizard_step == 0:
            master_password = self.setup_master_password.get()
            confirm_password = self.setup_confirm_password.get()
            full_name = self.setup_full_name_entry.get().strip()
            email = self.setup_email_entry.get().strip()

            if not full_name:
                self.show_message("error", "Full name is required", msg_type="error")
                validation_passed = False
            elif not email:
                self.show_message("error", "email_required_error", msg_type="error")
                validation_passed = False
            elif not master_password or master_password != confirm_password:
                self.show_message("error", "passwords_dont_match", msg_type="error")
                validation_passed = False
            elif len(master_password) < 1:
                self.show_message("error", "password_too_short", msg_type="error")
                validation_passed = False

        if validation_passed and self.wizard_step < len(self.wizard_frames) - 1:
            self.wizard_step += 1
            self.show_step()

    def prev_step(self):
        if self.wizard_step > 0:
            self.wizard_step -= 1
            self.show_step()

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
                text=self.lang_manager.get_string("password_strength_template", length=len(password), strength=strength, score=score), 
                text_color=color
            )

    def _generate_welcome_message(self, count: int = 1) -> str:
        """
        Return `count` unique security tips (default 1). Tips are full sentences and
        prefixed with 'Security Tip:' for consistent UI display.
        """
        safety_tips: List[str] = [
            "Security Tip: Use a unique, strong password for every account and avoid reusing passwords.",
            "Security Tip: Enable two-factor authentication (2FA) or multi-factor authentication (MFA) on all critical accounts.",
            "Security Tip: Beware of phishing emails asking for credentials; verify the sender and never enter credentials from a link.",
            "Security Tip: Regularly review and tighten your account security and privacy settings.",
            "Security Tip: Prefer long passphrases made of multiple unrelated words rather than short, complex passwords.",
            "Security Tip: Never share your primary or master password with anyone or store it in plain text.",
            "Security Tip: Use a reputable password manager to generate and securely store passwords and secrets.",
            "Security Tip: Avoid using public Wi-Fi for sensitive transactions; if you must, use a trusted VPN.",
            "Security Tip: Keep your operating system, applications, and firmware updated to patch known vulnerabilities.",
            "Security Tip: Hover over links to inspect their real destination before clicking and verify expected domains.",
            "Security Tip: Do not use easily guessed personal information (birthdays, names) in passwords.",
            "Security Tip: Secure your home Wi-Fi with a strong password and the strongest available encryption (WPA3 where supported).",
            "Security Tip: Be cautious of unexpected or unsolicited messages, even from known contacts — accounts can be compromised.",
            "Security Tip: Enable automatic updates for your OS and security software where feasible.",
            "Security Tip: Lock devices when not in use and require a PIN, password, biometric, or smart lock to resume.",
            "Security Tip: Use different passwords for personal, work, and financial accounts to limit cross-account compromise.",
            "Security Tip: Verify presence of HTTPS and a valid certificate before entering sensitive information on websites.",
            "Security Tip: Limit what you share on social media; information there can be used for social engineering attacks.",
            "Security Tip: Back up important data regularly to multiple locations (offline and cloud) and test restore procedures.",
            "Security Tip: Use a firewall to block unwanted incoming traffic and monitor for suspicious connections.",
            "Security Tip: Be skeptical of offers that seem too good to be true — they are often scams or phishing attempts.",
            "Security Tip: Cover your webcam when not in use and disable or manage camera access for apps.",
            "Security Tip: Review app permissions before installation and only grant permissions that are necessary.",
            "Security Tip: Treat urgent money or information requests skeptically — verify by calling the person through a known-good number.",
            "Security Tip: Use a privacy screen on laptops in public places to reduce shoulder-surfing risk.",
            "Security Tip: Shred physical documents that contain sensitive information before disposal.",
            "Security Tip: Monitor bank and credit card statements frequently and enable alerts for suspicious activity.",
            "Security Tip: Never insert unknown USB drives into your computer — they can carry malware or exfiltrate data.",
            "Security Tip: Use passphrases (4+ random words) which are easier to remember and harder to brute-force than short passwords.",
            "Security Tip: Periodically search for your personal data online to understand and reduce your digital footprint.",
            "Security Tip: Disable Bluetooth and location services when they are not needed to limit tracking and attack surface.",
            "Security Tip: Sign out from websites and shared devices when finished to prevent unauthorized access.",
            "Security Tip: Keep a separate email address for shopping and subscriptions to reduce spam to your primary inbox.",
            "Security Tip: Verify the source before scanning QR codes and avoid scanning codes from unknown or suspicious sources.",
            "Security Tip: Teach family members, especially children and elderly relatives, about basic online safety and scams.",
            "Security Tip: Avoid oversharing on dating apps and verify identities before meeting in person.",
            "Security Tip: Change default credentials on IoT devices and keep their firmware up to date.",
            "Security Tip: Block and delete suspicious text messages instead of replying, and report phishing SMS to your carrier.",
            "Security Tip: Prefer credit cards over debit cards for online purchases because of stronger consumer protections.",
            "Security Tip: Wipe devices securely (factory reset + crypto erase) before disposal or resale to remove personal data.",
            "Security Tip: Be mindful of what you post in public forums and remember that anything public can be scraped.",
            "Security Tip: Inspect ATMs and gas pumps for card skimmers and avoid using compromised-looking machines.",
            "Security Tip: Never trust unsolicited tech support calls; contact vendors using official channels if you suspect an issue.",
            "Security Tip: Use virtual or single-use credit card numbers for trials and untrusted merchants when available.",
            "Security Tip: Check your video-call background and be careful sharing sensitive information during remote meetings.",
            "Security Tip: Trust your instincts — if something feels off, pause and validate before proceeding.",
            # Additional, more advanced / operational tips:
            "Security Tip: Use hardware security keys (FIDO2/WebAuthn) where supported for stronger phishing-resistant MFA.",
            "Security Tip: Use app-specific or service-specific passwords for applications that do not support modern MFA.",
            "Security Tip: Monitor breach notification services and consider dark-web monitoring to know if credentials leak.",
            "Security Tip: Use DNS filtering or secure DNS (DoH/DoT) to reduce exposure to malicious domains.",
            "Security Tip: Configure account recovery options (alternate email, phone) and store them securely.",
            "Security Tip: Limit the number of people with administrative privileges and follow the principle of least privilege.",
            "Security Tip: Segment your network (guest vs. trusted) to reduce lateral movement from compromised devices.",
            "Security Tip: Disable unused services and close unnecessary ports on networked devices to reduce attack surface.",
            "Security Tip: Use full-disk encryption (e.g., BitLocker, FileVault) to protect data at rest on lost or stolen devices.",
            "Security Tip: Securely store MFA backup codes or recovery keys offline (paper or secure hardware) in a safe place.",
            "Security Tip: Regularly audit third-party app access to your accounts and revoke access that is no longer required.",
            "Security Tip: Be cautious installing browser extensions — only install trusted extensions and review their permissions.",
            "Security Tip: Maintain a separate non-admin account for daily work and reserve an admin account for elevated tasks.",
            "Security Tip: Keep device firmware (router, NAS, IoT) current and change default management ports and credentials.",
            "Security Tip: Verify downloads by checking cryptographic checksums or digital signatures when available.",
            "Security Tip: Use DMARC, DKIM, and SPF on your email domain to reduce email spoofing and phishing impact.",
            "Security Tip: Implement immutable or offline backups to protect against ransomware and ensure recoverability.",
            "Security Tip: Use passkeys (platform-backed credentials) where supported to simplify authentication and reduce phishing.",
            "Security Tip: Rotate API keys, secrets, and certificates periodically and remove unused credentials.",
            "Security Tip: Store highly sensitive data encrypted using strong, vetted encryption libraries and manage keys securely.",
            "Security Tip: Use secure coding practices and regularly run static and dynamic analysis on production code.",
            "Security Tip: Avoid clicking on shortened URLs without previewing them and use URL expanders when unsure.",
            "Security Tip: Use content/ad blockers or safe-browsing extensions to reduce risk from malvertising.",
            "Security Tip: Use SIM/PIN protection on mobile devices and enable carrier-level protections where offered.",
            "Security Tip: Be wary of public/unknown charging stations (risk of juice jacking); use your own cable or a power-only adapter.",
            "Security Tip: Keep an incident response plan and contacts ready so you can act quickly when a breach is suspected.",
            "Security Tip: Maintain and review logs for suspicious activity and keep them stored securely off the main system.",
            "Security Tip: Use network segmentation and VLANs for critical infrastructure to limit potential wide-spread compromise.",
            "Security Tip: Use hardware-backed secure enclaves (TPM/SE) and enable Secure Boot where available.",
            "Security Tip: Use certificate pinning or strict TLS validation in apps that handle sensitive data.",
            "Security Tip: Test your backups regularly by performing full restores to ensure integrity and process accuracy.",
            "Security Tip: Avoid mixing personal devices with corporate systems for privileged or sensitive tasks.",
            "Security Tip: Consider endpoint detection and response (EDR) for business-critical systems to improve detection.",
            "Security Tip: Establish a change control process to review and approve configuration changes to infrastructure.",
            "Security Tip: Limit use of browser autofill for sensitive fields and require re-authentication for high-risk actions.",
            "Security Tip: Remove default or sample content from web applications and harden frameworks before deployment.",
            "Security Tip: Use tokenization or vaulting for payment data and sensitive PII to reduce compliance scope.",
            "Security Tip: Maintain a minimal public exposure profile — limit exposed services, APIs, and ports to what is necessary."
        ]

        # Safeguard count
        try:
            total = len(safety_tips)
            if count < 1:
                count = 1
            if count > total:
                count = total

            if count == 1:
                # choose a single random tip
                tip = secrets.choice(safety_tips)
                return tip
            else:
                # return `count` unique tips
                chosen = secrets.SystemRandom().sample(safety_tips, count)
                # format as numbered list for clarity in UI
                lines = [f"{idx}. {t}" for idx, t in enumerate(chosen, start=1)]
                return "\n".join(lines)
        except Exception as e:
            # graceful fallback — keep a simple message so UI doesn't break
            try:
                logger.error(f"Failed to generate welcome message: {e}")
            except Exception:
                pass
            return "Security Tip: Keep your software updated and use strong, unique passwords for each account."
    
    def complete_setup(self, setup_window):
        master_password = self.setup_master_password.get()
        confirm_password = self.setup_confirm_password.get()
        full_name = self.setup_full_name_entry.get().strip()
        email = self.setup_email_entry.get().strip()

        if not full_name:
            self.show_message("error", "Full name is required", msg_type="error")
            return
        if not email:
            self.show_message("error", "email_required_error", msg_type="error")
            return
        if not master_password or master_password != confirm_password:
            self.show_message("error", "passwords_dont_match", msg_type="error")
            return
        if len(master_password) < 1:
            self.show_message("error", "password_too_short", msg_type="error")
            return

        selected_questions = []
        for item in self.security_questions:
            if item["var"].get():
                answer = item["entry"].get().strip()
                if not answer:
                    self.show_message("security_questions_error_title", "security_questions_error_message", msg_type="error")
                    return
                selected_questions.append((item["question"], answer))

        if len(selected_questions) != 3:
            self.show_message("security_questions_error_title", "security_questions_error_message", msg_type="error")
            return

        try:
            if self.secure_file_manager:
                if not self.secure_file_manager.initialize_encryption(master_password):
                    self.show_message("error", "secure_storage_init_error", msg_type="error")
                    return
                if not self.secure_file_manager.initialize_vault_files():
                    self.show_message("error", "create_vault_files_error", msg_type="error")
                    return
            
            db_path = "manageyouraccount"
            self.database = DatabaseManager(db_path, self.crypto, self.secure_file_manager)
            self.database.initialize_database(master_password, email, full_name)

            hashed_questions = []
            for question, answer in selected_questions:
                salt = self.crypto.generate_salt()
                answer_hash = self.crypto.generate_key_from_password(answer, salt)
                hashed_questions.append((question, base64.b64encode(salt + answer_hash).decode('utf-8')))
            
            self.database.save_security_questions(hashed_questions)
            
            if self.secure_file_manager:
                self.secure_file_manager.sync_all_files()
            self.show_message("success", "setup_success_message")
            
            setup_window.destroy()
            self.show_login_screen()
        except Exception as e:
            self.show_message("error", "setup_failed_message", msg_type="error", error=str(e))

    def show_main_interface(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        self.root.state('zoomed')
        self.root.resizable(True, True)
        self.root.minsize(800, 600)

        self.reset_inactivity_timer()
        self.root.bind("<KeyPress>", self.reset_inactivity_timer)
        self.root.bind("<Motion>", self.reset_inactivity_timer)
        self.root.bind("<Button-1>", self.reset_inactivity_timer)

        if not self.settings.get('tutorial_completed', False):
            tutorial = TutorialManager(self.root, self.lang_manager)
            tutorial.show_tutorial_window()
            self.settings['tutorial_completed'] = True
            self.save_settings_to_file()

        toolbar = ctk.CTkFrame(self.main_frame, height=70)
        toolbar.pack(fill="x", padx=10, pady=10)
        toolbar.pack_propagate(False)
        
        if self.trial_manager and self.trial_manager.is_trial_active:
            remaining_minutes = int(self.trial_manager.minutes_remaining)

            def _english_time(n, unit):
                if unit == "day":
                    return f"{n} day" if n == 1 else f"{n} days"
                if unit == "hour":
                    return f"{n} hour" if n == 1 else f"{n} hours"
                # minutes
                return f"{n} minute" if n == 1 else f"{n} minutes"

            if remaining_minutes >= 24 * 60:
                remaining_days = remaining_minutes // (24 * 60)
                time_text = _english_time(remaining_days, "day")
            elif remaining_minutes >= 60:
                remaining_hours = remaining_minutes // 60
                time_text = _english_time(remaining_hours, "hour")
            else:
                time_text = _english_time(remaining_minutes, "minute")

            # UI: bold primary line + subdued secondary line
            trial_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
            trial_frame.pack(side="left", padx=20, pady=8)

            primary_label = ctk.CTkLabel(
                trial_frame,
                text=f"⏳ Trial — {time_text} remaining",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#FF7A18",  # warm orange to attract attention
                anchor="w",
                justify="left"
            )
            primary_label.pack(anchor="w")

            secondary_label = ctk.CTkLabel(
                trial_frame,
                text="When the trial ends, you'll need to activate the full version to continue.",
                font=ctk.CTkFont(size=11),
                text_color="#6B7280",  # soft gray for secondary info
                anchor="w",
                justify="left"
            )
            secondary_label.pack(anchor="w", pady=(4, 0))
        
        left_toolbar_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        left_toolbar_frame.pack(side="left", fill="y", padx=25, pady=10)

        ctk.CTkLabel(
            left_toolbar_frame,
            text=self.lang_manager.get_string("main_toolbar_title"),
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w")
        
        welcome_message = self._generate_welcome_message()
        ctk.CTkLabel(
            left_toolbar_frame,
            text=welcome_message,
            font=ctk.CTkFont(size=12),
            justify="left",
            anchor="w"
        ).pack(anchor="w", pady=(5, 0))
        
        ctk.CTkButton(
            toolbar, 
            text=self.lang_manager.get_string("logout"), 
            width=100, 
            height=55,
            image=logout,
            compound="left",  # icon on the left, text on the right
            command=self.lock_vault,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)
        
        ctk.CTkButton(
            toolbar, 
            text=self.lang_manager.get_string("settings"), 
            width=120, 
            height=55,
            image=settings,
            compound="left",  # icon on the left, text on the right
            command=self.show_settings,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)

        ctk.CTkButton(
            toolbar,
            text=self.lang_manager.get_string("about"),
            width=120,
            height=55,
            image=info,
            compound="left",  # icon on the left, text on the right
            command=self.show_about_dialog,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)

        # Determine state for backup/restore buttons based on trial status
        backup_restore_state = "normal"
        if self.trial_manager and self.trial_manager.status == 'TRIAL':
            backup_restore_state = "disabled"

        ctk.CTkButton(
            toolbar,
            text=self.lang_manager.get_string("backup"),
            width=120,
            height=55,
            image=save,
            compound="left",
            command=self.show_backup_dialog,
            font=ctk.CTkFont(size=18),
            state=backup_restore_state
        ).pack(side="right", padx=10, pady=8)

        ctk.CTkButton(
            toolbar,
            text=self.lang_manager.get_string("restore_old_backup"),
            width=160,
            height=55,
            image=restore_icon,
            compound="left",
            command=self.show_restore_dialog,
            font=ctk.CTkFont(size=16),
            state=backup_restore_state
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
            self.show_message("error", "database_not_available_error", msg_type="error")
            return

        backup_folder = os.path.join(os.getcwd(), "backups")
        os.makedirs(backup_folder, exist_ok=True)
        backups = sorted(glob.glob(os.path.join(backup_folder, "*.svbk")), reverse=True)

        win = tk.Toplevel(self.root)
        set_icon(win)
        win.title(self.lang_manager.get_string("restore_dialog_title"))
        win.geometry("820x480")
        win.resizable(True, True)

        top_frame = tk.Frame(win)
        top_frame.pack(fill="x", padx=12, pady=(12,6))

        tk.Label(top_frame, text=self.lang_manager.get_string("available_backups_label"), anchor="w", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")

        info_label = tk.Label(top_frame, text=self.lang_manager.get_string("select_backup_details"), anchor="w", justify="left")
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

        preview_lbl = tk.Label(win, text=self.lang_manager.get_string("preview_manifest_label"), anchor="w")
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
                info_label.config(text=self.lang_manager.get_string("select_backup_details"))
                return
            idx = sel[0]
            path = backups[idx]
            try:
                size = os.path.getsize(path)
                mtime = datetime.utcfromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%SZ")
                info_text = self.lang_manager.get_string("backup_file_details_template", filename=os.path.basename(path), path=path, size=size, mtime=mtime)
                info_label.config(text=info_text)
            except Exception as e:
                info_label.config(text=self.lang_manager.get_string("error_reading_file_info", e=e))
        
        def browse_for_backup():
            filepath = filedialog.askopenfilename(
                title=self.lang_manager.get_string("select_backup_file_title"),
                filetypes=[(self.lang_manager.get_string("secure_vault_backups_filetype"), "*.svbk"), (self.lang_manager.get_string("all_files_filetype"), "*.*")]
            )
            if filepath:
                # Always add to the top of the list, even if not in backups folder
                if filepath not in backups:
                    backups.insert(0, filepath)
                    listbox.insert(0, self.lang_manager.get_string("external_backup_label", index=len(backups), filename=os.path.basename(filepath)))
                else:
                    idx = backups.index(filepath)
                    listbox.selection_clear(0, "end")
                    listbox.selection_set(idx)
                # Select the newly added file
                listbox.selection_clear(0, "end")
                listbox.selection_set(0)
                on_selection()

        listbox.bind("<<ListboxSelect>>", on_selection)
        on_selection()

        def preview_contents():
            sel = listbox.curselection()
            if not sel:
                self.show_message("no_selection_error", "select_backup_to_preview_error", msg_type="error")
                return
            idx = sel[0]
            backup_path = backups[idx]

            code = simpledialog.askstring(self.lang_manager.get_string("backup_code_prompt_preview"), self.lang_manager.get_string("backup_code_prompt_preview"), parent=win, show="*")
            if code is None:
                return

            status_var.set(self.lang_manager.get_string("previewing_backup_status"))
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
                    self.show_message("preview_failed_error", "preview_failed_error", msg_type="error", be=be)
                    return
                except Exception as e:
                    self.show_message("preview_failed_error", "unexpected_preview_error", msg_type="error", e=e)
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
                        preview_text.insert("1.0", self.lang_manager.get_string("failed_to_read_manifest", e=e, files="\n".join(os.path.basename(p) for p in restored)))
                else:
                    preview_text.insert("1.0", self.lang_manager.get_string("no_manifest_found", files="\n".join(os.path.basename(p) for p in restored)))

                preview_text.configure(state="disabled")
            finally:
                try:
                    shutil.rmtree(tempdir)
                except Exception:
                    pass
                status_var.set(self.lang_manager.get_string("preview_complete_status"))

        def perform_restore():
            sel = listbox.curselection()
            if not sel:
                self.show_message("no_selection_error", "select_backup_to_restore_error", msg_type="error")
                return
            idx = sel[0]
            backup_path = backups[idx]

            code = simpledialog.askstring(self.lang_manager.get_string("backup_code_prompt_restore"), self.lang_manager.get_string("backup_code_prompt_restore"), parent=win, show="*")
            if code is None:
                return

            proceed = self.show_message("confirm_restore_title", "confirm_restore_message", ask="yesno")
            if not proceed:
                return

            status_var.set(self.lang_manager.get_string("restoring_backup_status"))
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
                    self.show_message("restore_failed_error", "restore_failed_error", msg_type="error", be=be)
                    status_var.set("")
                    return
                except Exception as e:
                    shutil.rmtree(tempdir, ignore_errors=True)
                    self.show_message("restore_failed_error", "unexpected_restore_error", msg_type="error", e=e)
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
                status_var.set(self.lang_manager.get_string("restore_complete_status"))
                message = self.lang_manager.get_string("restore_complete_message", moved="\n".join(os.path.basename(p) for p in moved), backups="\n".join(backups_created))

                if self.show_message("restore_complete_message_title", message, ask="yesno"):
                    try:
                        try:
                            self.root.destroy()
                        except Exception:
                            pass
                        sys.exit(0)
                    except SystemExit:
                        raise
                    except Exception as e:
                        self.show_message("exit_failed_error", "exit_failed_error", e=e)
                else:
                    self.show_message("restore_complete_info", "restore_complete_info")
                win.destroy()
            except Exception as e:
                self.show_message("restore_error_title", "restore_error_message", msg_type="error", e=e)
                status_var.set("")
                try:
                    shutil.rmtree(tempdir, ignore_errors=True)
                except Exception:
                    pass

        browse_btn = tk.Button(btn_frame, text=self.lang_manager.get_string("browse_button"), command=browse_for_backup, width=12)
        browse_btn.pack(side="left", padx=(0,8))

        preview_btn = tk.Button(btn_frame, text=self.lang_manager.get_string("preview_contents_button"), command=preview_contents, width=18)
        preview_btn.pack(side="left", padx=(0,8))

        restore_btn = tk.Button(btn_frame, text=self.lang_manager.get_string("restore_selected_backup_button"), command=perform_restore, width=22)
        restore_btn.pack(side="left", padx=(0,8))

        close_btn = tk.Button(btn_frame, text=self.lang_manager.get_string("close_button"), command=win.destroy, width=12)
        close_btn.pack(side="right")

        win.transient(self.root)
        win.grab_set()
        win.focus_force()

    def show_backup_dialog(self):
        import tkinter.simpledialog as simpledialog
        if not self.database:
            self.show_message("error", "database_not_available_error", msg_type="error")
            return

        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("backup_dialog_title"))
        dialog.geometry("630x730")
        dialog.grab_set()
        dialog.resizable(False, False)

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("create_encrypted_backup_title"), 
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(20, 10))

        warning_frame = ctk.CTkFrame(main_frame, fg_color="#2b1515")  # Dark red background
        warning_frame.pack(fill="x", padx=10, pady=15)

        ctk.CTkLabel(warning_frame, text=self.lang_manager.get_string("critical_security_warnings_title"), 
                    font=ctk.CTkFont(size=18, weight="bold"), 
                    text_color="#ff4444").pack(pady=(15, 10))

        warnings_text = self.lang_manager.get_string("backup_warnings_text")

        warning_label = ctk.CTkLabel(warning_frame, text=warnings_text, 
                                    font=ctk.CTkFont(size=12), 
                                    text_color="#ff6666",
                                    justify="left")
        warning_label.pack(padx=15, pady=(0, 15))

        code_frame = ctk.CTkFrame(main_frame)
        code_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(code_frame, text=self.lang_manager.get_string("enter_backup_code_label"), 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 5))

        ctk.CTkLabel(code_frame, text=self.lang_manager.get_string("remember_backup_code_warning"), 
                    font=ctk.CTkFont(size=12), 
                    text_color="#ff4444").pack(pady=(0, 10))

        code_entry = SecureEntry(code_frame, width=400, height=40, show="*",
                                placeholder_text=self.lang_manager.get_string("backup_code_placeholder"))
        code_entry.pack(pady=(0, 10))

        def toggle_code_visibility():
            if code_entry.cget("show") == "*":
                code_entry.configure(show="")
                show_btn.configure(text=self.lang_manager.get_string("hide_button"))
            else:
                code_entry.configure(show="*")
                show_btn.configure(text=self.lang_manager.get_string("show_button"))

        show_btn = ctk.CTkButton(code_frame, text=self.lang_manager.get_string("show_button"), width=80, height=30,
                                command=toggle_code_visibility)
        show_btn.pack(pady=(0, 15))

        def create_backup():
            code = code_entry.get().strip()
            if not code:
                self.show_message("error", "backup_code_required_error", msg_type="error")
                return

            if len(code) < 8:
                self.show_message("error", "backup_code_min_length_error", msg_type="error")
                return
            confirm_msg = self.lang_manager.get_string("final_backup_confirmation_message", code_length=len(code))

            if not self.show_message("final_backup_confirmation_title", confirm_msg, ask="yesno"):
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
                
                success_msg = self.lang_manager.get_string("backup_complete_message", out_path=out_path)
                
                self.show_message("backup_complete_title", success_msg)
                dialog.destroy()
            except Exception as e:
                self.show_message("backup_failed_title", "backup_failed_message", msg_type="error", error=str(e))

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("cancel_button"), 
                    command=dialog.destroy, 
                    width=120, height=45).pack(side="left", padx=15)
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("create_backup_button"), 
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
            text=self.lang_manager.get_string("navigation"), 
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(20, 15), padx=15)
        self.sidebar_buttons = []
        self.active_button = None
        icon_accounts   = ctk.CTkImage(Image.open("icons/user.png"), size=(24, 24))
        icon_generator  = ctk.CTkImage(Image.open("icons/password.png"), size=(24, 24))
        icon_report     = ctk.CTkImage(Image.open("icons/security.png"), size=(24, 24))

        sidebar_configs = [
            (self.lang_manager.get_string("your_accounts"), icon_accounts, self.show_passwords),
            (self.lang_manager.get_string("password_generator"), icon_generator, self.show_password_generator),
            (self.lang_manager.get_string("security_report"), icon_report, self.show_security_report),
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
                
                if not self.secure_file_manager.perform_integrity_check():
                    logger.error("Integrity check failed during vault lock")
                    self.show_message("Security Warning", "File integrity check failed.", msg_type="warning")
                
                self.secure_file_manager.cleanup_temp_files()
                logger.info("Temporary files cleaned up")
            self.authenticated = False
            self.database = None
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
                        pass
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
                    shortcut = shell.CreateShortCut(str(desktop_path / "SecureVault Pro.lnk"))
                    shortcut.Targetpath = str(app_path)
                    shortcut.WorkingDirectory = str(app_dir)
                    shortcut.Description = "SecureVault Pro - Secure Password Storage"
                    shortcut.save()
                    logger.info("Windows desktop shortcut created")
                except ImportError:
                    batch_content = f"""@echo off
    cd /d "{app_dir}"
    "{app_path}"
    pause
    """
                    with open(desktop_path / "SecureVault Pro.bat", "w") as f:
                        f.write(batch_content)
                    logger.info("Windows batch file created")
                    
            elif sys.platform == "darwin":  # macOS
                try:
                    script = f'''
                    tell application "Finder"
                        make alias file to file POSIX file "{app_path}" at desktop
                        set name of result to "SecureVault Pro"
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
    Name=SecureVault Pro
    Comment=Secure Password Storage and Management
    Exec="{app_path}"
    Icon=application-x-executable
    Terminal=false
    StartupNotify=true
    Categories=Utility;Security;
    """
                desktop_file_path = desktop_path / "SecureVault Pro.desktop"
                with open(desktop_file_path, "w") as f:
                    f.write(desktop_file_content)
                desktop_file_path.chmod(0o755)
                logger.info("Linux desktop file created")
            return True
        except Exception as e:
            logger.warning(f"Could not create desktop integration: {e}")
            return False

    def show_settings(self):
        settings_window = ThemedToplevel(self.root)
        settings_window.title(self.lang_manager.get_string("settings"))
        settings_window.geometry("500x600")
        settings_window.grab_set()
        settings_window.resizable(False, False)
        
        main_frame = ctk.CTkFrame(settings_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("security_settings_title"), 
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)
        
        password_frame = ctk.CTkFrame(main_frame)
        password_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(password_frame, text=self.lang_manager.get_string("master_password_label"), 
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        ctk.CTkButton(password_frame, text=self.lang_manager.get_string("change_master_password_button"),
                    command=self.change_master_password_dialog,
                    height=40).pack(pady=10)

        tfa_frame = ctk.CTkFrame(main_frame)
        tfa_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(tfa_frame, text=self.lang_manager.get_string("tfa_title"),
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        tfa_enabled = self.settings.get('tfa_secret') is not None
        tfa_button_text = self.lang_manager.get_string("disable_2fa_button") if tfa_enabled else self.lang_manager.get_string("enable_2fa_button")
        tfa_button = ctk.CTkButton(tfa_frame, text=tfa_button_text,
                                   command=self.show_tfa_dialog,
                                   height=40)
        tfa_button.pack(pady=10)


        timeout_frame = ctk.CTkFrame(main_frame)
        timeout_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(timeout_frame, text=self.lang_manager.get_string("auto_logout_title"),
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        ctk.CTkLabel(timeout_frame, text=self.lang_manager.get_string("auto_logout_message"),
                    font=ctk.CTkFont(size=12)).pack(pady=10)
        
        lang_frame = ctk.CTkFrame(main_frame)
        lang_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(lang_frame, text=self.lang_manager.get_string("language_settings"),
                        font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        language_option_frame = ctk.CTkFrame(lang_frame, fg_color="transparent")
        language_option_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(language_option_frame, text=self.lang_manager.get_string("language"),
                        font=ctk.CTkFont(size=14)).pack(side="left", padx=10)

        lang_options = ctk.CTkOptionMenu(
            language_option_frame,
            values=self.lang_manager.supported_languages,
            command=self.change_language,
            variable=ctk.StringVar(value=self.lang_manager.language)
        )
        lang_options.pack(side="right", padx=10)

    def show_about_dialog(self):
        about_dialog = ThemedToplevel(self.root)
        about_dialog.title(self.lang_manager.get_string("about_dialog_title"))
        about_dialog.geometry("1000x600")
        about_dialog.resizable(False, False)
        about_dialog.grab_set()

        main_frame = ctk.CTkFrame(about_dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("about_slogan"), font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=(0, 15))

        about_text = self.lang_manager.get_string("about_text")
        
        textbox = ctk.CTkTextbox(main_frame, wrap="word", height=400, font=ctk.CTkFont(size=14))
        textbox.pack(fill="both", expand=True, pady=10)
        textbox.insert("1.0", about_text)
        textbox.configure(state="disabled")

        close_button = ctk.CTkButton(main_frame, text=self.lang_manager.get_string("close_button"), command=about_dialog.destroy, width=100)
        close_button.pack(pady=(15, 0))

    def show_tfa_dialog(self):
        tfa_enabled = self.settings.get('tfa_secret') is not None
        if tfa_enabled:
            self.disable_tfa_dialog()
        else:
            self.enable_tfa_dialog()

    def enable_tfa_dialog(self):
        if not self.verify_master_password_dialog():
            self.show_message("error", "tfa_setup_aborted_error", msg_type="error")
            return

        full_name, email = self.database.get_master_account_details()

        # If email is not available, use the full name for the provisioning URI
        account_name = email if email else (full_name if full_name else "SecureVault User")

        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("enable_tfa_dialog_title"))
        dialog.geometry("380x550")
        dialog.resizable(False, False)
        dialog.grab_set()

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("scan_qr_code_label"),
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        secret = self.tfa_manager.generate_secret()
        uri = self.tfa_manager.get_provisioning_uri(secret, account_name, full_name)
        qr_image_data = self.tfa_manager.generate_qr_code(uri)
        qr_image = Image.open(qr_image_data)
        qr_photo = ImageTk.PhotoImage(qr_image)

        qr_label = ctk.CTkLabel(main_frame, image=qr_photo, text="")
        qr_label.image = qr_photo
        qr_label.pack(pady=10)

        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("enter_6_digit_code_verify_label"),
                     font=ctk.CTkFont(size=14)).pack(pady=10)

        code_entry = SecureEntry(main_frame, width=200)
        code_entry.pack(pady=5)

        def verify_and_enable():
            code = code_entry.get().strip()
            if self.tfa_manager.verify_code(secret, code):
                encrypted_secret = self.crypto.encrypt_data(secret, self.database.encryption_key)
                self.settings['tfa_secret'] = base64.b64encode(encrypted_secret).decode('utf-8')
                self.save_settings_to_file()
                self.show_message("success", "tfa_enabled_success")
                dialog.destroy()
            else:
                self.show_message("error", "invalid_code_try_again", msg_type="error")

        verify_button = ctk.CTkButton(main_frame, text=self.lang_manager.get_string("verify_and_enable_button"), command=verify_and_enable)
        verify_button.pack(pady=20)

    def disable_tfa_dialog(self):
        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("disable_tfa_dialog_title"))
        dialog.geometry("400x250")
        dialog.grab_set()

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("enter_6_digit_code_disable_label"),
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        
        code_entry = SecureEntry(main_frame, width=200)
        code_entry.pack(pady=10)

        def verify_and_disable():
            code = code_entry.get().strip()
            encrypted_secret_b64 = self.settings.get('tfa_secret')
            encrypted_secret = base64.b64decode(encrypted_secret_b64)
            secret = self.crypto.decrypt_data(encrypted_secret, self.database.encryption_key)
            if self.tfa_manager.verify_code(secret, code):
                self.settings['tfa_secret'] = None
                self.save_settings_to_file()
                self.show_message("success", "tfa_disabled_success")
                dialog.destroy()
            else:
                self.show_message("error", "invalid_code", msg_type="error")

        verify_button = ctk.CTkButton(main_frame, text=self.lang_manager.get_string("verify_and_disable_button"), command=verify_and_disable)
        verify_button.pack(pady=20)

    def verify_tfa_dialog(self):
        if not self.settings.get('tfa_secret'):
            return True
        if self.enforce_lockout(show_error=True):
            return False

        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("tfa_dialog_title"))
        dialog.geometry("400x250")
        dialog.grab_set()
        
        result = {"verified": False}
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("enter_2fa_code_label"),
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        code_entry = SecureEntry(main_frame, width=200)
        code_entry.pack(pady=10)
        code_entry.focus()

        def verify_tfa():
            code = code_entry.get().strip()
            encrypted_secret_b64 = self.settings.get('tfa_secret')
            encrypted_secret = base64.b64decode(encrypted_secret_b64)
            secret = self.crypto.decrypt_data(encrypted_secret, self.database.encryption_key)
            
            is_valid = self.tfa_manager.verify_code(secret, code)
            self.auth_guardian.record_login_attempt(is_valid)

            if is_valid:
                result["verified"] = True
                dialog.destroy()
            else:
                self.show_message("error", "invalid_2fa_code", msg_type="error")
                if self.auth_guardian.is_locked_out():
                    dialog.destroy()
                    self.lock_vault()
        
        def on_cancel():
            dialog.destroy()

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("cancel_button"), command=on_cancel, width=100).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("verify_button"), command=verify_tfa, width=100).pack(side="right", padx=10)

        dialog.wait_window()
        return result["verified"]

    def prompt_for_tfa(self):
        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("tfa_dialog_title"))
        dialog.geometry("400x250")
        dialog.grab_set()

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("enter_2fa_code_label"),
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        
        code_entry = SecureEntry(main_frame, width=200)
        code_entry.pack(pady=10)

        def verify_tfa():
            try:
                code = code_entry.get().strip()
                encrypted_secret_b64 = self.settings.get('tfa_secret')
                encrypted_secret = base64.b64decode(encrypted_secret_b64)
                secret = self.crypto.decrypt_data(encrypted_secret, self.database.encryption_key)
                
                is_valid = self.tfa_manager.verify_code(secret, code)
                # A failed TFA attempt should also count towards lockout
                self.auth_guardian.record_login_attempt(is_valid)

                if is_valid:
                    self.authenticated = True
                    if self.secure_file_manager:
                        self.security_monitor = SecurityMonitor(self.secure_file_manager)
                        self.security_monitor.set_alert_callback(self.handle_security_alert)
                        self._start_security_monitoring()
                    dialog.destroy()
                    self.show_main_interface()
                else:
                    self.show_message("error", "invalid_2fa_code", msg_type="error")
                    if self.auth_guardian.is_locked_out():
                        dialog.destroy()
                        self.lock_vault()

            except InvalidTag:
                messagebox.showerror(
                    "2FA Verification Error",
                    "2FA verification failed, this is most likely due to an incorrect 'master password'. Please try logging in again."
                )
                dialog.destroy()
                self.lock_vault()

        verify_button = ctk.CTkButton(main_frame, text=self.lang_manager.get_string("verify_button"), command=verify_tfa)
        verify_button.pack(pady=20)

    def change_master_password_dialog(self):
        if not self.verify_security_questions():
            return
        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("change_master_password_dialog_title"))
        dialog.geometry("450x530")
        dialog.resizable(False, False)
        dialog.grab_set()
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("change_master_password_icon_title"),
                    font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("current_password_label"), 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        current_entry = SecureEntry(main_frame, placeholder_text=self.lang_manager.get_string("current_password_placeholder"),
                                    show="*", width=350, height=40)
        current_entry.pack(padx=20, pady=(0, 10))
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("new_password_label"),
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        new_entry = SecureEntry(main_frame, placeholder_text=self.lang_manager.get_string("new_password_placeholder"),
                                show="*", width=350, height=40)
        new_entry.pack(padx=20, pady=(0, 10))
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("confirm_new_password_label"),
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        confirm_entry = SecureEntry(main_frame, placeholder_text=self.lang_manager.get_string("confirm_new_password_placeholder"),
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
                    progress_label.configure(text=self.lang_manager.get_string("current_password_required_error"), text_color="#FF4444")
                except:
                    self.show_message("error", "current_password_required_error", msg_type="error")
                    return
                current_entry.focus()
                return
            if not new:
                try:
                    progress_label.configure(text=self.lang_manager.get_string("new_password_required_error"), text_color="#FF4444")
                except:
                    self.show_message("error", "new_password_required_error", msg_type="error")
                    return
                new_entry.focus()
                return
            if len(new) < 8:
                try:
                    progress_label.configure(text=self.lang_manager.get_string("new_password_min_length_error"), text_color="#FF4444")
                except:
                    self.show_message("error", "new_password_min_length_error", msg_type="error")
                    return
                new_entry.focus()
                return
            if new != confirm:
                try:
                    progress_label.configure(text=self.lang_manager.get_string("new_passwords_no_match_error"), text_color="#FF4444")
                except:
                    self.show_message("error", "new_passwords_no_match_error", msg_type="error")
                    return
                confirm_entry.focus()
                return
            if current == new:
                try:
                    progress_label.configure(text=self.lang_manager.get_string("new_password_must_be_different_error"), text_color="#FF4444")
                except:
                    self.show_message("error", "new_password_must_be_different_error", msg_type="error")
                    return
                new_entry.focus()
                return
            try:
                progress_label.configure(text=self.lang_manager.get_string("changing_password_status"), text_color="#FFAA44")
                dialog.update()
            except:
                pass
            
            try:
                self.database.change_master_password(current, new)
                try:
                    progress_label.configure(text=self.lang_manager.get_string("password_changed_success_status"), text_color="#00FF00")
                    dialog.update()
                except:
                    pass
                restart_result = self.show_message("password_changed_success_title", "password_changed_success_message")
                dialog.destroy()
                self.restart_program()
                
            except ValueError as ve:
                error_msg = str(ve)
                if "Current password is incorrect" in error_msg:
                    try:
                        progress_label.configure(text=self.lang_manager.get_string("current_password_incorrect_error"), text_color="#FF4444")
                    except:
                        self.show_message("error", "current_password_incorrect_error", msg_type="error")
                    current_entry.focus()
                    current_entry.select_range(0, tk.END)
                else:
                    try:
                        progress_label.configure(text=f"❌ {error_msg}", text_color="#FF4444")
                    except:
                        self.show_message("error", error_msg, msg_type="error")
            except Exception as e:
                error_msg = self.lang_manager.get_string("password_change_failed_error", error=str(e))
                logger.error(f"PASSWORD CHANGE ERROR: {error_msg}")
                try:
                    progress_label.configure(text=self.lang_manager.get_string("password_change_failed_status"), text_color="#FF4444")
                except:
                    self.show_message("error", "password_change_failed_status", msg_type="error")
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        cancel_btn = ctk.CTkButton(button_frame, text=self.lang_manager.get_string("cancel_button"), 
                                command=dialog.destroy, width=120, height=45)
        cancel_btn.pack(side="left", padx=15)
        
        change_btn = ctk.CTkButton(button_frame, text=self.lang_manager.get_string("change_master_password_button"), 
                                command=validate_and_change_password,
                                width=150, height=45, 
                                font=ctk.CTkFont(size=16, weight="bold"))
        change_btn.pack(side="right", padx=15)
        
        current_entry.focus()

    def change_language(self, language: str):
        self.lang_manager.set_language(language)
        self.settings['language'] = language
        self.save_settings_to_file()
        self.show_message('language_change_title', 'language_change_message')

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
                    self.show_message("Security Warning", "File integrity check failed during restart.", msg_type="warning")
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
            self.show_message("Restart Error", f"Failed to restart program automatically: {str(e)}\n\nPlease manually restart the application.", msg_type="error")
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
                self.show_message("Verification", "Password change verified successfully!\nYour new password is working correctly.")
            else:
                logger.warning("New password verification failed")
                self.show_message("Verification Warning", "Password was changed but verification failed.\nPlease try logging in again.", msg_type="warning")
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            self.show_message("Verification Warning", f"Password was changed but couldn't verify: {str(e)}", msg_type="warning")
                                        
    def show_passwords(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text=self.lang_manager.get_string("your_accounts_title"), 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        
        ctk.CTkButton(header, text=self.lang_manager.get_string("add_new_account"), 
                      command=self.show_account_dialog,
                      width=180, height=55, font=ctk.CTkFont(size=20, weight="bold")).pack(side="right", padx=25, pady=15)
        
        search_frame = ctk.CTkFrame(self.main_panel)
        search_frame.pack(fill="x", padx=15, pady=10)
        
        self.search_entry = NonArabicEntry(search_frame, placeholder_text=self.lang_manager.get_string("search_placeholder"),
                                         width=400, height=45)
        self.search_entry.pack(side="left", padx=25, pady=15)

        self.search_entry.bind("<KeyRelease>", self.search_accounts)

        self.passwords_container = ctk.CTkScrollableFrame(self.main_panel)
        self.passwords_container.pack(fill="both", expand=True, padx=15, pady=15)
        self.load_password_cards()

    def load_password_cards(self, query: str = None):
        for widget in self.passwords_container.winfo_children():
            widget.destroy()
        if not self.database:
            return
        try:
            metadata_conn = sqlite3.connect(self.database.metadata_db)
            if query:
                sql = """
                    SELECT id, name, email, url, notes, created_at, updated_at, tags, security_level
                    FROM accounts 
                    WHERE id != 'master_account' AND (name LIKE ? OR email LIKE ? OR url LIKE ?)
                    ORDER BY updated_at DESC
                """
                params = (f"%{query}%", f"%{query}%", f"%{query}%")
                cursor = metadata_conn.execute(sql, params)
            else:
                sql = """
                    SELECT id, name, email, url, notes, created_at, updated_at, tags, security_level
                    FROM accounts 
                    WHERE id != 'master_account'
                    ORDER BY updated_at DESC
                """
                cursor = metadata_conn.execute(sql)

            accounts = cursor.fetchall()
            metadata_conn.close()
            if not accounts:
                if query:
                    self.show_no_accounts_message(self.lang_manager.get_string("no_accounts_found_search"))
                else:
                    self.show_no_accounts_message()
                return
            for account_row in accounts:
                self.create_account_card(account_row)
        except Exception as e:
            self.show_error_message(f"Error loading accounts: {str(e)}")

    def search_accounts(self, event=None):
        query = self.search_entry.get().strip()
        self.load_password_cards(query=query)

    def show_no_accounts_message(self, message=None):
        if message is None:
            message = self.lang_manager.get_string("no_accounts_found")
        frame = ctk.CTkFrame(self.passwords_container)
        frame.pack(fill="x", padx=10, pady=20)
        ctk.CTkLabel(frame, text=message,
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#888888").pack(pady=20)
        if self.lang_manager.get_string("no_accounts_found_search") not in message:
            ctk.CTkLabel(frame, text=self.lang_manager.get_string("add_new_account"),
                         font=ctk.CTkFont(size=14),
                         text_color="#666666").pack(pady=(0, 20))

    def show_error_message(self, message):
        frame = ctk.CTkFrame(self.passwords_container)
        frame.pack(fill="x", padx=10, pady=20)
        ctk.CTkLabel(frame, text=f"❌ {message} , please re-start program or contact developer", 
                     font=ctk.CTkFont(size=14), 
                     text_color="#FF4444").pack(pady=20)

    def create_account_card(self, account_row):
        account_id, name, email, url, notes, created_at, updated_at, tags, security_level = account_row
        username, password = self.database.get_account_credentials(account_id)
        
        if password:
            score, strength, _ = self.password_generator.assess_strength(password)
        else:
            score, strength = 0, self.lang_manager.get_string("unknown_strength")
        
        account_data = {
            "id": account_id,
            "name": name,
            "username": username or email or self.lang_manager.get_string("no_username"),
            "email": email or "",
            "url": url or self.lang_manager.get_string("no_url"),
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
        if url and url != self.lang_manager.get_string("no_url"):
            ctk.CTkLabel(left_frame, text=f"🌐 {url}", 
                         text_color="#888888", font=ctk.CTkFont(size=14)).pack(anchor="w", pady=2)
        right_frame = ctk.CTkFrame(content, fg_color="transparent")
        right_frame.pack(side="right")
        strength_color = self.get_strength_color(strength)
        ctk.CTkLabel(right_frame, text=self.lang_manager.get_string("strength_template", strength=strength), 
                     text_color=strength_color, font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(0, 10))
        
        self.create_action_buttons(right_frame, account_data)

    def get_strength_color(self, strength):
        colors = {
            "Excellent": "#00FF00", "Very Strong": "#00FF00", "Strong": "#44FF44",
            "Medium": "#FFAA44", "Weak": "#FF8844", "Very Weak": "#FF4444", "Unknown": "#888888"
        }
        return colors.get(strength, "#888888")

    def verify_security_questions(self):
        if self.enforce_lockout(show_error=True):
            return False
        dialog = SecurityQuestionsDialog(self.root, self.database, self.crypto, self.lang_manager)
        is_correct = dialog.show()
        
        # We treat a security question failure like a password failure for lockout purposes.
        self.auth_guardian.record_login_attempt(is_correct)
        
        if is_correct:
            return True
        else:
            self.show_message("error", "invalid_answer", msg_type="error")
            if self.auth_guardian.is_locked_out():
                self.lock_vault()
            return False

    def create_action_buttons(self, parent, account):
        button_frame = ctk.CTkFrame(parent, fg_color="transparent")
        button_frame.pack()
        buttons = [
            (self.lang_manager.get_string("view_action"), lambda: self.view_account_details(account)),
            (self.lang_manager.get_string("edit_action"), lambda: self.show_account_dialog(account)),
            (self.lang_manager.get_string("copy_password_action"), lambda: self.copy_password_to_clipboard(account)),
            (self.lang_manager.get_string("delete_action"), lambda: self.delete_account(account))
        ]
        if account['url'] and account['url'] != self.lang_manager.get_string("no_url"):
            buttons.insert(2, (self.lang_manager.get_string("open_action"), lambda: self.open_website(account)))
        for text, command in buttons:
            color = "#FF4444" if "Delete" in text else None
            ctk.CTkButton(button_frame, text=text, width=100, height=45,
                          command=command, font=ctk.CTkFont(size=16),
                          fg_color=color).pack(side="left", padx=5)

    def delete_account(self, account):
        if self.settings.get('tfa_secret'):
            if not self.verify_tfa_dialog():
                return
        else:
            if not self.verify_security_questions():
                return
        result = self.show_message("delete_confirm_title", "delete_confirm_message", ask="yesno", account_name=account['name'])
        if result:
            try:
                self.database.delete_account(account['id'])
                self.show_message("delete_success_title", "delete_success_message", account_name=account['name'])
                self.load_password_cards()
            except Exception as e:
                self.show_message("error", "delete_failed_message", msg_type="error", error=str(e))

    def view_account_details(self, account):
        if self.settings.get('tfa_secret'):
            if not self.verify_tfa_dialog():
                return
        else:
            if not self.verify_master_password_dialog():
                return

        username, password = self.database.get_account_credentials(account["id"])
        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("account_details_title", account_name=account['name']))
        dialog.geometry("500x770")
        dialog.resizable(0,0)
        dialog.grab_set()
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("view_details_title", account_name=account['name']),
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=15)
        
        details = [
            (self.lang_manager.get_string("account_name_label"), account['name']),
            (self.lang_manager.get_string("username_label"), username or self.lang_manager.get_string("not_set")),
            (self.lang_manager.get_string("email_label"), account.get('email', self.lang_manager.get_string("not_set"))),
            (self.lang_manager.get_string("website_label"), account.get('url', self.lang_manager.get_string("not_set"))),
            (self.lang_manager.get_string("password_label"), password or self.lang_manager.get_string("not_available"))
        ]
        
        for label, value in details:
            self.create_detail_field(main_frame, label, value, is_password=label == self.lang_manager.get_string("password_label"))
        
        self.create_detail_field(main_frame, self.lang_manager.get_string("notes_label"), account.get('notes', self.lang_manager.get_string("no_notes_available")))
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("copy_password_button"),
                      command=lambda: self.copy_password_to_clipboard(account), width=150).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("close_button_label"), command=dialog.destroy, width=100).pack(side="right", padx=10)

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
        if not self.verify_security_questions():
            return
        if not self.verify_master_password_dialog():
            return
        try:
            username, password = self.database.get_account_credentials(account["id"])
            if password:
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                self.show_message("copied_title", "copy_success_message", account_name=account['name'])
                self.root.after(30000, lambda: self.root.clipboard_clear())
            else:
                self.show_message("error", "password_not_found", msg_type="error")
        except Exception as e:
            self.show_message("error", "copy_failed_message", msg_type="error", error=str(e))

    def open_website(self, account):
        if self.verify_master_password_dialog():
            try:
                url = account.get('url')
                if url and url != self.lang_manager.get_string("no_url"):
                    if not url.startswith(('http://', 'https://')):
                        url = f"https://{url}"
                    logger.info(f"Opening website for account {account['name']}: {url}")
                    webbrowser.open_new_tab(url)
                else:
                    self.show_message("error", "no_url_for_account", msg_type="error")
            except Exception as e:
                logger.error(f"Failed to open website for account {account['name']}: {e}")
                self.show_message("error", "website_open_failed", msg_type="error", error=str(e))

    def show_account_dialog(self, account=None):
        is_edit = account is not None
        title = self.lang_manager.get_string("edit_account_title", account_name=account['name']) if is_edit else self.lang_manager.get_string("add_account_title")
        dialog = ThemedToplevel(self.root)
        dialog.title(title)
        dialog.geometry("550x800")
        dialog.resizable(0,0)
        dialog.grab_set()
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        icon_title = self.lang_manager.get_string("edit_account_icon_title") if is_edit else self.lang_manager.get_string("add_account_icon_title")
        ctk.CTkLabel(main_frame, text=icon_title, 
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
            ("name", self.lang_manager.get_string("account_name_label"), account['name'] if account else ""),
            ("username", self.lang_manager.get_string("username_label"), username),
            ("email", self.lang_manager.get_string("email_label"), account.get('email', '') if account else ""),
            ("url", self.lang_manager.get_string("website_url_label"), account.get('url', '') if account else ""),
            ("password", self.lang_manager.get_string("password_label"), password),
            ("notes", self.lang_manager.get_string("notes_label"), account.get('notes', '') if account else "")
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
                entry = NonArabicEntry(parent, width=450, height=40)
                entry.pack(padx=25, pady=(0, 15))
                if default_value:
                    entry.insert(0, default_value)
                entries[field_name] = entry
        
        return entries

    def create_password_field(self, parent, default_value=""):
        password_frame = ctk.CTkFrame(parent, fg_color="transparent")
        password_frame.pack(padx=25, pady=(0, 15))
        password_entry = SecureEntry(password_frame, width=320, height=40, show="*")
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
        
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("cancel_button"), 
                      command=dialog.destroy, width=120, height=45).pack(side="left", padx=15)
        
        save_text = self.lang_manager.get_string("update_account_button") if account else self.lang_manager.get_string("add_account_button")
        ctk.CTkButton(button_frame, text=save_text, 
                      command=lambda: self.save_account(dialog, entries, account),
                      width=150, height=45, font=ctk.CTkFont(size=16, weight="bold")).pack(side="right", padx=15)

    def save_account(self, dialog, entries, account=None):
        if account:
            if self.settings.get('tfa_secret'):
                if not self.verify_tfa_dialog():
                    return
            else:
                if not self.verify_security_questions():
                    return
        try:
            name = entries["name"].get().strip()
            username = entries["username"].get().strip()
            url = entries["url"].get().strip()
            password = entries["password"].get()
            notes = entries["notes"].get("1.0", tk.END).strip()
            
            if not name:
                self.show_message("error", "account_name_required", msg_type="error")
                return
            if not password:
                self.show_message("error", "password_required", msg_type="error")
                return
            email = entries["email"].get().strip()
            if account:  # Update existing account
                self.database.update_account(account["id"], name, email, url, notes, username, password)
                self.show_message("success", "update_success_message", account_name=name)
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
                    self.show_message("error", "id_generation_failed", msg_type="error")
                    return
                try:
                    metadata_conn = sqlite3.connect(self.database.metadata_db)
                    cursor = metadata_conn.execute("SELECT name FROM accounts WHERE name = ? AND id != 'master_account'", (name,))
                    existing_name = cursor.fetchone()
                    metadata_conn.close()
                    
                    if existing_name:
                        result = self.show_message("duplicate_name_title", "duplicate_name_message", ask="yesno", account_name=name)
                        if not result:
                            return
                except Exception as e:
                    logger.error(f"Error checking account name uniqueness: {e}")
                
                try:
                    new_account = Account(
                        id=account_id,
                        name=name,
                        username=username,
                        email=email,
                        url=url,
                        notes=notes,
                        created_at=datetime.now(),
                        updated_at=datetime.now(),
                        tags=[],
                        security_level=SecurityLevel.MEDIUM
                    )
                    
                    self.database.add_account(new_account, username, password)
                    self.show_message("success", "add_success_message", account_name=name)
                    
                except sqlite3.IntegrityError as e:
                    if "UNIQUE constraint failed" in str(e):
                        self.show_message("error", "duplicate_account_error", msg_type="error", error=str(e))
                    else:
                        self.show_message("error", "database_error", msg_type="error", error=str(e))
                    return
                except Exception as e:
                    self.show_message("error", "create_failed_message", msg_type="error", error=str(e))
                    return
            
            dialog.destroy()
            self.load_password_cards()
            
        except Exception as e:
            self.show_message("error", "save_failed_message", msg_type="error", error=str(e))
            logger.error(f"Full error details: {e}")
            import traceback
            traceback.print_exc()
            
    def show_password_generator(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text=self.lang_manager.get_string("password_generator_title"), 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        
        content = ctk.CTkFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        settings_frame = ctk.CTkFrame(content)
        settings_frame.pack(side="left", fill="both", expand=True, padx=(20, 10), pady=20)
        
        ctk.CTkLabel(settings_frame, text=self.lang_manager.get_string("generator_settings"), 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        length_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        length_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(length_frame, text=self.lang_manager.get_string("password_length"), 
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        
        self.length_var = tk.IntVar(value=16)
        self.length_slider = ctk.CTkSlider(length_frame, from_=8, to=64, 
                                           variable=self.length_var, width=300)
        self.length_slider.pack(fill="x", pady=5)
        self.length_label = ctk.CTkLabel(length_frame, text=self.lang_manager.get_string("password_length_template", value=16))
        self.length_label.pack(anchor="w")
        
        def update_length_label(value):
            self.length_label.configure(text=self.lang_manager.get_string("password_length_template", value=int(float(value))))
        
        self.length_slider.configure(command=update_length_label)
        
        options_frame = ctk.CTkFrame(settings_frame)
        options_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(options_frame, text=self.lang_manager.get_string("character_types"), 
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        
        checkbox_options = [
            (self.lang_manager.get_string("include_uppercase"), self.use_uppercase),
            (self.lang_manager.get_string("include_lowercase"), self.use_lowercase),
            (self.lang_manager.get_string("include_digits"), self.use_digits),
            (self.lang_manager.get_string("include_symbols"), self.use_symbols),
            (self.lang_manager.get_string("exclude_ambiguous"), self.exclude_ambiguous)
        ]
        for text, var in checkbox_options:
            ctk.CTkCheckBox(options_frame, text=text, variable=var).pack(anchor="w", padx=15, pady=5)
        
        ctk.CTkButton(settings_frame, text=self.lang_manager.get_string("generate_password_action"), 
                      command=self.generate_password_gui, height=50,
                      font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        result_frame = ctk.CTkFrame(content)
        result_frame.pack(side="right", fill="both", expand=True, padx=(10, 20), pady=20)
        
        ctk.CTkLabel(result_frame, text=self.lang_manager.get_string("generated_password"), 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        password_display_frame = ctk.CTkFrame(result_frame, fg_color="transparent")
        password_display_frame.pack(fill="x", padx=20, pady=10)
        self.generated_password_entry = ctk.CTkEntry(password_display_frame, width=350, height=50,
                                                     font=ctk.CTkFont(size=16, family="monospace"))
        self.generated_password_entry.pack(fill="x", pady=(0, 10))
        button_frame = ctk.CTkFrame(password_display_frame, fg_color="transparent")
        button_frame.pack(fill="x")
        
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("copy_action"), width=120, height=40,
                      command=self.copy_generated_password).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("regenerate_action"), width=120, height=40,
                      command=self.generate_password_gui).pack(side="right")
        
        self.strength_frame = ctk.CTkFrame(result_frame)
        self.strength_frame.pack(fill="x", padx=20, pady=15)
        self.strength_title = ctk.CTkLabel(self.strength_frame, text=self.lang_manager.get_string("strength_analysis_title"), 
                                           font=ctk.CTkFont(size=16, weight="bold"))
        self.strength_title.pack(pady=10)
        self.strength_details = ctk.CTkLabel(self.strength_frame, text=self.lang_manager.get_string("generate_to_see_analysis"))
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
            self.show_message("Error", f"Failed to generate password: {str(e)}", msg_type="error")

    def update_strength_analysis(self, password):
        score, strength, recommendations = self.password_generator.assess_strength(password)
        strength_color = self.get_strength_color(strength)
        self.strength_details.configure(
            text=self.lang_manager.get_string("strength_analysis_template", strength=strength, score=score, length=len(password), unique_chars=len(set(password))),
            text_color=strength_color
        )

    def copy_generated_password(self):
        password = self.generated_password_entry.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.show_message("copied_title", "copied_message")
        else:
            self.show_message("error", "no_password_to_copy", msg_type="error")

    def show_security_report(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text=self.lang_manager.get_string("security_report_title"), 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        content = ctk.CTkScrollableFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        
        stats_frame = ctk.CTkFrame(content)
        stats_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(stats_frame, text=self.lang_manager.get_string("overall_statistics"), 
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
            
            stats_text = self.lang_manager.get_string("statistics_template", total_accounts=total_accounts, strong_passwords=strong_passwords, weak_passwords=weak_passwords, duplicate_passwords=len(duplicate_passwords))
            ctk.CTkLabel(stats_frame, text=stats_text, 
                         font=ctk.CTkFont(size=14)).pack(pady=10)
            if weak_passwords > 0:
                weak_frame = ctk.CTkFrame(content)
                weak_frame.pack(fill="x", padx=20, pady=15)
                
                ctk.CTkLabel(weak_frame, text=self.lang_manager.get_string("weak_passwords_title"), 
                             font=ctk.CTkFont(size=16, weight="bold"), 
                             text_color="#FF8844").pack(pady=15)
                
                for account_id, name in accounts:
                    username, password = self.database.get_account_credentials(account_id)
                    if password:
                        score, strength, _ = self.password_generator.assess_strength(password)
                        if score < 60:
                            account_frame = ctk.CTkFrame(weak_frame)
                            account_frame.pack(fill="x", padx=15, pady=5)
                            
                            ctk.CTkLabel(account_frame, text=self.lang_manager.get_string("weak_password_template", name=name, strength=strength, score=score), 
                                         text_color=self.get_strength_color(strength)).pack(side="left", padx=15, pady=10)
            if duplicate_passwords:
                dup_frame = ctk.CTkFrame(content)
                dup_frame.pack(fill="x", padx=20, pady=15)
                
                ctk.CTkLabel(dup_frame, text=self.lang_manager.get_string("duplicate_passwords_title"), 
                             font=ctk.CTkFont(size=16, weight="bold"), 
                             text_color="#FF4444").pack(pady=15)
                for password, names in password_counts.items():
                    if len(names) > 1:
                        dup_account_frame = ctk.CTkFrame(dup_frame)
                        dup_account_frame.pack(fill="x", padx=15, pady=5)
                        
                        ctk.CTkLabel(dup_account_frame, text=self.lang_manager.get_string("shared_by_template", names=', '.join(names)), 
                                     text_color="#FF4444").pack(side="left", padx=15, pady=10)
        except Exception as e:
            ctk.CTkLabel(content, text=self.lang_manager.get_string("report_error_template", error=str(e)), 
                         text_color="#FF4444").pack(pady=20)

    def get_remaining_lockout_time(self) -> int:
        return self.auth_guardian.get_remaining_lockout_time()

    def enforce_lockout(self, show_error=False) -> bool:
        if self.is_currently_locked_out():
            if show_error:
                remaining_time = self.get_remaining_lockout_time()
                minutes, seconds = divmod(remaining_time, 60)
                self.show_message("Account Locked", f"Account is locked for {minutes:02d}:{seconds:02d} due to failed attempts.", msg_type="error")
            self.log_security_event("LOCKOUT_ENFORCED", "Attempt blocked - user locked out")
            return True
        return False

    def is_currently_locked_out(self) -> bool:
        return self.auth_guardian.is_locked_out()

    def check_startup_lockout(self):
        if self.is_currently_locked_out():
            remaining_time = self.get_remaining_lockout_time()
            minutes, seconds = divmod(remaining_time, 60)
            logger.info(f"User is locked out on startup - {minutes:02d}:{seconds:02d} remaining")
            self.trial_manager.show_lockout_dialog(remaining_time)
            self.root.quit()
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
        dialog = ThemedToplevel(self.root)
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
        logger.info("Starting SecureVault Pro...")
        ModernPasswordManagerGUI.create_desktop_integration()
        app = ModernPasswordManagerGUI()
        app.root.app = app  # Attach app instance to root
        logger.info("Application initialized successfully")
        app.run()
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        logger.info("Please ensure all required dependencies are installed:")
        logger.info("pip install customtkinter cryptography pillow")
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Startup Error",
                           f"Failed to start SecureVault Pro:\n\n{str(e)}\n\n"
                           f"Please check the console for more details.")
        except:
            pass

if __name__ == "__main__":
    main()