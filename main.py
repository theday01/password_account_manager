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
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
from dataclasses import dataclass 
from enum import Enum
from process_lock import check_single_instance
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import customtkinter as ctk
from ui_utils import set_icon, ThemedToplevel, CustomMessageBox, ask_string
from secure_file_manager import SecureFileManager, SecureVaultSetup, SecurityMonitor, setup_secure_vault
from PIL import Image, ImageTk
import logging
from audit_logger import setup_logging
from tutorial import TutorialManager
from localization import LanguageManager
import threading
from notification_manager import _periodic_sender, notifier, send_safe_notification
from desktop_notifier import Icon
from password_reminder import PasswordReminder
from asyncio_manager import asyncio_manager
from tamper_manager import TamperManager
from auth_guardian import AuthGuardian
from machine_id_utils import generate_machine_id
from typing import List
import secrets
from pathlib import Path
import threading
from datetime import datetime
from backup import BackupManager
from encrypted_db import get_encrypted_connection, create_encrypted_database, Row as EncryptedRow
from enhanced_loading_screen import EnhancedLoadingScreen
from enhanced_trial_manager import get_trial_manager

logger = logging.getLogger(__name__)

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
activation_icon = ctk.CTkImage(
    light_image=Image.open("icons/activation.png"),
    size=(24, 24)
)
class ToolTip:
    """
    A simple tooltip class for CustomTkinter widgets.
    Shows a popup message when hovering over a widget.
    """
    def __init__(self, widget, text: str, delay: int = 500):
        """
        Initialize tooltip.
        
        Args:
            widget: The widget to attach the tooltip to
            text: The tooltip message to display
            delay: Delay in milliseconds before showing tooltip
        """
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tooltip_window = None
        self.scheduled_id = None
        
        # Bind events
        self.widget.bind("<Enter>", self._on_enter)
        self.widget.bind("<Leave>", self._on_leave)
        self.widget.bind("<Button-1>", self._on_leave)
    
    def _on_enter(self, event=None):
        """Schedule tooltip display on mouse enter."""
        self._cancel_scheduled()
        self.scheduled_id = self.widget.after(self.delay, self._show_tooltip)
    
    def _on_leave(self, event=None):
        """Hide tooltip and cancel scheduled display on mouse leave."""
        self._cancel_scheduled()
        self._hide_tooltip()
    
    def _cancel_scheduled(self):
        """Cancel any scheduled tooltip display."""
        if self.scheduled_id:
            self.widget.after_cancel(self.scheduled_id)
            self.scheduled_id = None
    
    def _show_tooltip(self):
        """Display the tooltip window."""
        if self.tooltip_window:
            return
        
        # Get widget position
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        
        # Create tooltip window
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        
        # Make tooltip stay on top
        self.tooltip_window.attributes("-topmost", True)
        
        # Create tooltip frame with border
        frame = tk.Frame(
            self.tooltip_window,
            background="#2D3748",
            borderwidth=1,
            relief="solid"
        )
        frame.pack(fill="both", expand=True)
        
        # Create tooltip label
        label = tk.Label(
            frame,
            text=self.text,
            justify="left",
            background="#2D3748",
            foreground="#F7FAFC",
            font=("Segoe UI", 10),
            padx=10,
            pady=8,
            wraplength=300
        )
        label.pack()
    
    def _hide_tooltip(self):
        """Hide and destroy the tooltip window."""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None


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
            if secure_file_manager.temp_dir:
                self.metadata_db = os.path.join(secure_file_manager.temp_dir, "metadata.db")
                self.sensitive_db = os.path.join(secure_file_manager.temp_dir, "sensitive.db")
                self.salt_path = os.path.join(secure_file_manager.temp_dir, "salt_file")
                self.integrity_path = os.path.join(secure_file_manager.temp_dir, "integrity_file")
            else:
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
    
    def _get_metadata_connection(self):
        """Get an encrypted connection to the metadata database."""
        if not self.encryption_key:
            raise ValueError("Encryption key not set. Call authenticate() first.")
        return get_encrypted_connection(self.metadata_db, self.encryption_key)
    
    def _get_sensitive_connection(self):
        """Get an encrypted connection to the sensitive database."""
        if not self.encryption_key:
            raise ValueError("Encryption key not set. Call authenticate() first.")
        return get_encrypted_connection(self.sensitive_db, self.encryption_key)
    
    
    def _checkpoint_databases(self):
        """Checkpoint WAL files to ensure all changes are written to the main database files.
        This ensures that when files are synced, all changes are in the main database files,
        not just in WAL files. This is important for data persistence.
        """
        try:
            # Small delay to ensure file system has flushed any pending writes
            import time
            time.sleep(0.1)
            
            # Checkpoint metadata database
            if os.path.exists(self.metadata_db):
                try:
                    metadata_conn = self._get_metadata_connection()
                    # Checkpoint WAL to main database file
                    # PASSIVE is safe and non-blocking
                    metadata_conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
                    metadata_conn.close()
                except Exception as e:
                    logger.debug(f"Metadata DB checkpoint: {e}")
            
            # Checkpoint sensitive database
            if os.path.exists(self.sensitive_db):
                try:
                    sensitive_conn = self._get_sensitive_connection()
                    # Checkpoint WAL to main database file
                    sensitive_conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
                    sensitive_conn.close()
                except Exception as e:
                    logger.debug(f"Sensitive DB checkpoint: {e}")
            
            logger.debug("Database checkpoints completed")
        except Exception as e:
            logger.warning(f"Failed to checkpoint databases: {e}")
            # Don't fail the operation if checkpoint fails - the commit should have written the data
        
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
            metadata_conn = create_encrypted_database(self.metadata_db, self.encryption_key)
            metadata_conn.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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
            sensitive_conn = create_encrypted_database(self.sensitive_db, self.encryption_key)
            sensitive_conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    account_id TEXT PRIMARY KEY,
                    encrypted_data BLOB NOT NULL
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
            
            master_data = {
                "name": full_name,
                "username": "master",
                "password": master_password,
                "email": email,
                "url": "",
                "notes": "System account for authentication verification",
                "tags": [],
                "security_level": SecurityLevel.CRITICAL.value,
                "recovery_email": "",
                "phone_number": "",
                "account_type": "System",
                "category": "Critical",
                "two_factor_enabled": 0,
                "last_password_change": datetime.now().isoformat()
            }
            encrypted_data = self.crypto.encrypt_data(json.dumps(master_data), self.encryption_key)
            
            metadata_conn = self._get_metadata_connection()
            metadata_conn.execute("""
                INSERT OR IGNORE INTO accounts (id, created_at, updated_at)
                VALUES (?, ?, ?)
            """, (
                "master_account",
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            metadata_conn.commit()
            metadata_conn.close()
            sensitive_conn = self._get_sensitive_connection()
            sensitive_conn.execute("""
                INSERT OR IGNORE INTO credentials (account_id, encrypted_data)
                VALUES (?, ?)
            """, ("master_account", encrypted_data))
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
                sensitive_conn = self._get_sensitive_connection()
                cursor = sensitive_conn.execute("""
                    SELECT encrypted_data
                    FROM credentials 
                    WHERE account_id = 'master_account'
                    LIMIT 1
                """)
                test_row = cursor.fetchone()
                sensitive_conn.close()
                if test_row:
                    try:
                        decrypted_json = self.crypto.decrypt_data(test_row[0], self.encryption_key)
                        master_data = json.loads(decrypted_json)
                        if master_data.get("username") == "master" and master_data.get("password") == master_password:
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
            metadata_conn = self._get_metadata_connection()
            cursor = metadata_conn.execute("SELECT id FROM accounts WHERE id = ?", (account.id,))
            if cursor.fetchone():
                raise ValueError(f"Account with ID '{account.id}' already exists")
            metadata_conn.execute("""
                INSERT INTO accounts (id, created_at, updated_at)
                VALUES (?, ?, ?)
            """, (
                account.id,
                account.created_at.isoformat(),
                account.updated_at.isoformat()
            ))
            metadata_conn.commit()
            
            # Verify the account was saved before proceeding
            verify_cursor = metadata_conn.execute("SELECT id FROM accounts WHERE id = ?", (account.id,))
            if not verify_cursor.fetchone():
                metadata_conn.close()
                raise ValueError(f"Account was not saved to database")
            metadata_conn.close()
            metadata_conn = None
            
            account_data = {
                "name": account.name,
                "username": username,
                "password": password,
                "email": account.email,
                "url": account.url,
                "notes": account.notes,
                "tags": account.tags,
                "security_level": account.security_level.value,
            }
            encrypted_data = self.crypto.encrypt_data(json.dumps(account_data), self.encryption_key)
            
            sensitive_conn = self._get_sensitive_connection()
            sensitive_conn.execute("""
                INSERT INTO credentials (account_id, encrypted_data)
                VALUES (?, ?)
            """, (account.id, encrypted_data))
            sensitive_conn.commit()
            
            # Verify credentials were saved
            verify_cursor = sensitive_conn.execute("SELECT account_id FROM credentials WHERE account_id = ?", (account.id,))
            if not verify_cursor.fetchone():
                sensitive_conn.close()
                raise ValueError(f"Credentials were not saved to database")
            sensitive_conn.close()
            sensitive_conn = None
            
            self.log_action("CREATE", "ACCOUNT", account.id, f"Created account: {account.name}")
            
            if self.secure_file_manager:
                # Ensure all database changes are flushed to disk before syncing
                # This is critical for data persistence
                self._checkpoint_databases()
                
                # Verify files exist before syncing
                if not os.path.exists(self.metadata_db) or not os.path.exists(self.sensitive_db):
                    logger.error(f"Database files not found after account creation. Metadata: {os.path.exists(self.metadata_db)}, Sensitive: {os.path.exists(self.sensitive_db)}")
                    raise ValueError("Database files not found after account creation")
                
                self.secure_file_manager.rotate_integrity_signature()
                # Sync files to secure storage to persist changes
                # This is critical - without this, changes are lost on restart
                try:
                    logger.info(f"Syncing account '{account.name}' to secure storage...")
                    sync_success = self.secure_file_manager.sync_all_files()
                    if not sync_success:
                        logger.error("Failed to sync account changes to secure storage - sync_all_files returned False")
                        raise ValueError("Failed to sync account changes to secure storage")
                    logger.info(f"Account '{account.name}' synced to secure storage successfully")
                except Exception as e:
                    logger.error(f"Failed to sync account changes to secure storage: {e}")
                    import traceback
                    traceback.print_exc()
                    raise ValueError(f"Failed to sync account changes to secure storage: {e}")
            
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
                    
    def get_all_decrypted_accounts(self) -> List[dict]:
        """Fetches and decrypts all account data from the database."""
        accounts = []
        try:
            metadata_conn = self._get_metadata_connection()
            metadata_conn.row_factory = EncryptedRow
            cursor = metadata_conn.execute("SELECT id, created_at, updated_at FROM accounts WHERE id != 'master_account'")
            all_metadata = cursor.fetchall()
            metadata_conn.close()

            sensitive_conn = self._get_sensitive_connection()
            for meta_row in all_metadata:
                try:
                    cursor = sensitive_conn.execute("SELECT encrypted_data FROM credentials WHERE account_id = ?", (meta_row['id'],))
                    sensitive_row = cursor.fetchone()
                    if sensitive_row:
                        decrypted_json = self.crypto.decrypt_data(sensitive_row[0], self.encryption_key)
                        sensitive_data = json.loads(decrypted_json)
                        
                        # Combine metadata and sensitive data
                        full_account = dict(meta_row)
                        full_account.update(sensitive_data)
                        accounts.append(full_account)
                except Exception as e:
                    logger.error(f"Failed to decrypt account {meta_row['id']}: {e}")
            sensitive_conn.close()
            return accounts
        except Exception as e:
            logger.error(f"Failed to get all decrypted accounts: {e}")
            return []
    
    def get_master_account_email(self) -> Optional[str]:
        try:
            sensitive_conn = self._get_sensitive_connection()
            cursor = sensitive_conn.execute("SELECT encrypted_data FROM credentials WHERE account_id = 'master_account'")
            row = cursor.fetchone()
            sensitive_conn.close()
            if row:
                decrypted_json = self.crypto.decrypt_data(row[0], self.encryption_key)
                master_data = json.loads(decrypted_json)
                return master_data.get("email")
            return None
        except Exception as e:
            logger.error(f"Failed to get master account email: {e}")
            return None

    def update_account(self, account_id: str, updated_data: dict):
        """Updates an existing account with new data."""
        try:
            # First, get the current encrypted data
            sensitive_conn = self._get_sensitive_connection()
            cursor = sensitive_conn.execute("SELECT encrypted_data FROM credentials WHERE account_id = ?", (account_id,))
            row = cursor.fetchone()
            if not row:
                sensitive_conn.close()
                raise ValueError(f"No credentials found for account ID {account_id}")

            # Decrypt, update, and re-encrypt
            decrypted_json = self.crypto.decrypt_data(row[0], self.encryption_key)
            account_data = json.loads(decrypted_json)
            account_data.update(updated_data) # Merge new data
            new_encrypted_data = self.crypto.encrypt_data(json.dumps(account_data), self.encryption_key)

            # Update the credentials table
            sensitive_conn.execute("UPDATE credentials SET encrypted_data = ? WHERE account_id = ?", (new_encrypted_data, account_id))
            sensitive_conn.commit()
            sensitive_conn.close()

            # Update the timestamp in the metadata table
            metadata_conn = self._get_metadata_connection()
            metadata_conn.execute("UPDATE accounts SET updated_at = ? WHERE id = ?", (datetime.now().isoformat(), account_id))
            metadata_conn.commit()
            metadata_conn.close()
            
            self.log_action("UPDATE", "ACCOUNT", account_id, f"Updated account: {updated_data.get('name', account_id)}")

            if self.secure_file_manager:
                self._checkpoint_databases()
                self.secure_file_manager.rotate_integrity_signature()
                self.secure_file_manager.sync_all_files()
                logger.info("Account update synced to secure storage")

        except Exception as e:
            logger.error(f"Failed to update account {account_id}: {e}")
            raise

    def update_master_account_email(self, email: str):
        """Updates the master account's email address."""
        try:
            sensitive_conn = self._get_sensitive_connection()
            cursor = sensitive_conn.execute("SELECT encrypted_data FROM credentials WHERE account_id = 'master_account'")
            row = cursor.fetchone()
            if row:
                decrypted_json = self.crypto.decrypt_data(row[0], self.encryption_key)
                master_data = json.loads(decrypted_json)
                master_data['email'] = email
                new_encrypted_data = self.crypto.encrypt_data(json.dumps(master_data), self.encryption_key)
                sensitive_conn.execute("UPDATE credentials SET encrypted_data = ? WHERE account_id = 'master_account'", (new_encrypted_data,))
                sensitive_conn.commit()
            sensitive_conn.close()

            self.log_action("UPDATE", "ACCOUNT", "master_account", f"Updated master account email to {email}")

            if self.secure_file_manager:
                self._checkpoint_databases()
                self.secure_file_manager.rotate_integrity_signature()
                self.secure_file_manager.sync_all_files()
                logger.info("Master account email update synced to secure storage")

        except Exception as e:
            logger.error(f"Failed to update master account email: {e}")
            raise
    
    def delete_account(self, account_id: str):
        """Deletes an account from both metadata and sensitive tables."""
        try:
            # Delete from metadata table
            metadata_conn = self._get_metadata_connection()
            metadata_conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
            metadata_conn.commit()
            metadata_conn.close()

            # Delete from credentials table
            sensitive_conn = self._get_sensitive_connection()
            sensitive_conn.execute("DELETE FROM credentials WHERE account_id = ?", (account_id,))
            sensitive_conn.commit()
            sensitive_conn.close()

            self.log_action("DELETE", "ACCOUNT", account_id, f"Deleted account ID: {account_id}")

            if self.secure_file_manager:
                self._checkpoint_databases()
                self.secure_file_manager.rotate_integrity_signature()
                self.secure_file_manager.sync_all_files()
                logger.info("Account deletion synced to secure storage")

        except Exception as e:
            logger.error(f"Failed to delete account {account_id}: {e}")
            raise
    
    def change_master_password(self, current_password: str, new_password: str):
        if not self.authenticate(current_password):
            raise ValueError("Current password is incorrect")
        logger.info("Starting master password change process...")
        new_salt = self.crypto.generate_salt()
        new_encryption_key = self.crypto.generate_key_from_password(new_password, new_salt)
        new_integrity_key = self.crypto.generate_key_from_password(new_password + "_integrity", new_salt)
        logger.info("Generated new encryption keys")

        sensitive_conn = self._get_sensitive_connection()
        cursor = sensitive_conn.execute("SELECT account_id, encrypted_data FROM credentials")
        all_credentials = cursor.fetchall()
        logger.info(f"Found {len(all_credentials)} accounts to re-encrypt")

        for account_id, encrypted_data in all_credentials:
            try:
                decrypted_json = self.crypto.decrypt_data(encrypted_data, self.encryption_key)
                account_data = json.loads(decrypted_json)

                # If it's the master account, update its password field to the new master password
                if account_id == 'master_account':
                    account_data['password'] = new_password
                
                # Re-encrypt with the new key
                new_encrypted_blob = self.crypto.encrypt_data(json.dumps(account_data), new_encryption_key)
                
                sensitive_conn.execute(
                    "UPDATE credentials SET encrypted_data = ? WHERE account_id = ?",
                    (new_encrypted_blob, account_id)
                )
                logger.info(f"Re-encrypted credentials for account {account_id}")
            except Exception as e:
                logger.error(f"Failed to re-encrypt account {account_id}: {e}")
                sensitive_conn.rollback()
                sensitive_conn.close()
                raise ValueError(f"Failed to re-encrypt account {account_id}: {e}")
        
        sensitive_conn.commit()
        sensitive_conn.close()
        logger.info("All credentials re-encrypted successfully")
        self.encryption_key = new_encryption_key
        self.integrity_key = new_integrity_key
        if self.secure_file_manager:
            # Update encryption key BEFORE syncing files
            # This ensures the integrity signature is computed with the new key
            self.secure_file_manager.encryption_key = new_encryption_key
        try:
            with open(self.salt_path, "wb") as f:
                f.write(new_salt)
            logger.info(f"New salt written to {self.salt_path}")
        except Exception as e:
            logger.error(f"Failed to write salt file: {e}")
            raise ValueError(f"Failed to write salt file: {e}")
        
        self.log_action("UPDATE", "SYSTEM", "master_password", "Master password changed successfully")
        
        if self.secure_file_manager:
            # CRITICAL: Sync files FROM temp_dir TO secure_dir BEFORE cleaning up
            # This saves the new salt file and re-encrypted databases to permanent storage
            # sync_all_files() will also rotate the integrity signature with the new encryption key
            try:
                self.secure_file_manager.sync_all_files()
                logger.info("Changes synced to secure storage and integrity signature updated")
            except Exception as e:
                logger.error(f"Failed to sync to secure storage: {e}")
                raise ValueError(f"Failed to sync changes to secure storage: {e}")
            # Now safe to cleanup temp files after they've been synced to secure storage
            self.secure_file_manager.cleanup_temp_files()
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
        metadata_conn = self._get_metadata_connection()
        metadata_conn.execute("""
            INSERT INTO audit_log (timestamp, action, entity_type, entity_id, details)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), action, entity_type, entity_id, details))
        metadata_conn.commit()
        metadata_conn.close()

    def save_security_questions(self, questions: List[Tuple[str, str]]):
        metadata_conn = self._get_metadata_connection()
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
        metadata_conn = self._get_metadata_connection()
        try:
            cursor = metadata_conn.execute("SELECT question, answer_hash FROM security_questions")
            questions = cursor.fetchall()
            return questions
        except Exception as e:
            logger.error(f"Failed to get security questions: {e}")
            return []
        finally:
            metadata_conn.close()

    def get_metadata_connection(self):
        return self._get_metadata_connection()

    def get_account_by_id(self, account_id: str) -> Optional[dict]:
        """Fetches and decrypts a single account's complete data by its ID."""
        try:
            # Get metadata
            metadata_conn = self._get_metadata_connection()
            metadata_conn.row_factory = EncryptedRow
            cursor = metadata_conn.execute("SELECT id, created_at, updated_at FROM accounts WHERE id = ?", (account_id,))
            meta_row = cursor.fetchone()
            metadata_conn.close()

            if not meta_row:
                return None

            # Get and decrypt sensitive data
            sensitive_conn = self._get_sensitive_connection()
            cursor = sensitive_conn.execute("SELECT encrypted_data FROM credentials WHERE account_id = ?", (account_id,))
            sensitive_row = cursor.fetchone()
            sensitive_conn.close()
            
            if sensitive_row:
                decrypted_json = self.crypto.decrypt_data(sensitive_row[0], self.encryption_key)
                sensitive_data = json.loads(decrypted_json)
                
                # Combine metadata and sensitive data
                full_account = dict(meta_row)
                full_account.update(sensitive_data)
                return full_account
            
            return None # Should not happen if data is consistent
            
        except Exception as e:
            logger.error(f"Database error while fetching account by ID '{account_id}': {e}")
            return None

    def migrate_schema(self):
        """
        Handles database schema migrations.
        For this version, since we are starting fresh, this function will simply
        ensure the new table structure is present. In the future, this would
        contain logic to migrate data from an old schema to a new one.
        """
        try:
            # This is a good place to put logic for migrating existing users' data
            # from the old schema (many columns in 'accounts') to the new schema
            # (encrypted blob in 'credentials').
            # Since the user confirmed no existing users, we'll just log this.
            logger.info("Schema migration check: No data migration needed for new schema.")
            
            # We can still check if the tables are correctly formed, just in case.
            metadata_conn = self._get_metadata_connection()
            metadata_conn.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            metadata_conn.commit()
            metadata_conn.close()

            sensitive_conn = self._get_sensitive_connection()
            sensitive_conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    account_id TEXT PRIMARY KEY,
                    encrypted_data BLOB NOT NULL
                )
            """)
            sensitive_conn.commit()
            sensitive_conn.close()
            logger.info("Schema verification check completed successfully.")
        except Exception as e:
            logger.error(f"Database error during schema migration/verification: {e}")
            raise


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

            answer_entry = ctk.CTkEntry(
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

class ModernPasswordManagerGUI:
    def __init__(self):
        self.version_data = {}
        try:
            with open("version.json", "r") as f:
                self.version_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Could not load version data: {e}")
            self.version_data = {"version": "N/A"}

        self.lang_manager = LanguageManager()
        self.crypto = CryptoManager()
        self.password_generator = PasswordGenerator(self.lang_manager)
        self.database = None
        self.secure_file_manager = None
        self.password_reminder = None
        self.authenticated = False  # Initialize here to prevent cleanup error
        ctk.set_appearance_mode("dark")  
        self.root = ctk.CTk()
        self.root.withdraw()
        # Start the asyncio event loop manager
        asyncio_manager.start()
        
        # Set the icon immediately
        set_icon(self.root)
        
        # Start the asyncio event loop manager
        asyncio_manager.start()
        self.root.title(self.lang_manager.get_string("app_title"))
        self.root.geometry("1200x800")
        
        # Set icon again after window properties are set
        set_icon(self.root)
        
        # Schedule another icon setting after event loop starts
        self.root.after(100, lambda: set_icon(self.root))
        
        self.show_loading_screen()

        self.backup_manager = None

    def start_periodic_tampering_check(self):
        """
        if not self.authenticated:
            return  # Stop checking if the user has logged out

        is_valid, reason = self.trial_manager.check_activation_integrity()
        if not is_valid:
            logger.critical(f"Tampering detected during periodic check: {reason}")
            self.show_tampering_remediate_screen()
            return  # Stop further checks

        # Schedule the next check
        self.root.after(30000, self.start_periodic_tampering_check)
        """
        pass

    def show_message(self, title_key: str, message_key: str, msg_type: str = "info", ask: str = None, **kwargs) -> bool:
        current_lang = self.lang_manager.language
        self.lang_manager.set_language("English")

        title = self.lang_manager.get_string(title_key)
        message = self.lang_manager.get_string(message_key, **kwargs)

        self.lang_manager.set_language(current_lang)
        
        dialog = CustomMessageBox(title=title, message=message, msg_type=msg_type, ask=ask)
        return dialog.show()

    def _initialize_app(self):
        self.authenticated = False
        self.accounts = []
        self.auth_guardian = AuthGuardian(self.secure_file_manager)
        self.settings = self.auth_guardian._settings
        self.inactivity_timer = None
        self.inactivity_warning_timer = None
        self.INACTIVITY_TIMEOUT = 15 * 60 * 1000  # 15 minutes in milliseconds
        self.INACTIVITY_WARNING_TIMEOUT = 13 * 60 * 1000  # 13 minutes (2 minutes before logout)
        self.load_settings()
        self.setup_ui()
        self.start_lockout_validation_timer()

    def show_welcome_dialog(self):
        welcome_window = ThemedToplevel(self.root)
        welcome_window.title(self.lang_manager.get_string("welcome_title"))
        welcome_window.geometry("550x550")
        #welcome_window.resizable(False, False)
        welcome_window.grab_set()  # Make the window modal

        # Center the window
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (550 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (550 // 2)
        welcome_window.geometry(f"+{x}+{y}")

        main_frame = ctk.CTkFrame(welcome_window, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(pady=(20, 15))

        try:
            logo_image = Image.open("icons/mainlogo.png")
            logo_ctk_image = ctk.CTkImage(light_image=logo_image, size=(170, 45))
            logo_label = ctk.CTkLabel(header_frame, image=logo_ctk_image, text="")
            logo_label.pack(pady=(0, 10))
        except Exception as e:
            logger.error(f"Failed to load logo in welcome dialog: {e}")
            ctk.CTkLabel(
                header_frame,
                text="SecureVault Pro",
                font=ctk.CTkFont(size=28, weight="bold")
            ).pack()

        ctk.CTkLabel(
            header_frame,
            text=self.lang_manager.get_string("welcome_message_1"),
            font=ctk.CTkFont(size=16),
            text_color=("gray20", "gray80")
        ).pack()

        # Features
        features_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        features_frame.pack(pady=20, padx=20, fill="x", expand=True)

        def create_feature_frame(parent, title_key, desc_key):
            feature_frame = ctk.CTkFrame(parent, fg_color=("gray90", "gray20"), corner_radius=10)
            feature_frame.pack(pady=8, padx=10, fill="x")

            title_label = ctk.CTkLabel(
                feature_frame,
                text=self.lang_manager.get_string(title_key),
                font=ctk.CTkFont(size=14, weight="bold")
            )
            title_label.pack(anchor="w", padx=15, pady=(10, 2))

            desc_label = ctk.CTkLabel(
                feature_frame,
                text=self.lang_manager.get_string(desc_key),
                font=ctk.CTkFont(size=12),
                text_color=("gray40", "gray60"),
                wraplength=450,
                justify="left"
            )
            desc_label.pack(anchor="w", padx=15, pady=(0, 10))

        create_feature_frame(features_frame, "welcome_feature_1_title", "welcome_feature_1_desc")
        create_feature_frame(features_frame, "welcome_feature_2_title", "welcome_feature_2_desc")
        create_feature_frame(features_frame, "welcome_feature_3_title", "welcome_feature_3_desc")

        # Button
        close_button = ctk.CTkButton(
            main_frame,
            text=self.lang_manager.get_string("get_started_button"),
            command=welcome_window.destroy,
            height=50,
            font=ctk.CTkFont(size=13, weight="bold")
        )
        close_button.pack(pady=10, padx=0)

        welcome_window.wait_window()

    def show_loading_screen(self):
        """Display professional enterprise-grade loading screen"""
        def on_loading_complete():
            self._setup_secure_file_manager()
            self.tamper_manager = TamperManager()
            self._initialize_app()

        # Create and show the enhanced loading screen
        enhanced_loader = EnhancedLoadingScreen(self.root, self.lang_manager, self.version_data)
        enhanced_loader.show(on_loading_complete)

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
            'tutorial_completed': False,
            'language': 'English',
            'last_login_timestamp': 0.0,
            'consecutive_logins': 0
        }
        
        # After authentication, auth_guardian holds the decrypted settings.
        # Before authentication, it holds the defaults.
        if hasattr(self, 'auth_guardian') and self.auth_guardian:
            guardian_settings = self.auth_guardian.get_settings()
            logger.info(f"Loading settings from auth_guardian: {list(guardian_settings.keys())}")
            # Merge settings: guardian_settings override defaults
            self.settings = {**default_settings, **guardian_settings}
        else:
            logger.info("No auth_guardian, using default settings")
            self.settings = default_settings
        
        logger.info(f"Loaded tutorial_completed: {self.settings.get('tutorial_completed', False)}")

        if 'language' in self.settings:
            self.lang_manager.set_language(self.settings['language'])

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
        """Enhanced setup_ui with proper activation handling."""
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Initialize enhanced trial manager
        self.trial_manager = get_trial_manager()
        
        # CRITICAL: Check if activated FIRST - before ANY security checks
        try:
            # Get the raw activation info without triggering security checks
            activation_info = self.trial_manager.get_activation_info()
            is_activated = activation_info.get('is_activated', False)
            
            if is_activated:
                logger.info("✅ Program is ACTIVATED - Skipping trial security checks")
                
                # Clear any lingering tampering flags for activated users
                self.trial_manager.tampering_detected = False
                self.trial_manager.permanent_lockout = False
                
                # Normal startup for activated users
                if self.check_startup_lockout():
                    return
                
                if not self.is_vault_initialized():
                    logger.info("Vault not initialized, showing setup wizard")
                    self.show_login_screen()
                    self.update_login_button_states()
                    return
                
                self.show_login_screen()
                self.update_login_button_states()
                return
                
        except Exception as e:
            logger.error(f"Error checking activation status: {e}")
            # Continue to security checks if we can't determine activation status
        
        # Only run these checks for NON-ACTIVATED users
        logger.info("Program not activated - performing trial security checks")
        
        # Check for permanent lockout
        is_locked, lockout_reason = self.trial_manager._check_permanent_lockout()
        if is_locked:
            logger.critical(f"PERMANENT LOCKOUT DETECTED: {lockout_reason}")
            self.show_permanent_lockout_screen(lockout_reason)
            return
        
        # Check tripwire integrity
        if not self.trial_manager._check_tripwires():
            logger.critical("TRIPWIRE INTEGRITY FAILURE")
            self.show_permanent_lockout_screen("Security tripwires compromised")
            return
        
        # Load and verify trial state
        try:
            trial_state = self.trial_manager._load_trial_state()
            
            if self.trial_manager.tampering_detected:
                logger.critical("TAMPERING DETECTED DURING STATE LOAD")
                self.show_permanent_lockout_screen("Trial state tampering detected")
                return
        except Exception as e:
            logger.critical(f"CRITICAL ERROR DURING INTEGRITY CHECK: {e}")
            self.show_permanent_lockout_screen("Security verification failed")
            return
        
        # Check trial/activation status
        can_access, reason = self.trial_manager.is_access_allowed()
        
        if not can_access:
            if "locked" in reason:
                self.show_permanent_lockout_screen(reason)
                return
            elif "trial_expired" in reason:
                self.show_activation_required_screen()
                return
        
        # Start monitoring for trial users
        self.trial_manager.start_monitoring()
        
        # Normal startup
        if self.check_startup_lockout():
            return
        
        if not self.is_vault_initialized():
            logger.info("Vault not initialized, showing setup wizard")
            self.show_login_screen()
            self.update_login_button_states()
            return
        
        self.show_login_screen()
        self.update_login_button_states()
                
    def show_permanent_lockout_screen(self, reason: str):
        """
        Show permanent lockout screen - NO ACCESS ALLOWED.
        Only developer recovery can restore access.
        """
        # Center and configure window
        self.root.update_idletasks()
        window_width = 1000
        window_height = 800
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.resizable(False, False)
        
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        # Make window always on top temporarily
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        
        # Main container with gradient-like background
        main_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        main_container.pack(fill="both", expand=True)
        
        # Animated warning header
        header_frame = ctk.CTkFrame(main_container, fg_color=("#DC2626", "#7F1D1D"), height=120)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=40, pady=20)
        
        # Warning icon and title
        icon_title_frame = ctk.CTkFrame(header_content, fg_color="transparent")
        icon_title_frame.pack(fill="x")
        
        ctk.CTkLabel(
            icon_title_frame,
            text="⛔",
            font=ctk.CTkFont(size=64)
        ).pack(side="left", padx=(0, 20))
        
        title_stack = ctk.CTkFrame(icon_title_frame, fg_color="transparent")
        title_stack.pack(side="left", fill="x", expand=True)
        
        ctk.CTkLabel(
            title_stack,
            text="SECURITY LOCKOUT ACTIVATED",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="white"
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            title_stack,
            text="⚠️ Unauthorized Tampering Detected",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#FEE2E2", "#FFE5E5")
        ).pack(anchor="w", pady=(5, 0))
        
        # Scrollable content area
        content_scroll = ctk.CTkScrollableFrame(main_container, fg_color="transparent")
        content_scroll.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Lockout reason card
        reason_card = ctk.CTkFrame(content_scroll, fg_color=("#FED7AA", "#78350F"), corner_radius=12)
        reason_card.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            reason_card,
            text="🛡️ Lockout Reason",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#92400E"
        ).pack(pady=(20, 8), padx=25, anchor="w")
        
        ctk.CTkLabel(
            reason_card,
            text=reason,
            font=ctk.CTkFont(size=13),
            text_color="#78350F",
            wraplength=850,
            justify="left"
        ).pack(pady=(0, 20), padx=25, anchor="w")
        
        # Warning details card
        details_card = ctk.CTkFrame(content_scroll, fg_color=("#F5F5F5", "#1E1E1E"), corner_radius=12)
        details_card.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            details_card,
            text="⚠️ Security Violation Details",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 15), padx=25, anchor="w")
        
        violations = [
            ("🚫 Trial Manipulation", "Attempts to extend or bypass the trial period"),
            ("📁 File Tampering", "Unauthorized modification of protected system files"),
            ("🕐 Clock Manipulation", "System time has been altered to circumvent restrictions"),
            ("🔓 Security Bypass", "Attempts to disable or circumvent security mechanisms")
        ]
        
        for title, desc in violations:
            violation_item = ctk.CTkFrame(details_card, fg_color=("gray90", "gray25"), corner_radius=8)
            violation_item.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(
                violation_item,
                text=title,
                font=ctk.CTkFont(size=13, weight="bold")
            ).pack(anchor="w", padx=15, pady=(10, 2))
            
            ctk.CTkLabel(
                violation_item,
                text=desc,
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(anchor="w", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(
            details_card,
            text="⛔ Access to SecureVault Pro has been permanently blocked for security reasons.",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#DC2626"
        ).pack(pady=(10, 20), padx=25)
        
        # Recovery options card
        recovery_card = ctk.CTkFrame(content_scroll, fg_color=("#E0F2FE", "#1E3A5F"), corner_radius=12)
        recovery_card.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            recovery_card,
            text="🔓 Access Restoration Options",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 15), padx=25, anchor="w")
        
        options = [
            "1 - Purchase and activate a valid license key to restore full access",
            "2 - Contact the developer for assistance ",
            "3 - Provide your Machine ID below for faster support resolution"
        ]
        
        for option in options:
            ctk.CTkLabel(
                recovery_card,
                text=option,
                font=ctk.CTkFont(size=12),
                text_color=("#1E40AF", "#93C5FD")
            ).pack(anchor="w", padx=35, pady=3)
        
        ctk.CTkLabel(
            recovery_card,
            text="",
            height=10
        ).pack()
        
        # Machine ID section
        machine_id = self.trial_manager.get_machine_id()
        
        id_card = ctk.CTkFrame(content_scroll, fg_color=("#F3F4F6", "#2D2D2D"), corner_radius=12)
        id_card.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            id_card,
            text="🔑 Machine ID (Required for Support)",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 10), padx=20, anchor="w")
        
        id_display_frame = ctk.CTkFrame(id_card, fg_color="transparent")
        id_display_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        id_entry = ctk.CTkEntry(
            id_display_frame,
            width=750,
            height=45,
            font=ctk.CTkFont(size=11, family="monospace"),
            justify="center",
            fg_color=("white", "#1A1A1A"),
            border_width=2,
            border_color=("#3B82F6", "#2563EB")
        )
        id_entry.pack(side="left", padx=(0, 10))
        id_entry.insert(0, machine_id)
        id_entry.configure(state="readonly")
        
        def copy_machine_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(machine_id)
            copy_btn.configure(text="✅ Copied", fg_color="#10B981")
            self.root.after(2000, lambda: copy_btn.configure(text="📋 Copy", fg_color="#6B7280"))
        
        copy_btn = ctk.CTkButton(
            id_display_frame,
            text="📋 Copy",
            command=copy_machine_id,
            width=100,
            height=45,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#6B7280",
            hover_color="#4B5563"
        )
        copy_btn.pack(side="right")
        
        # Action buttons
        button_frame = ctk.CTkFrame(main_container, fg_color=("#F9FAFB", "#1A1A1A"), height=90)
        button_frame.pack(fill="x", padx=0, pady=0, side="bottom")
        button_frame.pack_propagate(False)
        
        buttons_inner = ctk.CTkFrame(button_frame, fg_color="transparent")
        buttons_inner.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Exit button
        ctk.CTkButton(
            buttons_inner,
            text="❌ Exit Program",
            command=self.root.quit,
            width=200,
            height=50,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=("#DC2626", "#991B1B"),
            hover_color=("#B91C1C", "#7F1D1D"),
            corner_radius=10
        ).pack(side="left")
        
        # Activate button
        ctk.CTkButton(
            buttons_inner,
            text="🔓 Activate License Key",
            command=self.show_activation_dialog,
            width=250,
            height=50,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#10B981",
            hover_color="#059669",
            corner_radius=10
        ).pack(side="right")

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
        try:
            logo_image = Image.open("icons/mainlogo.png")
            logo_ctk_image = ctk.CTkImage(light_image=logo_image, size=(300, 80))
            logo_label = ctk.CTkLabel(login_card, image=logo_ctk_image, text="")
            logo_label.pack(pady=(30, 30), padx=40)
        except Exception as e:
            logger.error(f"Failed to load logo: {e}")
            # Fallback to text if image fails to load
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
        self.master_password_entry = ctk.CTkEntry(
            password_frame,
            placeholder_text=self.lang_manager.get_string("enter_master_password"),
            show="*",
            width=300,
            height=45,
            font=ctk.CTkFont(size=16)
        )
        self.master_password_entry.pack(side="left", padx=(0, 5))
        
        # --- DISABLE COPY/PASTE FOR LOGIN ---
        # Returns "break" to stop the event from propagating, effectively blocking the action
        self._block_copy_paste_comprehensive(self.master_password_entry)
        # ------------------------------------

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
        
    def show_activation_required_screen(self):
        """Show professional activation screen when trial expires."""
        # Center the main window on screen
        self.root.update_idletasks()
        window_width = 800
        window_height = 650
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.resizable(False, False)
        
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        card = ctk.CTkFrame(container, corner_radius=15, fg_color=("#F5F5F5", "#1E1E1E"))
        card.pack(padx=40, pady=40)
        
        # Lock icon
        ctk.CTkLabel(
            card,
            text="🔒",
            font=ctk.CTkFont(size=64)
        ).pack(pady=(30, 10))
        
        # Title
        ctk.CTkLabel(
            card,
            text="Activation Required",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=(10, 5))
        
        # Message
        ctk.CTkLabel(
            card,
            text="Your 7-day trial period has expired.\nPlease activate SecureVault Pro to continue.",
            font=ctk.CTkFont(size=14),
            text_color="#666666",
            justify="center"
        ).pack(pady=(5, 20), padx=40)
        
        # Machine ID display
        machine_id = self.trial_manager.get_machine_id()
        
        id_frame = ctk.CTkFrame(card, fg_color=("#E8E8E8", "#2A2A2A"), corner_radius=10)
        id_frame.pack(fill="x", padx=40, pady=15)
        
        ctk.CTkLabel(
            id_frame,
            text="Your Machine ID:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(15, 5), padx=20)
        
        id_entry = ctk.CTkEntry(
            id_frame,
            width=400,
            height=40,
            font=ctk.CTkFont(size=11, family="monospace"),
            justify="center"
        )
        id_entry.pack(pady=(5, 15), padx=20)
        id_entry.insert(0, machine_id)
        id_entry.configure(state="readonly")
        
        # Copy button for Machine ID
        def copy_machine_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(machine_id)
            copy_btn.configure(text="✅ Copied!")
            self.root.after(2000, lambda: copy_btn.configure(text="Copy Machine ID"))
        
        copy_btn = ctk.CTkButton(
            card,
            text="Copy Machine ID",
            command=copy_machine_id,
            width=200,
            height=40,
            fg_color=("#4A90E2", "#357ABD")
        )
        copy_btn.pack(pady=(0, 15))
        
        # Activate button
        ctk.CTkButton(
            card,
            text="🔑 Activate Now",
            command=self.show_activation_dialog,
            width=250,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#10B981",
            hover_color="#059669"
        ).pack(pady=(10, 20))
        
        # Exit button
        ctk.CTkButton(
            card,
            text="Exit Program",
            command=self.root.quit,
            width=200,
            height=40,
            fg_color=("#999999", "#555555")
        ).pack(pady=(0, 30))

    def show_activation_dialog(self):
        """Show activation dialog for entering license key."""
        dialog = ThemedToplevel(self.root)
        dialog.title("Activate SecureVault Pro")
        dialog.grab_set()
        dialog.resizable(False, False)
        self.center_window(dialog, 500, 400)
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        ctk.CTkLabel(
            main_frame,
            text="🔑 Activate SecureVault Pro",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(0, 10))
        
        ctk.CTkLabel(
            main_frame,
            text="Enter your license key to activate the application",
            font=ctk.CTkFont(size=12),
            text_color="#888888"
        ).pack(pady=(0, 20))
        
        # License key entry
        ctk.CTkLabel(
            main_frame,
            text="License Key:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=20)
        
        license_entry = ctk.CTkEntry(
            main_frame,
            width=440,
            height=45,
            font=ctk.CTkFont(size=12, family="monospace"),
            placeholder_text="Enter your 64-character license key"
        )
        license_entry.pack(pady=(5, 15), padx=20)
        license_entry.focus()
        
        # Status label
        status_label = ctk.CTkLabel(
            main_frame,
            text="",
            font=ctk.CTkFont(size=11)
        )
        status_label.pack(pady=(0, 15))
        
        def perform_activation():
            license_key = license_entry.get().strip()
            
            if not license_key:
                status_label.configure(text="⚠️ Please enter a license key", text_color="#FF9500")
                return
            
            status_label.configure(text="🔄 Verifying license key...", text_color="#4A90E2")
            dialog.update()
            
            # Verify and activate
            success, message = self.trial_manager.activate(license_key)
            
            if success:
                status_label.configure(text="✅ Activation successful!", text_color="#10B981")
                dialog.update()
                
                # Professional Success Message
                success_title = "Activation Complete"
                success_message = (
                    "Thank you for choosing SecureVault Pro.\n\n"
                    "Your license has been successfully verified and registered to this workstation.\n\n"
                    "To finalize the configuration and initialize all premium security modules, "
                    "the application must be restarted.\n\n"
                    "The program will now close. Please relaunch it manually to continue."
                )
                
                # Using CustomMessageBox directly for better formatting control
                CustomMessageBox(
                    title=success_title, 
                    message=success_message, 
                    msg_type="info"
                ).show()
                
                dialog.destroy()
                
                # Clean shutdown instead of automatic restart
                # This breaks the main loop and triggers the cleanup in run()
                self.root.quit()
            else:
                status_label.configure(text=f"❌ {message}", text_color="#EF4444")
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=(10, 0))
        
        ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=dialog.destroy,
            width=120,
            height=40,
            fg_color=("#999999", "#555555")
        ).pack(side="left", padx=10)
        
        ctk.CTkButton(
            button_frame,
            text="Activate",
            command=perform_activation,
            width=150,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#10B981",
            hover_color="#059669"
        ).pack(side="right", padx=10)
        
        license_entry.bind("<Return>", lambda e: perform_activation())

    def show_tamper_detected_screen(self):
        """Show critical tamper detection screen that blocks all access."""
        # Center the main window on screen
        self.root.update_idletasks()
        window_width = 900
        window_height = 700
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.resizable(False, False)
        
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        # Make window always on top
        self.root.attributes('-topmost', True)
        
        container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        card = ctk.CTkFrame(container, corner_radius=15, fg_color=("#FEE2E2", "#450A0A"))
        card.pack(padx=40, pady=40)
        
        # Critical error icon
        ctk.CTkLabel(
            card,
            text="⛔",
            font=ctk.CTkFont(size=72)
        ).pack(pady=(30, 10))
        
        # Title
        ctk.CTkLabel(
            card,
            text="CRITICAL SECURITY ALERT",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#DC2626"
        ).pack(pady=(10, 5))
        
        # Subtitle
        ctk.CTkLabel(
            card,
            text="Activation Tampering Detected",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#991B1B"
        ).pack(pady=(5, 20))
        
        # Warning message
        warning_text = (
            "Unauthorized modification to the activation system has been detected.\n"
            "This may indicate:\n\n"
            "• Manual tampering with activation files\n"
            "• Malicious software activity\n"
            "• Unauthorized attempts to bypass licensing\n\n"
            "For your security, all access to SecureVault Pro has been blocked."
        )
        
        ctk.CTkLabel(
            card,
            text=warning_text,
            font=ctk.CTkFont(size=13),
            text_color="#7F1D1D",
            justify="center"
        ).pack(pady=(0, 20), padx=50)
        
        # Developer contact info
        info_frame = ctk.CTkFrame(card, fg_color=("#FED7AA", "#78350F"), corner_radius=10)
        info_frame.pack(fill="x", padx=40, pady=15)
        
        ctk.CTkLabel(
            info_frame,
            text="🔧 Contact Developer to Restore Access",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#92400E"
        ).pack(pady=(15, 5), padx=20)
        
        ctk.CTkLabel(
            info_frame,
            text="Email: developer@securevaultpro.com\nSupport: https://support.securevaultpro.com",
            font=ctk.CTkFont(size=12),
            text_color="#78350F",
            justify="center"
        ).pack(pady=(5, 15), padx=20)
        
        # Machine ID for support
        machine_id = self.trial_manager.get_machine_id()
        
        support_frame = ctk.CTkFrame(card, fg_color=("#E5E7EB", "#1F2937"), corner_radius=10)
        support_frame.pack(fill="x", padx=40, pady=15)
        
        ctk.CTkLabel(
            support_frame,
            text="Machine ID (for support):",
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(pady=(10, 5), padx=20)
        
        id_entry = ctk.CTkEntry(
            support_frame,
            width=500,
            height=35,
            font=ctk.CTkFont(size=10, family="monospace"),
            justify="center"
        )
        id_entry.pack(pady=(5, 10), padx=20)
        id_entry.insert(0, machine_id)
        id_entry.configure(state="readonly")
        
        # Copy button
        def copy_machine_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(machine_id)
            copy_btn.configure(text="✅ Copied!")
            self.root.after(2000, lambda: copy_btn.configure(text="Copy Machine ID"))
        
        copy_btn = ctk.CTkButton(
            card,
            text="Copy Machine ID",
            command=copy_machine_id,
            width=180,
            height=35,
            fg_color=("#6B7280", "#4B5563")
        )
        copy_btn.pack(pady=(0, 15))
                
        # Buttons
        button_frame = ctk.CTkFrame(card, fg_color="transparent")
        button_frame.pack(pady=(10, 30))
        
        # Activate button
        ctk.CTkButton(
            button_frame,
            text="Activate License",
            command=self.show_activation_dialog,
            width=200,
            height=45,
            font=ctk.CTkFont(size=13),
            fg_color="#10B981",
            hover_color="#059669"
        ).pack(side="left", padx=10)
        
        # Exit
        ctk.CTkButton(
            button_frame,
            text="Exit Application",
            command=self.root.quit,
            width=200,
            height=45,
            font=ctk.CTkFont(size=13),
            fg_color=("#DC2626", "#991B1B"),
            hover_color=("#B91C1C", "#7F1D1D")
        ).pack(side="right", padx=10)

    def show_tampering_remediate_screen(self):
        """Show a less severe screen for tampering detected post-startup, prompting for activation."""
        self.root.update_idletasks()
        window_width = 800
        window_height = 650
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.resizable(False, False)

        for widget in self.main_frame.winfo_children():
            widget.destroy()

        container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center")

        card = ctk.CTkFrame(container, corner_radius=15, fg_color=("#F5F5F5", "#1E1E1E"))
        card.pack(padx=40, pady=40)

        ctk.CTkLabel(
            card,
            text="🛡️",
            font=ctk.CTkFont(size=64)
        ).pack(pady=(30, 10))

        ctk.CTkLabel(
            card,
            text="Activation State Modified",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=(10, 5))

        ctk.CTkLabel(
            card,
            text="A modification to the trial or activation files has been detected.\nPlease activate to continue.",
            font=ctk.CTkFont(size=14),
            text_color="#666666",
            justify="center"
        ).pack(pady=(5, 20), padx=40)

        machine_id = self.trial_manager.get_machine_id()

        id_frame = ctk.CTkFrame(card, fg_color=("#E8E8E8", "#2A2A2A"), corner_radius=10)
        id_frame.pack(fill="x", padx=40, pady=15)

        ctk.CTkLabel(
            id_frame,
            text="Your Machine ID:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(15, 5), padx=20)

        id_entry = ctk.CTkEntry(
            id_frame,
            width=400,
            height=40,
            font=ctk.CTkFont(size=11, family="monospace"),
            justify="center"
        )
        id_entry.pack(pady=(5, 15), padx=20)
        id_entry.insert(0, machine_id)
        id_entry.configure(state="readonly")

        def copy_machine_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(machine_id)
            copy_btn.configure(text="✅ Copied!")
            self.root.after(2000, lambda: copy_btn.configure(text="Copy Machine ID"))

        copy_btn = ctk.CTkButton(
            card,
            text="Copy Machine ID",
            command=copy_machine_id,
            width=200,
            height=40,
            fg_color=("#4A90E2", "#357ABD")
        )
        copy_btn.pack(pady=(0, 15))

        ctk.CTkButton(
            card,
            text="🔑 Activate Now",
            command=self.show_activation_dialog,
            width=250,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#10B981",
            hover_color="#059669"
        ).pack(pady=(10, 20))

        ctk.CTkButton(
            card,
            text="Exit Program",
            command=self.root.quit,
            width=200,
            height=40,
            fg_color=("#999999", "#555555")
        ).pack(pady=(0, 30))

    def show_activation_modal(self):
        """Show activation modal with program ID and activation input."""
        dialog = ThemedToplevel(self.root)
        dialog.title("Product Activation")
        dialog.grab_set()
        dialog.resizable(False, False)
        self.center_window(dialog, 600, 600)
        
        # Main container
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Header Section
        header_frame = ctk.CTkFrame(main_frame, fg_color=("#2E3440", "#1E1E1E"), height=100)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=25, pady=20)
        
        ctk.CTkLabel(
            header_content,
            text="🔑 Product Activation",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=("white", "white")
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            header_content,
            text="Activate your SecureVault Pro license",
            font=ctk.CTkFont(size=13),
            text_color=("#B0B0B0", "#B0B0B0")
        ).pack(anchor="w", pady=(5, 0))
        
        # Content Section
        content_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=25, pady=25)
        
        # Get activation info
        if hasattr(self, 'trial_manager'):
            activation_info = self.trial_manager.get_activation_info()
            machine_id = activation_info.get('machine_id', 'N/A')
            is_activated = activation_info.get('is_activated', False)
        else:
            machine_id = "Trial Manager Not Available"
            is_activated = False
        
        # Activation Status
        status_frame = ctk.CTkFrame(content_frame, fg_color=("gray90", "gray20"), corner_radius=10)
        status_frame.pack(fill="x", pady=(0, 20))
        
        status_content = ctk.CTkFrame(status_frame, fg_color="transparent")
        status_content.pack(fill="x", padx=20, pady=15)
        
        if is_activated:
            status_text = "✅ Product Activated"
            status_color = "#10B981"
            activation_date = activation_info.get('activation_date', 'Unknown')
            if activation_date and activation_date != 'Unknown':
                try:
                    from datetime import datetime
                    date_obj = datetime.fromisoformat(activation_date)
                    activation_date = date_obj.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            status_detail = f"Activated on: {activation_date}"
        else:
            status_text = "⚠️ Product Not Activated"
            status_color = "#F59E0B"
            days_remaining = activation_info.get('days_remaining', 0)
            status_detail = f"Trial: {days_remaining} day{'s' if days_remaining != 1 else ''} remaining"
        
        ctk.CTkLabel(
            status_content,
            text=status_text,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=status_color
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            status_content,
            text=status_detail,
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray60")
        ).pack(anchor="w", pady=(3, 0))
        
        # Program ID Section
        id_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        id_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            id_frame,
            text="Program ID:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(0, 8))
        
        # Program ID display with copy button
        id_display_frame = ctk.CTkFrame(id_frame, fg_color=("gray85", "gray25"), corner_radius=8)
        id_display_frame.pack(fill="x")
        
        id_inner_frame = ctk.CTkFrame(id_display_frame, fg_color="transparent")
        id_inner_frame.pack(fill="x", padx=15, pady=12)
        
        program_id_entry = ctk.CTkEntry(
            id_inner_frame,
            width=400,
            height=40,
            font=ctk.CTkFont(size=11, family="monospace"),
            state="readonly",
            fg_color=("white", "gray15")
        )
        program_id_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        program_id_entry.configure(state="normal")
        program_id_entry.insert(0, machine_id)
        program_id_entry.configure(state="readonly")
        
        def copy_program_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(machine_id)
            copy_btn.configure(text="✓ Copied")
            dialog.after(2000, lambda: copy_btn.configure(text="Copy"))
        
        copy_btn = ctk.CTkButton(
            id_inner_frame,
            text="Copy",
            command=copy_program_id,
            width=90,
            height=40,
            font=ctk.CTkFont(size=12)
        )
        copy_btn.pack(side="right")
        
        # Activation Code Section
        code_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        code_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            code_frame,
            text="Activation Code:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(0, 8))
        
        activation_code_entry = ctk.CTkEntry(
            code_frame,
            width=550,
            height=45,
            font=ctk.CTkFont(size=12, family="monospace"),
            placeholder_text="Enter your 64-character activation code",
            fg_color=("white", "gray15")
        )
        activation_code_entry.pack(fill="x")
        
        if not is_activated:
            activation_code_entry.focus()
        else:
            activation_code_entry.configure(state="disabled")
        
        # Status Label
        status_label = ctk.CTkLabel(
            content_frame,
            text="",
            font=ctk.CTkFont(size=12)
        )
        status_label.pack(pady=(5, 15))
        
        # Action Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color=("gray90", "gray15"), height=80)
        button_frame.pack(fill="x", padx=0, pady=0, side="bottom")
        button_frame.pack_propagate(False)
        
        buttons_inner = ctk.CTkFrame(button_frame, fg_color="transparent")
        buttons_inner.pack(fill="both", expand=True, padx=25, pady=18)
        
        def perform_activation():
            activation_code = activation_code_entry.get().strip()
            
            if not activation_code:
                status_label.configure(text="⚠️ Please enter an activation code", text_color="#F59E0B")
                return
            
            if not hasattr(self, 'trial_manager'):
                status_label.configure(text="❌ Activation system not available", text_color="#EF4444")
                return
            
            status_label.configure(text="🔄 Verifying activation code...", text_color="#3B82F6")
            dialog.update()
            
            # Verify and activate
            success, message = self.trial_manager.activate(activation_code)
            
            if success:
                status_label.configure(text="✅ Activation successful!", text_color="#10B981")
                dialog.update()
                
                self.show_message("success", 
                    "Thank you for activating SecureVault Pro!\n\nThe application will now restart to complete activation.",
                    msg_type="info")
                
                dialog.destroy()
                self.restart_program()
            else:
                status_label.configure(text=f"❌ {message}", text_color="#EF4444")
        
        def contact_developer():
            """Open contact information for developer support."""
            contact_dialog = ThemedToplevel(dialog)
            contact_dialog.title("Contact Developer")
            contact_dialog.grab_set()
            contact_dialog.resizable(False, False)
            self.center_window(contact_dialog, 500, 500)
            
            contact_frame = ctk.CTkFrame(contact_dialog)
            contact_frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            ctk.CTkLabel(
                contact_frame,
                text="Developer Support",
                font=ctk.CTkFont(size=20, weight="bold")
            ).pack(pady=(0, 15))
            
            ctk.CTkLabel(
                contact_frame,
                text="For activation support or inquiries, please contact:",
                font=ctk.CTkFont(size=12),
                wraplength=450
            ).pack(pady=(0, 20))
            
            # Contact Information
            info_frame = ctk.CTkFrame(contact_frame, fg_color=("gray90", "gray20"), corner_radius=10)
            info_frame.pack(fill="x", pady=(0, 20))
            
            info_content = ctk.CTkFrame(info_frame, fg_color="transparent")
            info_content.pack(fill="x", padx=20, pady=20)
            
            contact_info = [
                ("Developer:", "Hamza Saadi"),
                ("Company:", "EAGLESHADOW"),
                ("Email:", "support@eagleshadow.com"),
                ("WhatsApp:", "(+212) 6234222858"),
                ("Website:", "www.eagleshadow.com")
            ]
            
            # Items that should have copy buttons (Email, WhatsApp, Website)
            copyable_items = {"Email:", "WhatsApp:", "Website:"}
            
            for label, value in contact_info:
                row = ctk.CTkFrame(info_content, fg_color="transparent")
                row.pack(fill="x", pady=5)
                
                ctk.CTkLabel(
                    row,
                    text=label,
                    font=ctk.CTkFont(size=12, weight="bold"),
                    width=120,
                    anchor="w"
                ).pack(side="left")
                
                value_label = ctk.CTkLabel(
                    row,
                    text=value,
                    font=ctk.CTkFont(size=12),
                    anchor="w"
                )
                value_label.pack(side="left", fill="x", expand=True)
                
                # Add copy button for Email, WhatsApp, and Website
                if label in copyable_items:
                    def make_copy_function(text_to_copy, btn_ref):
                        def copy_text():
                            self.root.clipboard_clear()
                            self.root.clipboard_append(text_to_copy)
                            original_text = btn_ref.cget("text")
                            btn_ref.configure(text="✓ Copied")
                            contact_dialog.after(2000, lambda: btn_ref.configure(text=original_text))
                        return copy_text
                    
                    copy_btn = ctk.CTkButton(
                        row,
                        text="Copy",
                        command=lambda: None,  # Will be set below
                        width=70,
                        height=28,
                        font=ctk.CTkFont(size=11)
                    )
                    copy_btn.configure(command=make_copy_function(value, copy_btn))
                    copy_btn.pack(side="right", padx=(10, 0))
            
            ctk.CTkLabel(
                contact_frame,
                text="Include your Program ID when contacting support.",
                font=ctk.CTkFont(size=11),
                text_color="gray",
                wraplength=450
            ).pack(pady=(0, 10))
            
            ctk.CTkButton(
                contact_frame,
                text="Close",
                command=contact_dialog.destroy,
                width=120,
                height=40
            ).pack(pady=(10, 0))
        
        # Cancel Button
        ctk.CTkButton(
            buttons_inner,
            text="Cancel",
            command=dialog.destroy,
            width=130,
            height=45,
            font=ctk.CTkFont(size=14),
            fg_color=("gray70", "gray30"),
            hover_color=("gray60", "gray40")
        ).pack(side="left")
        
        # Contact Developer Button
        ctk.CTkButton(
            buttons_inner,
            text="Contact Developer",
            command=contact_developer,
            width=180,
            height=45,
            font=ctk.CTkFont(size=14),
            fg_color=("#3B82F6", "#2563EB"),
            hover_color=("#2563EB", "#1D4ED8")
        ).pack(side="left", padx=10)
        
        # Activate Button
        activate_btn = ctk.CTkButton(
            buttons_inner,
            text="✓ Activate",
            command=perform_activation,
            width=130,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#10B981",
            hover_color="#059669"
        )
        activate_btn.pack(side="right")
        
        if is_activated:
            activate_btn.configure(state="disabled")
        
        # Bind Enter key to activate
        activation_code_entry.bind("<Return>", lambda e: perform_activation())
    
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
            logger.info("Initializing encryption...")
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
        
        if auth_success:
            self.database.migrate_schema()
            # IMPORTANT: Set encryption key BEFORE reloading settings
            self.secure_file_manager.encryption_key = self.database.encryption_key
            logger.info(f"Encryption key set on secure_file_manager after login. Key is set: {self.secure_file_manager.encryption_key is not None}")
            
            # CRITICAL: Reload settings FIRST, before recording login attempt
            # This ensures we have the correct state before any save operations
            logger.info("Calling reload_settings() after successful auth...")
            self.auth_guardian.reload_settings()
            logger.info("reload_settings() completed")
            
            # Now record login attempt - this will preserve the settings we just loaded
            logger.info("Recording login attempt after settings reload...")
            self.auth_guardian.record_login_attempt(success=auth_success)
            logger.info("Login attempt recorded")

             # Initialize backup manager
            self.backup_manager = BackupManager(
                self.database,
                self.secure_file_manager,
                self.crypto
            )
            logger.info("Backup manager initialized")
        else:
            # For failed login, we can't reload settings (no encryption key yet)
            # But we still need to record the failed attempt
            self.auth_guardian.record_login_attempt(success=auth_success)

        if auth_success:
            
            self.load_settings() # Reload settings into the main app
            logger.info("load_settings() completed")

            # Check if 2FA is enabled and require verification
            logger.info(f"Checking 2FA status: hasattr(auth_guardian)={hasattr(self, 'auth_guardian')}, auth_guardian exists={self.auth_guardian is not None if hasattr(self, 'auth_guardian') else False}")
            if hasattr(self, 'auth_guardian') and self.auth_guardian:
                is_2fa_enabled = self.auth_guardian.is_tfa_enabled()
                logger.info(f"2FA is_tfa_enabled() returned: {is_2fa_enabled}")
                if is_2fa_enabled:
                    logger.info("2FA is enabled, showing 2FA verification dialog...")
                    if not self.verify_2fa_during_login():
                        # 2FA verification failed or was cancelled
                        logger.warning("2FA verification failed or was cancelled")
                        return
                    logger.info("2FA verification successful")
                else:
                    logger.info("2FA is not enabled, skipping 2FA verification")
            
            self.authenticated = True
            now = datetime.now().timestamp()
            last_login = self.settings.get('last_login_timestamp', 0.0)
            consecutive_logins = self.settings.get('consecutive_logins', 0)
            if (now - last_login) > 3600:
                consecutive_logins = 1
            else:
                consecutive_logins += 1
            self.auth_guardian.update_setting('last_login_timestamp', now)
            self.auth_guardian.update_setting('consecutive_logins', consecutive_logins)
            self.settings['last_login_timestamp'] = now
            self.settings['consecutive_logins'] = consecutive_logins
            
            self.show_loading_main_ui()
            self.root.after(100, self.show_main_interface)
            self.root.after(1000, self.start_periodic_tampering_check)

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
                self.show_message("error", "Account locked", msg_type="error")
                self.root.quit()
            else:
                remaining_attempts = self.auth_guardian.MAX_ATTEMPTS_BEFORE_LOCKOUT - self.auth_guardian.failed_attempts
                self.show_message("error", "invalid_master_password_error", msg_type="error", attempts=remaining_attempts)
                if self.auth_guardian.is_locked_out(): # Re-check after message
                    self.show_message("error", "Account locked", msg_type="error")
                    self.root.quit()

    def _block_copy_paste_comprehensive(self, widget, include_cut=True):
        """
        Comprehensive method to block copy/paste/cut operations regardless of Caps Lock state.
        Binds to all possible keyboard combinations including uppercase variations.
        
        Args:
            widget: The widget to apply the restrictions to
            include_cut: Whether to also block cut operations (default: True)
        """
        def block_event(event):
            """Block the event and return 'break' to prevent propagation"""
            return "break"
        
        # Block right-click context menu
        widget.bind("<Button-3>", block_event)
        widget.bind("<Button-2>", block_event)  # Middle mouse button
        
        # Block all variations of copy/paste/cut shortcuts
        # Handle both lowercase and uppercase to account for Caps Lock
        shortcuts = [
            "<Control-v>", "<Control-V>",  # Paste
            "<Control-c>", "<Control-C>",  # Copy
            "<Control-a>", "<Control-A>",  # Select all (often used with copy)
        ]
        
        if include_cut:
            shortcuts.extend(["<Control-x>", "<Control-X>"])  # Cut
        
        # Bind all variations
        for shortcut in shortcuts:
            widget.bind(shortcut, block_event)
        
        # Also bind to key press events to catch any other combinations
        def block_key_event(event):
            """Block copy/paste/cut on key press level"""
            # Check if Control key is pressed (mask 0x4 = Control)
            # Also check for Control+Shift combinations
            if event.state & 0x4:  # Control key mask
                key = event.keysym.lower()
                # Block 'v' (paste), 'c' (copy), 'x' (cut), 'a' (select all)
                # This works regardless of Caps Lock state since we use .lower()
                if key in ['v', 'c', 'x', 'a']:
                    return "break"
            # Check for Shift+Insert (alternative paste)
            if event.state & 0x1 and event.keysym == "Insert":  # Shift key mask
                return "break"
            return None
        
        widget.bind("<KeyPress>", block_key_event)
        widget.bind("<KeyRelease>", block_key_event)
        
        # Prevent clipboard access via menu shortcuts
        widget.bind("<Shift-Insert>", block_event)  # Alternative paste
        widget.bind("<Control-Insert>", block_event)  # Alternative copy

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

        while True:
            dialog = ThemedToplevel(self.root)
            dialog.title(self.lang_manager.get_string("verify_master_password_title"))
            dialog.grab_set()
            dialog.resizable(False, False)
            self.center_window(dialog, 400, 230)
            result = {"password": None, "confirmed": False}
            main_frame = ctk.CTkFrame(dialog)
            main_frame.pack(fill="both", expand=True, padx=20, pady=20)

            ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("auth_required"),
                        font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

            password_entry = ctk.CTkEntry(main_frame, width=300, height=40, show="*",
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
                # Ensure database is initialized
                if self.database is None:
                    db_path = "manageyouraccount"
                    self.database = DatabaseManager(db_path, self.crypto, self.secure_file_manager)
                
                auth_success = self.database.authenticate(result["password"])
                self.auth_guardian.record_login_attempt(auth_success)
                if auth_success:
                    # Set encryption key on secure_file_manager so settings can be read/written
                    self.secure_file_manager.encryption_key = self.database.encryption_key
                    logger.info("Encryption key set on secure_file_manager after authentication in verify_master_password_dialog")
                    return True
                else:
                    self.show_message("error", "invalid_master_password", msg_type="error")
                    if self.auth_guardian.is_locked_out():
                        self.lock_vault()  # Force lock and show screen
                        return False
            except Exception as e:
                logger.error(f"Authentication error in verify_master_password_dialog: {e}")
                self.show_message("error", "auth_failed", msg_type="error")
                return False

    def show_setup_wizard(self):
        if self.is_vault_initialized():
            self.show_message("setup_wizard_title", "vault_not_initialized_error")
            return
        
        self.update_login_button_states()

        # Informational security warning shown when user starts first-time setup.
        try:
            security_msg = (
                "Important security notice:\n\n"
                "Before running this program, ensure your Windows system is free of viruses or malware. "
                "Malicious software can directly compromise your system and your vault despite the use "
                "of advanced encryption mechanisms.\n\n"
                "Please create a long, strong, and unguessable master password to protect your vault."
            )
            messagebox.showinfo("Security Notice", security_msg)
        except Exception:
            logger.exception("Failed to display security notice dialog")
        self.setup_window = ThemedToplevel(self.root)
        self.setup_window.title(self.lang_manager.get_string("setup_wizard_title"))
        
        width, height = 550, 650
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
        
        warning_label = ctk.CTkLabel(
            step1_frame,
            text=self.lang_manager.get_string("master_password_warning"),
            font=ctk.CTkFont(size=12),
            text_color="#FFC107", 
            wraplength=450
        )
        warning_label.pack(pady=(0, 15), padx=20)

        self.setup_full_name_entry = ctk.CTkEntry(
            step1_frame, 
            placeholder_text="Full Name Ex. Hamza Saadi", 
            width=300, height=40
        )
        self.setup_full_name_entry.pack(pady=10)

        self.setup_email_entry = ctk.CTkEntry(
            step1_frame, 
            placeholder_text=self.lang_manager.get_string("email_placeholder"), 
            width=300, height=40
        )
        self.setup_email_entry.pack(pady=10)
        
        password_frame = ctk.CTkFrame(step1_frame, fg_color="transparent")
        password_frame.pack(pady=10)

        self.setup_master_password = ctk.CTkEntry(
            password_frame, 
            placeholder_text=self.lang_manager.get_string("master_password_placeholder"),
            show="*", width=300, height=40
        )
        self.setup_master_password.pack(side="left")

        # --- DISABLE COPY/PASTE FOR SETUP FIELDS ---
        # Applying restrictions to Full Name, Email, and Password fields
        self._block_copy_paste_comprehensive(self.setup_full_name_entry, include_cut=False)
        self._block_copy_paste_comprehensive(self.setup_email_entry, include_cut=False)
        self._block_copy_paste_comprehensive(self.setup_master_password, include_cut=True)
        # -------------------------------------------

        self.toggle_master_password_btn = ctk.CTkButton(
            password_frame,
            text="👁️",
            width=40,
            height=40,
            command=lambda: self.toggle_password_visibility(self.setup_master_password, self.toggle_master_password_btn)
        )
        self.toggle_master_password_btn.pack(side="left", padx=(5, 0))

        def generate_and_fill_password():
            """Generate a random 20-character password and fill the master password field"""
            random_password = self.password_generator.generate_password(length=20)
            self.setup_master_password.delete(0, "end")
            self.setup_master_password.insert(0, random_password)
            self.validate_master_password_realtime()

        self.generate_password_btn = ctk.CTkButton(
            password_frame,
            text="🎲",
            width=40,
            height=40,
            command=generate_and_fill_password,
            fg_color="#3B82F6",
            hover_color="#2563EB"
        )
        self.generate_password_btn.pack(side="left", padx=(5, 0))


        confirm_password_frame = ctk.CTkFrame(step1_frame, fg_color="transparent")
        confirm_password_frame.pack(pady=10)

        self.setup_confirm_password = ctk.CTkEntry(
            confirm_password_frame, 
            placeholder_text=self.lang_manager.get_string("confirm_password_placeholder"),
            show="*", width=300, height=40
        )
        self.setup_confirm_password.pack(side="left")

        # --- DISABLE COPY/PASTE FOR CONFIRM PASSWORD ---
        self._block_copy_paste_comprehensive(self.setup_confirm_password, include_cut=True)
        # -----------------------------------------------

        self.toggle_confirm_password_btn = ctk.CTkButton(
            confirm_password_frame,
            text="👁️",
            width=40,
            height=40,
            command=lambda: self.toggle_password_visibility(self.setup_confirm_password, self.toggle_confirm_password_btn)
        )
        self.toggle_confirm_password_btn.pack(side="left", padx=(5, 0))

        # --- Password Requirements Checklist ---
        checklist_frame = ctk.CTkFrame(step1_frame, fg_color="transparent")
        checklist_frame.pack(pady=10, padx=20, anchor="w")

        self.req_labels = {}
        requirements = {
            "length": self.lang_manager.get_string("password_req_length"),
            "uppercase": self.lang_manager.get_string("password_req_uppercase"),
            "lowercase": self.lang_manager.get_string("password_req_lowercase"),
            "number": self.lang_manager.get_string("password_req_number"),
            "symbol": self.lang_manager.get_string("password_req_symbol"),
        }

        for key, text in requirements.items():
            label = ctk.CTkLabel(checklist_frame, text=f"❌ {text}", text_color="gray", font=ctk.CTkFont(size=12))
            label.pack(anchor="w")
            self.req_labels[key] = label
        
        self.setup_master_password.bind("<KeyRelease>", self.validate_master_password_realtime)


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

        # Add duplicate warning label
        self.duplicate_warning_label = ctk.CTkLabel(
            step2_frame,
            text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#FF4444",
            wraplength=500
        )
        self.duplicate_warning_label.pack(pady=(0, 10))

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

            chk = ctk.CTkCheckBox(question_frame, text=question_text, variable=var,
                                command=lambda idx=i: self.on_question_toggle(idx))
            chk.pack(side="left")

            entry = ctk.CTkEntry(
                question_frame,
                placeholder_text=self.lang_manager.get_string("answer_placeholder"),
                width=300,
                height=30
            )
            entry.pack(side="right")
            
            # Bind key release event for real-time duplicate detection
            entry.bind("<KeyRelease>", lambda e, idx=i: self.check_duplicate_answers())
            
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
                
    def on_question_toggle(self, index):
        """Handle when a question checkbox is toggled"""
        # Clear the entry if checkbox is unchecked
        if not self.security_questions_vars[index].get():
            self.security_questions_entries[index].delete(0, tk.END)
        
        # Check for duplicates after toggle
        self.check_duplicate_answers()

    def check_duplicate_answers(self):
        """Check for duplicate answers in real-time and update UI"""
        # Collect answers from selected questions
        answers = {}
        duplicates = set()
        
        for i, item in enumerate(self.security_questions):
            if item["var"].get():  # Only check selected questions
                answer = item["entry"].get().strip().lower()
                if answer:  # Only check non-empty answers
                    if answer in answers:
                        duplicates.add(answer)
                        answers[answer].append(i)
                    else:
                        answers[answer] = [i]
        
        # Update UI based on duplicates found
        if duplicates:
            duplicate_text = "⚠️ Duplicate answers detected: " + ", ".join(f'"{dup}"' for dup in duplicates)
            self.duplicate_warning_label.configure(text=duplicate_text)
            
            # Highlight duplicate entries with red border
            for answer, indices in answers.items():
                if answer in duplicates:
                    for idx in indices:
                        self.security_questions_entries[idx].configure(border_color="#FF4444")
                else:
                    for idx in indices:
                        self.security_questions_entries[idx].configure(border_color="#3B82F6")
        else:
            self.duplicate_warning_label.configure(text="")
            # Reset all entry borders to normal
            for i, item in enumerate(self.security_questions):
                if item["var"].get():
                    self.security_questions_entries[i].configure(border_color="#3B82F6")

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
            elif not self.validate_email_domain(email):
                self.show_message("error", "invalid_email_domain_error", msg_type="error")
                validation_passed = False
            elif not master_password or master_password != confirm_password:
                self.show_message("error", "passwords_dont_match", msg_type="error")
                validation_passed = False
            elif not self.validate_master_password_realtime():
                self.show_message("error", "password_requirements_not_met", msg_type="error")
                validation_passed = False

        if validation_passed and self.wizard_step < len(self.wizard_frames) - 1:
            self.wizard_step += 1
            self.show_step()

    def validate_email_domain(self, email):
        """Validate that email has one of the allowed domains"""
        allowed_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'yahoo.fr', 'outlook.com']
        
        # Basic email format validation
        if '@' not in email:
            return False
        
        domain = email.split('@')[1].lower()
        
        # Check if domain is in allowed list
        return domain in allowed_domains

    def prev_step(self):
        if self.wizard_step > 0:
            self.wizard_step -= 1
            self.show_step()

    def validate_master_password_realtime(self, event=None):
        password = self.setup_master_password.get()
        
        # Define validation checks
        checks = {
            "length": len(password) >= 16,
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "number": any(c.isdigit() for c in password),
            "symbol": any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
        }

        # Update labels based on checks
        for key, is_met in checks.items():
            if key in self.req_labels:
                label = self.req_labels[key]
                base_text = self.lang_manager.get_string(f"password_req_{key}")
                if is_met:
                    label.configure(text=f"✅ {base_text}", text_color="green")
                else:
                    label.configure(text=f"❌ {base_text}", text_color="gray")
        
        return all(checks.values())

    def toggle_password_visibility(self, entry, button):
        if entry.cget("show") == "*":
            entry.configure(show="")
            button.configure(text="🙈")
        else:
            entry.configure(show="*")
            button.configure(text="👁️")

    def center_window(self, window, width: int, height: int):
        """Center a window on the screen."""
        window.update_idletasks()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")

    def _generate_welcome_message(self, count: int = 1) -> str:
        """
        Return `count` unique security tips (default 1). Tips are full sentences and
        prefixed with 'Security Tip:' for consistent UI display.
        """
        safety_tips: List[str] = [
            "Security Tip: Use a unique, strong password for every account and avoid reusing passwords.",
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
            "Security Tip: Regularly audit third-party app access to your accounts and revoke access that is no longer required.",
            "Security Tip: Be cautious installing browser extensions — only install trusted extensions and review their permissions.",
            "Security Tip: Maintain a separate non-admin account for daily work and reserve an admin account for elevated tasks.",
            "Security Tip: Keep device firmware (router, NAS, IoT) current and change default management ports and credentials.",
            "Security Tip: Verify downloads by checking cryptographic checksums or digital signatures when available.",
            "Security Tip: Use DMARC, DKIM, and SPF on your email domain to reduce email spoofing and phishing impact.",
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
        if not self.validate_master_password_realtime():
            self.show_message("error", "password_requirements_not_met", msg_type="error")
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

        # Check for duplicate answers
        answers = [answer for _, answer in selected_questions]
        if len(answers) != len(set(answers)):
            self.show_message("security_questions_error_title", "duplicate_answers_error", msg_type="error")
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

            def on_closing():
                """
                Handle window close button (X).
                Instead of closing, prompt the user to use the Logout button.
                """
                logger.info("Window close button pressed - Action intercepted")
                
                # Use the custom message box to match the app's theme
                CustomMessageBox(
                    title="Secure Logout Required", 
                    message="For security reasons, please use the red 'Logout' button located in the toolbar to securely close the application.", 
                    msg_type="warning"
                ).show()
            
            # Bind the close event (X button) to the new function
            self.root.protocol("WM_DELETE_WINDOW", on_closing)

            # The tutorial is now started manually from the "About" window.
            # logger.info(f"Tutorial check: tutorial_completed = {self.settings.get('tutorial_completed', False)}")
            # if not self.settings.get('tutorial_completed', False):
            #     logger.info("Showing tutorial window...")
            #     tutorial = TutorialManager(self.root, self.lang_manager)
            #     tutorial.show_tutorial_window()
            #     self.settings['tutorial_completed'] = True
            #     logger.info("Tutorial completed, saving settings...")
            #     self.save_settings_to_file()
            # else:
            #     logger.info("Tutorial already completed, skipping.")

            toolbar = ctk.CTkFrame(self.main_frame, height=70)
            toolbar.pack(fill="x", padx=10, pady=10)
            toolbar.pack_propagate(False)
            
            # Trial/Activation indicator (LEFT SIDE - before title)
            if hasattr(self, 'trial_manager'):
                status = self.trial_manager.get_trial_status()
                if not status['is_activated'] and status['days_remaining'] is not None:
                    trial_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
                    trial_frame.pack(side="left", padx=15, pady=10)
                    
                    days_remaining = status['days_remaining']
                    days_text = f"🕒 {days_remaining} day{'s' if days_remaining != 1 else ''} remaining"
                    
                    # Change color to red if 3 days or less remaining
                    if days_remaining <= 3:
                        text_color = "#EF4444"  # Red color for urgency
                    else:
                        text_color = "#FF9500"  # Orange color for normal trial
                    
                    ctk.CTkLabel(
                        trial_frame,
                        text=days_text,
                        font=ctk.CTkFont(size=14, weight="bold"),
                        text_color=text_color
                    ).pack(anchor="w")
                    
                    ctk.CTkLabel(
                        trial_frame,
                        text="Access will be restricted after trial expires",
                        font=ctk.CTkFont(size=10),
                        text_color="#888888"
                    ).pack(anchor="w", pady=(2, 0))
            
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
        
            # Check if program is activated (for enabling/disabling backup/restore)
            is_activated = False
            if hasattr(self, 'trial_manager'):
                trial_status = self.trial_manager.get_trial_status()
                is_activated = trial_status.get('is_activated', False)
            
            # Professional tooltip message for disabled features
            trial_tooltip_msg = "🔒 Premium Feature\n\nThis feature will be enabled once you activate the full version of the application."
            
            # Add Backup button (before About button) - disabled during trial
            backup_icon = ctk.CTkImage(Image.open("icons/uploadbk.png"), size=(24, 24))
            backup_btn = ctk.CTkButton(
                toolbar,
                text=self.lang_manager.get_string("backup"),
                width=120,
                height=55,
                image=backup_icon,
                compound="left",
                command=self.show_backup_window if is_activated else None,
                font=ctk.CTkFont(size=18),
                state="normal" if is_activated else "disabled",
                fg_color=None if is_activated else ("#888888", "#555555"),
                hover_color=None if is_activated else ("#888888", "#555555")
            )
            backup_btn.pack(side="right", padx=10, pady=8)
            
            # Add tooltip for disabled backup button
            if not is_activated:
                ToolTip(backup_btn, trial_tooltip_msg)
            
            # Add Restore button - disabled during trial
            restore_icon = ctk.CTkImage(Image.open("icons/backup.png"), size=(24, 24))
            restore_btn = ctk.CTkButton(
                toolbar,
                text=self.lang_manager.get_string("restore"),
                width=120,
                height=55,
                image=restore_icon,
                compound="left",
                command=self.show_restore_window if is_activated else None,
                font=ctk.CTkFont(size=18),
                state="normal" if is_activated else "disabled",
                fg_color=None if is_activated else ("#888888", "#555555"),
                hover_color=None if is_activated else ("#888888", "#555555")
            )
            restore_btn.pack(side="right", padx=10, pady=8)
            
            # Add tooltip for disabled restore button
            if not is_activated:
                ToolTip(restore_btn, trial_tooltip_msg)
            
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
            
            # Add Logout button (RED for safety/logout action)
            logout_icon = ctk.CTkImage(Image.open("icons/logout.png"), size=(24, 24))
            ctk.CTkButton(
                toolbar,
                text="Logout",
                width=120,
                height=55,
                image=logout_icon,
                compound="left",
                command=self.secure_logout,
                font=ctk.CTkFont(size=18),
                fg_color="#D32F2F",
                hover_color="#B71C1C"
            ).pack(side="right", padx=10, pady=8)

            content_frame = ctk.CTkFrame(self.main_frame)
            content_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            self.create_sidebar(content_frame)
            self.main_panel = ctk.CTkFrame(content_frame)
            self.main_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)
            
            self.show_passwords()
        
            # DEFERRED: Start expensive operations after UI is visible
            # Use root.after to schedule these tasks for later execution
            def deferred_startup_tasks():
                """Heavy operations deferred to after UI is shown"""
                logger.info("Starting deferred startup tasks...")
                
                try:
                    # Initialize password reminder (now with deferred start)
                    self.password_reminder = PasswordReminder(self.database, self)
                    self.password_reminder.start()  # Now starts the background thread
                    logger.info("Password reminder initialized and started")
                except Exception as e:
                    logger.error(f"Error initializing password reminder: {e}")
                
                try:
                    # Update expired passwords count
                    self.update_expired_passwords_count()
                    logger.info("Expired passwords count updated")
                except Exception as e:
                    logger.error(f"Error updating expired passwords: {e}")
                
                logger.info("Deferred startup tasks completed")
            
            # Schedule deferred tasks after a short delay to allow UI to render
            # Using a longer delay (500ms) to ensure UI is fully visible before heavy work
            self.root.after(500, deferred_startup_tasks)    
    
    # 5. Add the backup window method
    def show_backup_window(self):
        """Show backup creation window"""
        if not self.backup_manager:
            self.show_message("error", "Backup manager not initialized", msg_type="error")
            return
        
        # Verify master password first
        if not self.verify_master_password_dialog():
            return
        
        backup_window = ThemedToplevel(self.root)
        backup_window.title("Create Backup")
        backup_window.grab_set()
        backup_window.resizable(False, False)
        self.center_window(backup_window, 700, 850)
        
        # Main container
        main_frame = ctk.CTkFrame(backup_window)
        main_frame.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color=("#2E3440", "#1E1E1E"), height=80)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=20, pady=15)
        
        ctk.CTkLabel(header_content, text="💾 Create Backup",
                    font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w")
        
        ctk.CTkLabel(header_content, text="Secure your data with encrypted backups",
                    font=ctk.CTkFont(size=12), text_color="#B0B0B0").pack(anchor="w", pady=(5, 0))
        
        # Content area
        content_frame = ctk.CTkScrollableFrame(main_frame)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Backup Type Selection
        type_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        type_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(type_frame, text="📦 Backup Type",
                    font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(0, 10))
        
        backup_type_var = tk.StringVar(value="full")
        
        type_options = [
            ("full", "🔒 Full Backup", 
            "Complete vault including all accounts, settings, and security data.\n\n"
            "Remember: If you select this option, the program will create a full backup. "
            "When you restore it later, the backed-up passwords, settings and accounts will "
            "replace the current data."),
            ("accounts_only", "👤 Accounts Only (Recommended)", 
            "Only account credentials and metadata - faster and more secure")
        ]

        for value, title, description in type_options:
            option_frame = ctk.CTkFrame(type_frame, fg_color=("gray90", "gray20"), corner_radius=10)
            option_frame.pack(fill="x", pady=5)
            
            radio = ctk.CTkRadioButton(option_frame, text="", variable=backup_type_var, value=value)
            radio.pack(side="left", padx=15, pady=15)
            
            text_frame = ctk.CTkFrame(option_frame, fg_color="transparent")
            text_frame.pack(side="left", fill="x", expand=True, pady=15, padx=(0, 15))
            
            ctk.CTkLabel(text_frame, text=title, font=ctk.CTkFont(size=14, weight="bold"),
                        anchor="w").pack(anchor="w", fill="x")
            ctk.CTkLabel(text_frame, text=description, font=ctk.CTkFont(size=11),
                        text_color="gray", anchor="w", justify="left", wraplength=450).pack(anchor="w", fill="x", pady=(2, 0))
                                
        # Description
        desc_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        desc_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(desc_frame, text="📝 Description (Optional)",
                    font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(0, 10))
        
        description_text = ctk.CTkTextbox(desc_frame, height=80)
        description_text.pack(fill="x")
        description_text.insert("1.0", f"Manual backup - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
        # Backup History
        history_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        history_frame.pack(fill="x", pady=(0, 20))
        
        history_header = ctk.CTkFrame(history_frame, fg_color="transparent")
        history_header.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(history_header, text="📜 Recent Backups",
                    font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        
        ctk.CTkButton(history_header, text="🔄 Refresh", width=80, height=30,
                    command=lambda: update_backup_list()).pack(side="right")
        
        # Backup list
        backup_list_frame = ctk.CTkScrollableFrame(history_frame, height=200,
                                                fg_color=("gray90", "gray20"))
        backup_list_frame.pack(fill="both", expand=True)
                
        def update_backup_list():
            # Clear existing items
            for widget in backup_list_frame.winfo_children():
                widget.destroy()
            
            backups = self.backup_manager.get_backup_list()
            
            if not backups:
                ctk.CTkLabel(backup_list_frame, text="No backups found",
                            text_color="gray").pack(pady=20)
                return
            
            for backup in backups[:5]:  # Show only 5 most recent
                backup_item = ctk.CTkFrame(backup_list_frame, fg_color=("gray85", "gray25"),
                                        corner_radius=8)
                backup_item.pack(fill="x", pady=5, padx=5)
                
                info_frame = ctk.CTkFrame(backup_item, fg_color="transparent")
                info_frame.pack(fill="x", padx=15, pady=10)
                
                # Format timestamp
                try:
                    timestamp = datetime.fromisoformat(backup['timestamp'])
                    time_str = timestamp.strftime("%Y-%m-%d %H:%M")
                except:
                    time_str = backup.get('timestamp', 'Unknown')
                
                # Backup info
                ctk.CTkLabel(info_frame, text=f"📅 {time_str}",
                            font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")
                
                details = f"Type: {backup.get('backup_type', 'unknown')} | "
                details += f"Accounts: {backup.get('accounts_count', 0)} | "
                details += f"Size: {backup.get('file_size', 0) / (1024*1024):.2f} MB"
                
                ctk.CTkLabel(info_frame, text=details, font=ctk.CTkFont(size=10),
                            text_color="gray").pack(anchor="w")
        
        update_backup_list()
        
        # Status label
        status_label = ctk.CTkLabel(content_frame, text="", font=ctk.CTkFont(size=12))
        status_label.pack(pady=10)
        
        # Progress indicator
        progress_bar = ctk.CTkProgressBar(content_frame, mode='indeterminate')
        
        # Button frame
        button_frame = ctk.CTkFrame(main_frame, fg_color=("gray90", "gray15"), height=70)
        button_frame.pack(fill="x", padx=0, pady=0, side="bottom")
        button_frame.pack_propagate(False)
        
        buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        buttons.pack(fill="both", expand=True, padx=20, pady=15)
        
        def create_backup_action():
            backup_type = backup_type_var.get()
            description = description_text.get("1.0", tk.END).strip()
            
            # Show progress
            status_label.configure(text="Creating backup...", text_color="#3B82F6")
            progress_bar.pack(pady=5)
            progress_bar.start()
            backup_window.update()
            
            def perform_backup():
                success, message, backup_path = self.backup_manager.create_backup(
                    backup_type=backup_type,
                    description=description
                )
                
                # Update UI on main thread
                self.root.after(0, lambda: finish_backup(success, message))
            
            def finish_backup(success, message):
                progress_bar.stop()
                progress_bar.pack_forget()
                
                if success:
                    status_label.configure(text="✅ Backup created successfully!",
                                        text_color="#10B981")
                    update_backup_list()
                    self.show_message("success", message)
                else:
                    status_label.configure(text="❌ Backup failed", text_color="#EF4444")
                    self.show_message("error", message, msg_type="error")
            
            # Run backup in background thread
            threading.Thread(target=perform_backup, daemon=True).start()
        
        ctk.CTkButton(buttons, text="Cancel", command=backup_window.destroy,
                    width=120, height=40,
                    fg_color=("gray70", "gray30"),
                    hover_color=("gray60", "gray40")).pack(side="left")
        
        ctk.CTkButton(buttons, text="💾 Create Backup", command=create_backup_action,
                    width=150, height=40,
                    font=ctk.CTkFont(size=14, weight="bold"),
                    fg_color="#2B6CB0",
                    hover_color="#2563EB").pack(side="right")

    # 6. Add the restore window method
    def show_restore_window(self):
        """Show backup restore window"""
        if not self.backup_manager:
            self.show_message("error", "Backup manager not initialized", msg_type="error")
            return
        
        # Verify master password first
        if not self.verify_master_password_dialog():
            return
        
        restore_window = ThemedToplevel(self.root)
        restore_window.title("Restore Backup")
        restore_window.grab_set()
        restore_window.resizable(False, False)
        self.center_window(restore_window, 700, 750)
        
        # Main container
        main_frame = ctk.CTkFrame(restore_window)
        main_frame.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color=("#2E3440", "#1E1E1E"), height=80)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=20, pady=15)
        
        ctk.CTkLabel(header_content, text="🔄 Restore Backup",
                    font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w")
        
        ctk.CTkLabel(header_content, text="Restore your vault from a previous backup",
                    font=ctk.CTkFont(size=12), text_color="#B0B0B0").pack(anchor="w", pady=(5, 0))
        
        # Content area
        content_frame = ctk.CTkScrollableFrame(main_frame)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Warning message
        warning_frame = ctk.CTkFrame(content_frame, fg_color=("#FFE5E5", "#4A2020"), corner_radius=10)
        warning_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(warning_frame, text="⚠️ Important Warning",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color="#EF4444").pack(anchor="w", padx=15, pady=(10, 5))
        
        ctk.CTkLabel(warning_frame,
                    text="Restoring a backup will replace your current data. "
                        "Your current data will not be backed up before restoration; please check before proceeding.",
                    font=ctk.CTkFont(size=11),
                    text_color="#666666",
                    wraplength=600,
                    justify="left").pack(anchor="w", padx=15, pady=(0, 10))
        
        # Backup selection
        select_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        select_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(select_frame, text="📦 Select Backup to Restore",
                    font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(0, 10))
        
        # Backup list
        selected_backup = {"backup": None}
        backup_list_frame = ctk.CTkScrollableFrame(select_frame, height=300,
                                                fg_color=("gray90", "gray20"))
        backup_list_frame.pack(fill="both", expand=True)
        
        def update_backup_list():
            # Clear existing items
            for widget in backup_list_frame.winfo_children():
                widget.destroy()
            
            backups = self.backup_manager.get_backup_list()
            
            if not backups:
                ctk.CTkLabel(backup_list_frame, text="No backups found\n\n"
                            "You can import a backup file using the 'Import Backup' button",
                            text_color="gray").pack(pady=40)
                return
            
            for backup in backups:
                backup_item = ctk.CTkFrame(backup_list_frame, fg_color=("gray85", "gray25"),
                                        corner_radius=8)
                backup_item.pack(fill="x", pady=5, padx=5)
                
                item_content = ctk.CTkFrame(backup_item, fg_color="transparent")
                item_content.pack(fill="x", padx=15, pady=12)
                
                # Format timestamp
                try:
                    timestamp = datetime.fromisoformat(backup['timestamp'])
                    time_str = timestamp.strftime("%Y-%m-%d %H:%M")
                except:
                    time_str = backup.get('timestamp', 'Unknown')
                
                # Left side - info
                info_frame = ctk.CTkFrame(item_content, fg_color="transparent")
                info_frame.pack(side="left", fill="x", expand=True)
                
                ctk.CTkLabel(info_frame, text=f"📅 {time_str}",
                            font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w")
                
                details = f"Type: {backup.get('backup_type', 'unknown')} | "
                details += f"Accounts: {backup.get('accounts_count', 0)} | "
                details += f"Size: {backup.get('file_size', 0) / (1024*1024):.2f} MB"
                
                ctk.CTkLabel(info_frame, text=details, font=ctk.CTkFont(size=11),
                            text_color="gray").pack(anchor="w", pady=(2, 0))
                
                # Description if available
                if backup.get('description'):
                    ctk.CTkLabel(info_frame, text=backup['description'],
                            font=ctk.CTkFont(size=10, slant="italic"),
                            text_color="gray").pack(anchor="w", pady=(2, 0))
                
                # Right side - actions
                actions_frame = ctk.CTkFrame(item_content, fg_color="transparent")
                actions_frame.pack(side="right")
                
                def make_select_wrapper(b):
                    def select_action():
                        selected_backup["backup"] = b
                        # Visual feedback - highlight selected
                        for widget in backup_list_frame.winfo_children():
                            widget.configure(fg_color=("gray85", "gray25"))
                        backup_item.configure(fg_color=("#D4E6FF", "#2B4A6B"))
                    return select_action
                
                ctk.CTkButton(actions_frame, text="Select",
                            command=make_select_wrapper(backup),
                            width=80, height=30).pack(side="left", padx=5)
                
                def make_verify_wrapper(b):
                    def verify_action():
                        from pathlib import Path
                        backup_path = Path(b['backup_path'])
                        success, message = self.backup_manager.restore_backup(
                            backup_path, verify_only=True
                        )
                        if success:
                            self.show_message("success", message)
                        else:
                            self.show_message("error", message, msg_type="error")
                    return verify_action
                
                ctk.CTkButton(actions_frame, text="Verify",
                            command=make_verify_wrapper(backup),
                            width=80, height=30,
                            fg_color=("gray70", "gray30")).pack(side="left")
        
        update_backup_list()
        
        # Import backup option
        import_frame = ctk.CTkFrame(select_frame, fg_color="transparent")
        import_frame.pack(fill="x", pady=(10, 0))
        
        def import_backup():
            from tkinter import filedialog
            file_path = filedialog.askopenfilename(
                title="Select Backup File",
                filetypes=[("Backup Files", "*.svbak"), ("All Files", "*.*")]
            )
            
            if file_path:
                from pathlib import Path
                selected_backup["backup"] = {
                    'backup_path': file_path,
                    'timestamp': 'Imported',
                    'backup_type': 'unknown',
                    'accounts_count': 0,
                    'file_size': Path(file_path).stat().st_size
                }
                
                status_label.configure(text=f"✅ Backup imported: {Path(file_path).name}",
                                    text_color="#10B981")
        
        ctk.CTkButton(import_frame, text="📁 Import Backup File",
                    command=import_backup,
                    width=200, height=35).pack()
        
        # Status label
        status_label = ctk.CTkLabel(content_frame, text="", font=ctk.CTkFont(size=12))
        status_label.pack(pady=10)
        
        # Progress indicator
        progress_bar = ctk.CTkProgressBar(content_frame, mode='indeterminate')
        
        # Button frame
        button_frame = ctk.CTkFrame(main_frame, fg_color=("gray90", "gray15"), height=70)
        button_frame.pack(fill="x", padx=0, pady=0, side="bottom")
        button_frame.pack_propagate(False)
        
        buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        buttons.pack(fill="both", expand=True, padx=20, pady=15)
        
        def restore_action():
            if not selected_backup["backup"]:
                status_label.configure(text="⚠️ Please select a backup first",
                                    text_color="#F59E0B")
                return
            
            # Confirmation dialog
            result = self.show_message(
                "restore_confirm_title",
                "This will replace your current data. Continue?",
                ask="yesno"
            )
            
            if not result:
                return
            
            # Show progress
            status_label.configure(text="Restoring backup...", text_color="#3B82F6")
            progress_bar.pack(pady=5)
            progress_bar.start()
            restore_window.update()
            
            def perform_restore():
                from pathlib import Path
                backup_path = Path(selected_backup["backup"]['backup_path'])
                success, message = self.backup_manager.restore_backup(backup_path)
                
                # Update UI on main thread
                self.root.after(0, lambda: finish_restore(success, message))
            
            def finish_restore(success, message):
                progress_bar.stop()
                progress_bar.pack_forget()
                
                if success:
                    status_label.configure(text="✅ Restore completed!", text_color="#10B981")
                    self.show_message("success", message)
                    restore_window.destroy()
                    # Suggest restart
                    if self.show_message("restart_title", "Restart application now?", ask="yesno"):
                        self.restart_program()
                else:
                    status_label.configure(text="❌ Restore failed", text_color="#EF4444")
                    self.show_message("error", message, msg_type="error")
            
            # Run restore in background thread
            threading.Thread(target=perform_restore, daemon=True).start()
        
        ctk.CTkButton(buttons, text="Cancel", command=restore_window.destroy,
                    width=120, height=40,
                    fg_color=("gray70", "gray30"),
                    hover_color=("gray60", "gray40")).pack(side="left")
        
        ctk.CTkButton(buttons, text="🔄 Restore Backup", command=restore_action,
                    width=150, height=40,
                    font=ctk.CTkFont(size=14, weight="bold"),
                    fg_color="#EF4444",
                    hover_color="#DC2626").pack(side="right")


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
        icon_update     = ctk.CTkImage(Image.open("icons/upload.png"), size=(24, 24))

        top_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        top_frame.pack(side="top", fill="x", anchor="n")

        sidebar_configs = [
            (self.lang_manager.get_string("your_accounts"), icon_accounts, self.show_passwords),
            (self.lang_manager.get_string("password_generator"), icon_generator, self.show_password_generator),
            (self.lang_manager.get_string("security_report"), icon_report, self.show_security_report),
        ]

        for text, icon, command in sidebar_configs:
            btn = ctk.CTkButton(
                top_frame,
                text=text,
                image=icon,
                compound="left",
                anchor="w",
                command=lambda cmd=command, txt=text: self.handle_sidebar_click(cmd, txt),
                height=60,
                font=ctk.CTkFont(size=18),
                corner_radius=10,
                fg_color=("gray75", "gray25"),
                hover_color=("gray70", "gray30")
            )
            btn.pack(fill="x", padx=15, pady=10)
            self.sidebar_buttons.append(btn)
            
        # Add programmer credits at the bottom of the sidebar
        credits_label = ctk.CTkLabel(
            self.sidebar,
            text="This program was developed by Hamza Saadi from EAGLESHADOW ©2025",
            font=ctk.CTkFont(size=10),
            text_color="gray",
            wraplength=250
        )
        credits_label.pack(side="bottom", fill="x", padx=15, pady=(10, 20))
        
        update_config = (self.lang_manager.get_string("check_for_updates"), icon_update, self.show_update_checker)
        text, icon, command = update_config
        btn = ctk.CTkButton(
            self.sidebar,
            text=text,
            image=icon,
            compound="left",
            anchor="w",
            command=lambda cmd=command, txt=text: self.handle_sidebar_click(cmd, txt),
            height=60,
            font=ctk.CTkFont(size=18),
            corner_radius=10,
            fg_color=("gray75", "gray25"),
            hover_color=("gray70", "gray30")
        )
        btn.pack(side="bottom", fill="x", padx=15, pady=10)
        self.sidebar_buttons.append(btn)

        settings_config = (self.lang_manager.get_string("settings"), settings, self.show_settings)
        text, icon, command = settings_config
        btn = ctk.CTkButton(
            self.sidebar,
            text=text,
            image=icon,
            compound="left",
            anchor="w",
            command=lambda cmd=command, txt=text: self.handle_sidebar_click(cmd, txt),
            height=60,
            font=ctk.CTkFont(size=18),
            corner_radius=10,
            fg_color=("gray75", "gray25"),
            hover_color=("gray70", "gray30")
        )
        btn.pack(side="bottom", fill="x", padx=15, pady=(20, 10))
        self.sidebar_buttons.append(btn)
        
        activation_btn = ctk.CTkButton(
            self.sidebar,
            text="Activation",
            image=activation_icon,
            compound="left",
            anchor="w",
            command=lambda: self.handle_sidebar_click(self.show_activation_modal, "Activation"),
            height=60,
            font=ctk.CTkFont(size=18),
            corner_radius=10,
            fg_color=("#10B981", "#059669"),
            hover_color=("#059669", "#047857")
        )
        activation_btn.pack(side="bottom", fill="x", padx=15, pady=10)
        self.sidebar_buttons.append(activation_btn)
        
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
            if self.password_reminder:
                self.password_reminder.stop()
            if hasattr(self, 'tamper_manager'):
                self.tamper_manager.update_shutdown_status('SHUTDOWN_CLEAN')
            if self.secure_file_manager and self.authenticated:
                logger.info("Syncing files to secure storage before lock...")
                
                if not self.secure_file_manager.perform_integrity_check():
                    logger.error("Integrity check failed during vault lock")
                    self.show_message("Security Warning", "File integrity check failed.", msg_type="warning")
                
                # Ensure all database changes are flushed to disk before syncing
                if self.database:
                    self.database._checkpoint_databases()
                self.secure_file_manager.sync_all_files()
                self.secure_file_manager.cleanup_temp_files()
                logger.info("Temporary files cleaned up")
            self.authenticated = False
            self.database = None
            self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)  # Re-enable closing
            self.show_login_screen()
            
            logger.info("Vault locked successfully")
            
        except Exception as e:
            logger.error(f"Error during vault lock: {e}")
            self.authenticated = False
            self.database = None
            self.show_login_screen()

    def reset_inactivity_timer(self, event=None):
        # Cancel existing timers
        if self.inactivity_timer:
            self.root.after_cancel(self.inactivity_timer)
        if self.inactivity_warning_timer:
            self.root.after_cancel(self.inactivity_warning_timer)
        # Set the warning timer (2 minutes before logout)
        self.inactivity_warning_timer = self.root.after(self.INACTIVITY_WARNING_TIMEOUT, self._send_inactivity_warning)
        # Set the logout timer
        self.inactivity_timer = self.root.after(self.INACTIVITY_TIMEOUT, self.force_logout)

    def _send_inactivity_warning(self):
        """Send a Windows notification warning about imminent auto-logout."""
        logger.info("Sending inactivity warning notification (2 minutes until auto-logout).")
        try:
            from notification_manager import show_system_notification_fallback
            show_system_notification_fallback(
                "SecureVault Pro - Inactivity Warning",
                "The application will close in 2 minutes due to inactivity. Move your mouse or press a key to stay logged in."
            )
        except Exception as e:
            logger.error(f"Failed to send inactivity warning notification: {e}")

    def force_logout(self):
        logger.info("Logging out due to inactivity.")
        self.lock_vault()
        self.root.quit()

        
    def show_loading_main_ui(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        loading_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        loading_frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(loading_frame, text="Loading your vault, please wait...", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        progress_bar = ctk.CTkProgressBar(loading_frame, mode='indeterminate')
        progress_bar.pack(pady=10, padx=50)
        progress_bar.start()
    
    def run(self):
        try:
            self.root.mainloop()
        finally:
            # Stop trial monitoring
            if hasattr(self, 'trial_manager') and self.trial_manager:
                logger.info("Stopping trial monitoring")
                self.trial_manager.stop_monitoring()
            
            # Rest of cleanup...
            logger.info("Application shutting down")
            asyncio_manager.stop()
            
            if self.secure_file_manager:
                logger.info("Performing final sync and cleanup...")
                try:
                    if self.authenticated:
                        self.secure_file_manager.sync_all_files()
                    self.secure_file_manager.cleanup_temp_files()
                    logger.info("Secure cleanup completed")
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")
            
            # Run cleanup in a background thread with timeout
            import threading
            cleanup_thread = threading.Thread(target=shutdown_cleanup, daemon=True)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            cleanup_thread.join(timeout=5.0)  # Wait max 5 seconds for cleanup
            
            if cleanup_thread.is_alive():
                logger.warning("Cleanup thread did not finish within timeout, continuing shutdown anyway")

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

    def show_settings(self, parent_window=None):
            if parent_window:
                parent_window.destroy()

            settings_window = ThemedToplevel(self.root)
            settings_window.title(self.lang_manager.get_string("settings"))
            settings_window.grab_set()
            settings_window.resizable(False, False)
            self.center_window(settings_window, 720, 710)
            
            # Store reference to settings window for closing on successful changes
            self.settings_window = settings_window
            
            container = ctk.CTkFrame(settings_window)
            container.pack(fill="both", expand=True, padx=20, pady=20)
            
            # Header section with modern styling
            header = ctk.CTkFrame(container, fg_color=("#2E3440", "#1E1E1E"), height=90)
            header.pack(fill="x", padx=0, pady=(0, 10))
            header.pack_propagate(False)
            
            header_content = ctk.CTkFrame(header, fg_color="transparent")
            header_content.pack(fill="both", expand=True, padx=20, pady=15)
            
            ctk.CTkLabel(header_content, text=self.lang_manager.get_string("security_settings_title"), 
                        font=ctk.CTkFont(size=26, weight="bold")).pack(anchor="w")
            
            ctk.CTkLabel(header_content, text="Manage your security and privacy settings", 
                        font=ctk.CTkFont(size=12), text_color="#B0B0B0").pack(anchor="w")
            
            # Content area (regular frame instead of scrollable)
            content_frame = ctk.CTkFrame(container, fg_color="transparent")
            content_frame.pack(fill="both", expand=True)
            
            # License Status Section
            license_frame = ctk.CTkFrame(content_frame, fg_color=("#2E3440", "#1E1E1E"), corner_radius=12)
            license_frame.pack(fill="x", pady=(0, 15))
            
            license_content = ctk.CTkFrame(license_frame, fg_color="transparent")
            license_content.pack(fill="x", padx=20, pady=15)
            
            # Get license status
            if hasattr(self, 'trial_manager'):
                activation_info = self.trial_manager.get_activation_info()
                is_activated = activation_info.get('is_activated', False)
                
                if is_activated:
                    # Get Windows username
                    user_name = "User"
                    try:
                        # Get Windows username from environment variable
                        user_name = os.getenv('USERNAME') or os.getenv('USER') or "User"
                    except Exception as e:
                        logger.error(f"Failed to retrieve Windows username: {e}")
                    
                    license_status_text = f"Activated - {user_name}"
                    license_status_color = "#10B981"
                    license_icon = "✅"
                else:
                    license_status_text = "Pro Trial"
                    license_status_color = "#F59E0B"
                    license_icon = "🕒"
                    
                    # Add days remaining info
                    days_remaining = activation_info.get('days_remaining', 0)
                    if days_remaining is not None:
                        license_status_text += f" ({days_remaining} day{'s' if days_remaining != 1 else ''} remaining)"
            else:
                license_status_text = "License information unavailable"
                license_status_color = "gray"
                license_icon = "ℹ️"
            
            # License status label
            ctk.CTkLabel(
                license_content,
                text="License Status:",
                font=ctk.CTkFont(size=14, weight="bold"),
                anchor="w"
            ).pack(anchor="w", pady=(0, 5))
            
            status_display = ctk.CTkLabel(
                license_content,
                text=f"{license_icon} {license_status_text}",
                font=ctk.CTkFont(size=15),
                text_color=license_status_color,
                anchor="w"
            )
            status_display.pack(anchor="w")
            
            password_frame = ctk.CTkFrame(content_frame, fg_color=("#2E3440", "#1E1E1E"), corner_radius=12)
            password_frame.pack(fill="x", pady=10)
            
            ctk.CTkLabel(password_frame, text=self.lang_manager.get_string("master_password_label"), 
                        font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(15, 10))
            
            # Change Master Password button - disabled during trial
            change_pwd_btn = ctk.CTkButton(
                password_frame, 
                text=self.lang_manager.get_string("change_master_password_button"),
                command=self.change_master_password_dialog if is_activated else None,
                height=40,
                state="normal" if is_activated else "disabled",
                fg_color=None if is_activated else ("#888888", "#555555"),
                hover_color=None if is_activated else ("#888888", "#555555")
            )
            change_pwd_btn.pack(pady=10)
            
            # Add tooltip for disabled button
            if not is_activated:
                trial_tooltip_msg = "🔒 Premium Feature\n\nThis feature will be enabled once you activate the full version of the application."
                ToolTip(change_pwd_btn, trial_tooltip_msg)

            tfa_frame = ctk.CTkFrame(content_frame, fg_color=("#2E3440", "#1E1E1E"), corner_radius=12)
            tfa_frame.pack(fill="x", pady=10)

            ctk.CTkLabel(tfa_frame, text=self.lang_manager.get_string("two_factor_auth_title"), 
                        font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(15, 10))

            ctk.CTkLabel(tfa_frame, text=self.lang_manager.get_string("two_factor_auth_description"),
                        font=ctk.CTkFont(size=12), wraplength=600, justify="left").pack(pady=5, padx=10)

            # Show 2FA status
            if hasattr(self, 'auth_guardian') and self.auth_guardian and self.auth_guardian.is_tfa_enabled():
                status_label = ctk.CTkLabel(tfa_frame, text=self.lang_manager.get_string("two_factor_auth_enabled"),
                            font=ctk.CTkFont(size=14, weight="bold"), text_color="#00FF00")
                status_label.pack(pady=5)
                ctk.CTkButton(tfa_frame, text=self.lang_manager.get_string("disable_2fa_button"),
                            command=self.disable_2fa_dialog, height=40, fg_color="#FF4444",
                            hover_color="#CC0000").pack(pady=10)
            else:
                status_label = ctk.CTkLabel(tfa_frame, text=self.lang_manager.get_string("two_factor_auth_disabled"),
                            font=ctk.CTkFont(size=14), text_color="#FFAA00")
                status_label.pack(pady=5)
                ctk.CTkButton(tfa_frame, text=self.lang_manager.get_string("enable_2fa_button"),
                            command=self.enable_2fa_dialog, height=40).pack(pady=10)

            timeout_frame = ctk.CTkFrame(content_frame, fg_color=("#2E3440", "#1E1E1E"), corner_radius=12)
            timeout_frame.pack(fill="x", pady=10)

            ctk.CTkLabel(timeout_frame, text=self.lang_manager.get_string("auto_logout_title"),
                        font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(15, 10))

            ctk.CTkLabel(timeout_frame, text=self.lang_manager.get_string("auto_logout_message"),
                        font=ctk.CTkFont(size=12)).pack(pady=10)        

    def show_about_dialog(self):
        about_dialog = ThemedToplevel(self.root)
        about_dialog.title(self.lang_manager.get_string("about_dialog_title"))
        about_dialog.resizable(False, False)
        about_dialog.grab_set()
        self.center_window(about_dialog, 1000, 600)

        main_frame = ctk.CTkFrame(about_dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("about_slogan"), font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=(0, 15))

        about_text = self.lang_manager.get_string("about_text")
        
        version_label = ctk.CTkLabel(main_frame, text=f"Version: {self.version_data.get('version', 'N/A')}", font=ctk.CTkFont(size=12, weight="bold"))
        version_label.pack(pady=(0, 10))

        textbox = ctk.CTkTextbox(main_frame, wrap="word", height=380, font=ctk.CTkFont(size=14))
        textbox.pack(fill="both", expand=True, pady=10)
        textbox.insert("1.0", about_text)
        textbox.configure(state="disabled")

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=(15, 0))

        tutorial_button = ctk.CTkButton(button_frame, text="Tutorial", command=lambda: self.show_tutorial(about_dialog), width=100)
        tutorial_button.pack(side="left", padx=10)

        close_button = ctk.CTkButton(button_frame, text=self.lang_manager.get_string("close_button"), command=about_dialog.destroy, width=100)
        close_button.pack(side="right", padx=10)

    def show_tutorial(self, about_dialog=None):
        if about_dialog:
            about_dialog.destroy()
        logger.info("Showing tutorial window from About dialog...")
        tutorial = TutorialManager(self.root, self.lang_manager)
        tutorial.show_tutorial_window()
        # Mark tutorial as completed if it's the first time
        if not self.settings.get('tutorial_completed', False):
            self.auth_guardian.update_setting('tutorial_completed', True)
            self.settings['tutorial_completed'] = True
            logger.info("Tutorial marked as completed.")



    def change_master_password_dialog(self):
        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("change_master_password_dialog_title"))
        dialog.resizable(False, False)
        dialog.grab_set()
        self.center_window(dialog, 450, 530)
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("change_master_password_icon_title"),
                    font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        # Current Password with toggle button
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("current_password_label"), 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        current_password_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        current_password_frame.pack(padx=20, pady=(0, 10))
        current_entry = ctk.CTkEntry(current_password_frame, placeholder_text=self.lang_manager.get_string("current_password_placeholder"),
                                    show="*", width=300, height=40)
        current_entry.pack(side="left", padx=(0, 5))
        
        current_toggle_btn = ctk.CTkButton(
            current_password_frame,
            text="👁️",
            width=40,
            height=40,
            command=lambda: self.toggle_password_visibility(current_entry, current_toggle_btn)
        )
        current_toggle_btn.pack(side="left")
        
        # New Password with toggle button
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("new_password_label"),
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        new_password_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        new_password_frame.pack(padx=20, pady=(0, 10))
        new_entry = ctk.CTkEntry(new_password_frame, placeholder_text=self.lang_manager.get_string("new_password_placeholder"),
                                show="*", width=300, height=40)
        new_entry.pack(side="left", padx=(0, 5))
        
        new_toggle_btn = ctk.CTkButton(
            new_password_frame,
            text="👁️",
            width=40,
            height=40,
            command=lambda: self.toggle_password_visibility(new_entry, new_toggle_btn)
        )
        new_toggle_btn.pack(side="left")
        
        # Confirm Password with toggle button
        ctk.CTkLabel(main_frame, text=self.lang_manager.get_string("confirm_new_password_label"),
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        confirm_password_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        confirm_password_frame.pack(padx=20, pady=(0, 15))
        confirm_entry = ctk.CTkEntry(confirm_password_frame, placeholder_text=self.lang_manager.get_string("confirm_new_password_placeholder"),
                                    show="*", width=300, height=40)
        confirm_entry.pack(side="left", padx=(0, 5))
        
        confirm_toggle_btn = ctk.CTkButton(
            confirm_password_frame,
            text="👁️",
            width=40,
            height=40,
            command=lambda: self.toggle_password_visibility(confirm_entry, confirm_toggle_btn)
        )
        confirm_toggle_btn.pack(side="left")
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
                
                # CRITICAL: Update auth_guardian's encryption key with the new key
                # This ensures 2FA and other settings remain encrypted correctly after password change
                if hasattr(self, 'auth_guardian') and self.auth_guardian and self.database.encryption_key:
                    logger.info("Updating auth_guardian encryption key after password change...")
                    self.auth_guardian._settings_manager.encryption_key = self.database.encryption_key
                    # Force a save of settings with the new encryption key to ensure they're properly persisted
                    if self.auth_guardian._save_state():
                        logger.info("Auth guardian settings saved with new encryption key")
                        # Sync settings to secure storage immediately to ensure they persist
                        if self.secure_file_manager:
                            logger.info("Syncing updated settings to secure storage...")
                            if self.secure_file_manager.sync_all_files():
                                logger.info("Settings synced to secure storage successfully")
                            else:
                                logger.warning("Failed to sync settings to secure storage")
                    else:
                        logger.warning("Failed to save auth guardian settings with new encryption key")
                
                # Close settings window if open
                if hasattr(self, 'settings_window') and self.settings_window and self.settings_window.winfo_exists():
                    self.settings_window.destroy()
                
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


    def enable_2fa_dialog(self):
        """Dialog to enable Two-Factor Authentication."""
        try:
            # Try to import qrcode
            try:
                import qrcode
                QRCODE_AVAILABLE = True
            except ImportError:
                QRCODE_AVAILABLE = False
            
            if not hasattr(self, 'auth_guardian') or not self.auth_guardian:
                self.show_message("error", "2fa_not_configured", msg_type="error")
                return
            
            # Check if pyotp is available
            from auth_guardian import PYOTP_AVAILABLE
            if not PYOTP_AVAILABLE:
                self.show_message("error", "2fa_library_missing", msg_type="error")
                return
            
            if not QRCODE_AVAILABLE:
                self.show_message("error", "2fa_library_missing", msg_type="error")
                return
            
            # Generate a new TOTP secret
            secret = self.auth_guardian.generate_tfa_secret()
            
            # Create setup dialog with proper sizing
            setup_dialog = ThemedToplevel(self.root)
            setup_dialog.title(self.lang_manager.get_string("2fa_setup_title"))
            setup_dialog.grab_set()
            setup_dialog.resizable(False, False)
            self.center_window(setup_dialog, 600, 635)  # Optimized height
            
            # Main container
            main_container = ctk.CTkFrame(setup_dialog, fg_color="transparent")
            main_container.pack(fill="both", expand=True)
            
            # Header frame
            header_frame = ctk.CTkFrame(main_container, fg_color=("#2E3440", "#1E1E1E"), height=70)
            header_frame.pack(fill="x", padx=0, pady=0)
            header_frame.pack_propagate(False)
            
            # Header content
            header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
            header_content.pack(fill="both", expand=True, padx=20, pady=12)
            
            # Title with icon
            title_frame = ctk.CTkFrame(header_content, fg_color="transparent")
            title_frame.pack(anchor="w", fill="x")
            
            ctk.CTkLabel(title_frame, text="🔐", font=ctk.CTkFont(size=24)).pack(side="left", padx=(0, 10))
            ctk.CTkLabel(title_frame, text=self.lang_manager.get_string("2fa_setup_title"),
                        font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", anchor="w")
            
            ctk.CTkLabel(header_content, text="Add an extra layer of security to your account",
                        font=ctk.CTkFont(size=11), text_color="#B0B0B0").pack(anchor="w", pady=(3, 0))
            
            # Main content frame - NO SCROLLBAR
            main_frame = ctk.CTkFrame(main_container, fg_color="transparent")
            main_frame.pack(fill="both", expand=True, padx=20, pady=15)
            
            # Step 1
            step1_label = ctk.CTkLabel(
                main_frame, 
                text="Step 1: Scan the QR Code", 
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#4CAF50"
            )
            step1_label.pack(anchor="w", pady=(0, 5))
            
            # Compact instructions
            instructions_text = (
                "1. Install authenticator app  2. Scan QR code  3. Enter 6-digit code"
            )
            
            instructions_label = ctk.CTkLabel(
                main_frame,
                text=instructions_text,
                font=ctk.CTkFont(size=10),
                text_color="#999999"
            )
            instructions_label.pack(anchor="w", pady=(0, 8))
            
            # Generate QR code
            try:
                import pyotp
                
                email = self.database.get_master_account_email()
                totp = pyotp.TOTP(secret)

                provisioning_uri = self.auth_guardian.get_tfa_provisioning_uri(
                    account_name=email if email else "SecureVault Pro",
                    issuer_name="Vault",
                    secret=secret
                )

                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                    box_size=6,
                    border=3,
                )
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

                # Overlay icon
                icon_path = os.path.join("icons", "2fa_icon.png")
                if os.path.exists(icon_path):
                    try:
                        icon = Image.open(icon_path).convert("RGBA")
                        qr_w, qr_h = qr_img.size
                        max_size = qr_w // 4
                        icon.thumbnail((max_size, max_size))
                        
                        paste_x = (qr_w - icon.width) // 2
                        paste_y = (qr_h - icon.height) // 2
                        
                        qr_img.paste(icon, (paste_x, paste_y), icon)
                    except Exception as e:
                        logger.warning(f"Failed to overlay icon: {e}")
                
                # QR code size: 200x200
                qr_img = qr_img.resize((200, 200), Image.Resampling.LANCZOS)
                qr_ctk_image = ctk.CTkImage(light_image=qr_img, size=(200, 200))
                
                # QR Code container - centered
                qr_container = ctk.CTkFrame(main_frame, fg_color="white", border_width=2, 
                                        border_color="#CCCCCC", corner_radius=8)
                qr_container.pack(pady=8)
                
                qr_label = ctk.CTkLabel(qr_container, image=qr_ctk_image, text="", bg_color="white")
                qr_label.image = qr_ctk_image
                qr_label.pack(padx=6, pady=6)
                
            except Exception as e:
                logger.error(f"Failed to generate QR code: {e}")
                error_label = ctk.CTkLabel(
                    main_frame, 
                    text=f"❌ Error generating QR code",
                    text_color="#FF4444"
                )
                error_label.pack(pady=10)
                setup_dialog.destroy()
                return
            
            # Step 2
            step2_label = ctk.CTkLabel(
                main_frame, 
                text="Step 2: Enter Verification Code", 
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#2196F3"
            )
            step2_label.pack(anchor="w", pady=(10, 5))
            
            # Code entry
            code_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
            code_frame.pack(pady=5, fill="x")
            
            ctk.CTkLabel(
                code_frame, 
                text="Enter 6-digit code:",
                font=ctk.CTkFont(size=11)
            ).pack(anchor="w")
            
            code_entry = ctk.CTkEntry(
                code_frame,
                placeholder_text="000000",
                width=180,
                height=40,
                font=ctk.CTkFont(size=16, family="monospace"),
                justify="center",
                border_width=2,
                border_color="#2196F3"
            )
            code_entry.pack(pady=5)
            code_entry.bind("<KeyRelease>", lambda e: code_entry.configure(
                border_color="#FF6B6B" if code_entry.get() and not code_entry.get().isdigit() 
                else "#4CAF50" if len(code_entry.get()) == 6 and code_entry.get().isdigit()
                else "#2196F3"
            ))
            
            # Status label
            status_label = ctk.CTkLabel(
                code_frame, 
                text="⏳ Waiting for code input...", 
                font=ctk.CTkFont(size=10), 
                text_color="#9E9E9E"
            )
            status_label.pack(pady=2)
            
            def verify_and_enable():
                code = code_entry.get().strip()
                if not code or len(code) != 6 or not code.isdigit():
                    status_label.configure(text="❌ Please enter a valid 6-digit code", text_color="#FF4444")
                    code_entry.focus()
                    return
                
                try:
                    status_label.configure(text="⏳ Verifying code...", text_color="#2196F3")
                    status_label.update()
                    verify_btn.configure(state="disabled")
                    
                    import pyotp
                    totp = pyotp.TOTP(secret)
                    is_valid = totp.verify(code, valid_window=1)
                    
                    if is_valid:
                        status_label.configure(text="✅ Code verified successfully!", text_color="#4CAF50")
                        
                        if self.auth_guardian.enable_tfa(secret):
                            status_label.configure(text="✅ 2FA enabled! Closing...", text_color="#4CAF50")
                            
                            if hasattr(self, 'settings_window') and self.settings_window and self.settings_window.winfo_exists():
                                self.settings_window.destroy()
                            
                            setup_dialog.after(800, lambda: setup_dialog.destroy())
                        else:
                            status_label.configure(text="❌ Failed to enable 2FA", text_color="#FF4444")
                            verify_btn.configure(state="normal")
                    else:
                        status_label.configure(text="❌ Invalid code. Please try again.", text_color="#FF4444")
                        code_entry.focus()
                        code_entry.select_range(0, tk.END)
                        verify_btn.configure(state="normal")
                except Exception as e:
                    logger.error(f"Error verifying 2FA code: {e}")
                    status_label.configure(text=f"❌ Error: {str(e)[:40]}", text_color="#FF4444")
                    verify_btn.configure(state="normal")
            
            # Button frame at bottom
            button_frame = ctk.CTkFrame(main_container, fg_color=("gray90", "gray15"), height=70)
            button_frame.pack(fill="x", padx=0, pady=0, side="bottom")
            button_frame.pack_propagate(False)
            
            buttons_inner = ctk.CTkFrame(button_frame, fg_color="transparent")
            buttons_inner.pack(fill="both", expand=True, padx=20, pady=15)
            
            # Cancel button on the left
            cancel_btn = ctk.CTkButton(
                buttons_inner,
                text="Cancel",
                command=setup_dialog.destroy,
                height=40,
                width=120,
                font=ctk.CTkFont(size=13),
                fg_color="#757575",
                hover_color="#616161",
                corner_radius=8
            )
            cancel_btn.pack(side="left")
            
            # Verify button on the right
            verify_btn = ctk.CTkButton(
                buttons_inner,
                text="✓ Verify & Enable 2FA",
                command=verify_and_enable,
                height=40,
                width=200,
                font=ctk.CTkFont(size=13, weight="bold"),
                fg_color="#4CAF50",
                hover_color="#45A049",
                corner_radius=8
            )
            verify_btn.pack(side="right")
            
            code_entry.focus()
            code_entry.bind("<Return>", lambda e: verify_and_enable())
            
        except Exception as e:
            logger.error(f"Error in enable_2fa_dialog: {e}")
            self.show_message("error", f"Error setting up 2FA: {str(e)}", msg_type="error")

    def disable_2fa_dialog(self):
        """Dialog to disable Two-Factor Authentication."""
        if not hasattr(self, 'auth_guardian') or not self.auth_guardian:
            return
        
        if not self.auth_guardian.is_tfa_enabled():
            self.show_message("info", "2fa_not_configured", msg_type="info")
            return
        
        # First, verify master password for security
        if not self.verify_master_password_dialog():
            return
        
        result = messagebox.askyesno(
            self.lang_manager.get_string("2fa_disable_confirm_title"),
            self.lang_manager.get_string("2fa_disable_confirm_message"),
            parent=self.root
        )
        
        if result:
            try:
                if self.auth_guardian.disable_tfa():
                    # Close settings window if open
                    if hasattr(self, 'settings_window') and self.settings_window and self.settings_window.winfo_exists():
                        self.settings_window.destroy()
                    
                    self.show_message("success", "2fa_disabled_success", msg_type="info")
                else:
                    self.show_message("error", "Failed to disable 2FA", msg_type="error")
            except Exception as e:
                logger.error(f"Error disabling 2FA: {e}")
                self.show_message("error", f"Error disabling 2FA: {str(e)}", msg_type="error")



    def verify_2fa_during_login(self) -> bool:
            """Show 2FA verification dialog during login with enhanced UI. Returns True if verified, False otherwise."""
            if not hasattr(self, 'auth_guardian') or not self.auth_guardian:
                return True
            
            if not self.auth_guardian.is_tfa_enabled():
                return True
            
            # Check for lockout
            if self.auth_guardian.is_tfa_locked_out():
                lockout_time = self.auth_guardian.get_remaining_tfa_lockout_time()
                minutes = lockout_time // 60
                self.show_message("error", self.lang_manager.get_string("2fa_login_locked_out", minutes=minutes), msg_type="error")
                return False
            
            # Create enhanced 2FA verification dialog
            verify_dialog = ThemedToplevel(self.root)
            verify_dialog.title(self.lang_manager.get_string("2fa_login_required"))
            verify_dialog.resizable(False, False)
            verify_dialog.transient(self.root)  # Make it a child of main window
            verify_dialog.grab_set()  # Make it modal
            verify_dialog.lift()  # Bring to front
            verify_dialog.attributes('-topmost', True)  # Keep on top
            self.center_window(verify_dialog, 500, 500)
            verify_dialog.attributes('-topmost', False)  # Allow normal stacking after centering
            verify_dialog.focus_force()  # Force focus to this window
            
            # Main container
            main_container = ctk.CTkFrame(verify_dialog, fg_color="transparent")
            main_container.pack(fill="both", expand=True)
            
            # Header with gradient-like effect
            header_frame = ctk.CTkFrame(main_container, fg_color=("#2E3440", "#1E1E1E"), height=100)
            header_frame.pack(fill="x", padx=0, pady=0)
            header_frame.pack_propagate(False)
            
            header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
            header_content.pack(fill="both", expand=True, padx=25, pady=20)
            
            # Icon and title
            title_row = ctk.CTkFrame(header_content, fg_color="transparent")
            title_row.pack(fill="x")
            
            ctk.CTkLabel(title_row, text="🔐", font=ctk.CTkFont(size=32)).pack(side="left", padx=(0, 12))
            
            title_text_frame = ctk.CTkFrame(title_row, fg_color="transparent")
            title_text_frame.pack(side="left", fill="x", expand=True)
            
            ctk.CTkLabel(title_text_frame, text="Two-Factor Authentication",
                        font=ctk.CTkFont(size=20, weight="bold"),
                        anchor="w").pack(anchor="w")
            
            ctk.CTkLabel(title_text_frame, text="Verify your identity to continue",
                        font=ctk.CTkFont(size=12),
                        text_color="#B0B0B0",
                        anchor="w").pack(anchor="w", pady=(3, 0))
            
            # Content area
            content_frame = ctk.CTkFrame(main_container, fg_color="transparent")
            content_frame.pack(fill="both", expand=True, padx=25, pady=25)
            
            # Instructions with icon
            instruction_frame = ctk.CTkFrame(content_frame, fg_color=("gray90", "gray20"), corner_radius=10)
            instruction_frame.pack(fill="x", pady=(0, 20))
            
            ctk.CTkLabel(instruction_frame, 
                        text="📱 Open your authenticator app and enter the 6-digit code",
                        font=ctk.CTkFont(size=13),
                        wraplength=400,
                        justify="left").pack(padx=15, pady=12)
            
            # Code input label
            ctk.CTkLabel(content_frame, text="Enter Verification Code",
                        font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", pady=(0, 8))
            
            # Individual digit boxes for better UX
            code_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
            code_frame.pack(pady=(0, 10))
            
            # Create 6 individual digit entry boxes
            digit_entries = []
            for i in range(6):
                digit_entry = ctk.CTkEntry(
                    code_frame,
                    width=50,
                    height=60,
                    font=ctk.CTkFont(size=24, weight="bold", family="monospace"),
                    justify="center",
                    border_width=2,
                    border_color="#3B82F6"
                )
                digit_entry.pack(side="left", padx=3)
                digit_entries.append(digit_entry)
            
            # Helper text
            helper_text = ctk.CTkLabel(
                content_frame,
                text="⏱️ Code expires in 30 seconds",
                font=ctk.CTkFont(size=11),
                text_color="#888888"
            )
            helper_text.pack(pady=(8, 0))
            
            # Status indicator with icon
            status_frame = ctk.CTkFrame(content_frame, fg_color="transparent", height=40)
            status_frame.pack(fill="x", pady=(15, 10))
            status_frame.pack_propagate(False)
            
            status_label = ctk.CTkLabel(
                status_frame,
                text="",
                font=ctk.CTkFont(size=12)
            )
            status_label.pack()
            
            verified = [False]
            
            # Auto-focus management between digits
            def on_digit_change(index, event=None):
                """Handle digit input and auto-focus next field"""
                current_entry = digit_entries[index]
                text = current_entry.get()
                
                # Only allow single digit
                if len(text) > 1:
                    current_entry.delete(1, tk.END)
                    text = text[0]
                
                # Only allow digits
                if text and not text.isdigit():
                    current_entry.delete(0, tk.END)
                    return
                
                # Visual feedback - highlight filled boxes
                if text:
                    current_entry.configure(border_color="#10B981")
                    # Auto-focus next box
                    if index < 5:
                        digit_entries[index + 1].focus()
                    else:
                        # All digits entered, try to verify
                        verify_code()
                else:
                    current_entry.configure(border_color="#3B82F6")
            
            def on_digit_backspace(index, event):
                """Handle backspace to move to previous field"""
                current_entry = digit_entries[index]
                if not current_entry.get() and index > 0:
                    digit_entries[index - 1].focus()
                    digit_entries[index - 1].delete(0, tk.END)
            
            # Bind events to all digit entries
            for i, entry in enumerate(digit_entries):
                entry.bind("<KeyRelease>", lambda e, idx=i: on_digit_change(idx, e))
                entry.bind("<BackSpace>", lambda e, idx=i: on_digit_backspace(idx, e))
            
            def get_full_code():
                """Combine all digits into one code"""
                return "".join(entry.get() for entry in digit_entries)
            
            def verify_code():
                """Verify the entered code with visual feedback"""
                code = get_full_code()
                
                if len(code) != 6:
                    status_label.configure(
                        text="⚠️ Please enter all 6 digits",
                        text_color="#F59E0B"
                    )
                    return
                
                if not code.isdigit():
                    status_label.configure(
                        text="❌ Only numbers are allowed",
                        text_color="#EF4444"
                    )
                    return
                
                # Show verifying status
                status_label.configure(
                    text="🔄 Verifying code...",
                    text_color="#3B82F6"
                )
                verify_dialog.update()
                
                # Verify with auth guardian
                if self.auth_guardian.verify_tfa_code(code):
                    # Success animation
                    status_label.configure(
                        text="✅ Verification successful!",
                        text_color="#10B981"
                    )
                    
                    # Highlight all boxes green
                    for entry in digit_entries:
                        entry.configure(border_color="#10B981")
                    
                    verify_dialog.update()
                    verified[0] = True
                    
                    # Close after brief delay
                    verify_dialog.after(800, verify_dialog.destroy)
                else:
                    # Error animation
                    status_label.configure(
                        text="❌ Invalid code. Please try again.",
                        text_color="#EF4444"
                    )
                    
                    # Shake animation effect
                    for entry in digit_entries:
                        entry.configure(border_color="#EF4444")
                    
                    def reset_after_error():
                        # Check if dialog still exists before manipulating widgets
                        if not verify_dialog.winfo_exists():
                            return
                        for entry in digit_entries:
                            if entry.winfo_exists():
                                entry.delete(0, tk.END)
                                entry.configure(border_color="#3B82F6")
                        if digit_entries[0].winfo_exists():
                            digit_entries[0].focus()
                        if status_label.winfo_exists():
                            status_label.configure(text="")
                    
                    verify_dialog.after(1500, reset_after_error)
            
            # Button frame at bottom
            button_frame = ctk.CTkFrame(main_container, fg_color=("gray90", "gray15"), height=80)
            button_frame.pack(fill="x", padx=0, pady=0, side="bottom")
            button_frame.pack_propagate(False)
            
            buttons_inner = ctk.CTkFrame(button_frame, fg_color="transparent")
            buttons_inner.pack(fill="both", expand=True, padx=25, pady=20)
            
            # Cancel button
            def on_cancel():
                verified[0] = False
                verify_dialog.destroy()
            
            cancel_btn = ctk.CTkButton(
                buttons_inner,
                text="Cancel",
                command=on_cancel,
                height=45,
                width=120,
                font=ctk.CTkFont(size=14),
                fg_color=("gray70", "gray30"),
                hover_color=("gray60", "gray40")
            )
            cancel_btn.pack(side="left")
            
            # Verify button
            verify_btn = ctk.CTkButton(
                buttons_inner,
                text="✓ Verify Code",
                command=verify_code,
                height=45,
                width=150,
                font=ctk.CTkFont(size=14, weight="bold"),
                fg_color="#10B981",
                hover_color="#059669"
            )
            verify_btn.pack(side="right")
            
            # Focus first digit box
            digit_entries[0].focus()
            
            # Handle window close
            def on_closing():
                verified[0] = False
                verify_dialog.destroy()
            
            verify_dialog.protocol("WM_DELETE_WINDOW", on_closing)
            
            # Wait for dialog to close
            verify_dialog.wait_window()
            
            return verified[0]
    
    def restart_program(self):
        import sys
        import subprocess
        try:
            logger.info("Initiating secure program restart...")
            if hasattr(self, 'tamper_manager'):
                self.tamper_manager.update_shutdown_status('SHUTDOWN_CLEAN')
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
        """Enhanced version with engaging loading animation"""
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        
        # Create loading screen with progress bar
        loading_container = ctk.CTkFrame(self.main_panel, fg_color="transparent")
        loading_container.pack(fill="both", expand=True)
        
        # Center frame for loading elements
        center_frame = ctk.CTkFrame(loading_container, fg_color="transparent")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Loading title with icon
        title_frame = ctk.CTkFrame(center_frame, fg_color="transparent")
        title_frame.pack(pady=(0, 20))
        
        ctk.CTkLabel(
            title_frame,
            text="🔐 Loading Your Accounts",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack()
        
        ctk.CTkLabel(
            title_frame,
            text="Please wait while we securely retrieve your data...",
            font=ctk.CTkFont(size=12),
            text_color="#888888"
        ).pack(pady=(5, 0))
        
        # Progress bar
        progress_bar = ctk.CTkProgressBar(
            center_frame,
            width=400,
            height=12,
            corner_radius=6,
            progress_color="#3B82F6"
        )
        progress_bar.pack(pady=20)
        progress_bar.set(0)
        
        # Status label
        status_label = ctk.CTkLabel(
            center_frame,
            text="Initializing...",
            font=ctk.CTkFont(size=11),
            text_color="#666666"
        )
        status_label.pack(pady=(0, 10))
        
        # Fun loading messages
        loading_messages = [
            "🔍 Scanning vault...",
            "🔐 Decrypting accounts...",
            "🛡️ Verifying security...",
            "📊 Analyzing passwords...",
            "✨ Preparing your data...",
            "🎯 Almost there..."
        ]
        
        message_index = [0]
        
        def animate_loading():
            """Smooth progress animation"""
            current_progress = progress_bar.get()
            
            if current_progress < 0.95:
                # Increment progress
                increment = 0.15 if current_progress < 0.5 else 0.10
                new_progress = min(current_progress + increment, 0.95)
                progress_bar.set(new_progress)
                
                # Update message
                msg_idx = int(new_progress * len(loading_messages))
                if msg_idx < len(loading_messages) and msg_idx != message_index[0]:
                    message_index[0] = msg_idx
                    status_label.configure(text=loading_messages[msg_idx])
                
                # Schedule next update
                self.root.after(300, animate_loading)
            else:
                # Loading complete
                status_label.configure(text="✅ Ready!")
                progress_bar.set(1.0)
                
                # Show actual content after brief delay
                self.root.after(200, show_actual_content)
        
        def show_actual_content():
            """Display the actual accounts interface"""
            # Clear loading screen
            for widget in self.main_panel.winfo_children():
                widget.destroy()
            
            # Header with title and add button
            header = ctk.CTkFrame(self.main_panel)
            header.pack(fill="x", padx=15, pady=15)
            
            ctk.CTkLabel(
                header, 
                text=self.lang_manager.get_string("your_accounts_title"), 
                font=ctk.CTkFont(size=24, weight="bold")
            ).pack(side="left", padx=25, pady=15)
            
            ctk.CTkButton(
                header, 
                text=self.lang_manager.get_string("add_new_account"), 
                command=self.show_account_dialog,
                width=180, 
                height=55, 
                font=ctk.CTkFont(size=20, weight="bold")
            ).pack(side="right", padx=25, pady=15)
            
            # Search and filter section
            search_frame = ctk.CTkFrame(self.main_panel)
            search_frame.pack(fill="x", padx=15, pady=10)
            
            self.search_entry = ctk.CTkEntry(
                search_frame, 
                placeholder_text=self.lang_manager.get_string("search_placeholder"),
                width=400, 
                height=45
            )
            self.search_entry.pack(side="left", padx=25, pady=15)
            
            ctk.CTkLabel(
                search_frame, 
                text=self.lang_manager.get_string("filter_by_label")
            ).pack(side="left", padx=(10, 5))
            
            self.filter_var = ctk.StringVar(value=self.lang_manager.get_string("filter_show_all"))
            filter_options = [
                self.lang_manager.get_string("filter_show_all"),
                self.lang_manager.get_string("filter_weak_passwords"),
                self.lang_manager.get_string("filter_expired_passwords")
            ]
            self.filter_menu = ctk.CTkOptionMenu(
                search_frame, 
                variable=self.filter_var, 
                values=filter_options, 
                command=self.filter_accounts
            )
            self.filter_menu.pack(side="left", padx=(0, 10))

            self.expired_passwords_label = ctk.CTkLabel(
                search_frame, 
                text="", 
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="red"
            )
            self.expired_passwords_label.pack(side="right", padx=25, pady=15)

            self.search_entry.bind("<KeyRelease>", self.search_accounts)

            # Scrollable container for accounts
            self.passwords_container = ctk.CTkScrollableFrame(self.main_panel)
            self.passwords_container.pack(fill="both", expand=True, padx=15, pady=15)

            # Show checking message (this will be replaced by load_password_cards)
            password_check_label = ctk.CTkLabel(
                self.passwords_container, 
                text="Checking expired account passwords, please wait...",
                font=ctk.CTkFont(size=14, weight="bold")
            )
            password_check_label.pack(pady=20)
            self.root.after(15000, password_check_label.destroy)

            # Load actual password cards
            self.load_password_cards()
            self.update_expired_passwords_count()
        
        # Start the loading animation
        self.root.after(100, animate_loading)

    def is_password_weak(self, password: str) -> bool:
        if len(password) < 16:
            return True
        if not any(c.isupper() for c in password):
            return True
        if not any(c.islower() for c in password):
            return True
        if not any(c.isdigit() for c in password):
            return True
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return True
        return False

    def update_expired_passwords_count(self):
        if hasattr(self, 'expired_passwords_label') and self.expired_passwords_label.winfo_exists():
            if self.password_reminder:
                count = len(self.password_reminder.get_reminded_accounts())
                if count > 0:
                    self.expired_passwords_label.configure(text=self.lang_manager.get_string("expired_passwords_count", count=count))
                else:
                    self.expired_passwords_label.configure(text="")
            else:
                self.expired_passwords_label.configure(text="")

    def load_password_cards(self, query: str = None, filter_option: str = None):
        if not hasattr(self, 'passwords_container') or not self.passwords_container.winfo_exists():
            return
        for widget in self.passwords_container.winfo_children():
            widget.destroy()
        if not self.database:
            return

        loading_label = ctk.CTkLabel(self.passwords_container, text="Loading accounts...",
                                     font=ctk.CTkFont(size=14))
        loading_label.pack(pady=20)
        self.passwords_container.update_idletasks()

        def _load_in_background():
            try:
                all_accounts = self.database.get_all_decrypted_accounts()
                
                # Filter and search in memory
                filtered_accounts = all_accounts
                
                # Apply search query
                if query:
                    q = query.lower()
                    filtered_accounts = [
                        acc for acc in filtered_accounts 
                        if q in acc.get('name', '').lower() 
                        or q in acc.get('email', '').lower() 
                        or q in acc.get('url', '').lower()
                    ]
                
                # Apply filter option
                if filter_option and filter_option != self.lang_manager.get_string("filter_show_all"):
                    if filter_option == self.lang_manager.get_string("filter_expired_passwords"):
                        expired_ids = self.password_reminder.get_reminded_accounts()
                        filtered_accounts = [acc for acc in filtered_accounts if acc['id'] in expired_ids]
                    elif filter_option == self.lang_manager.get_string("filter_weak_passwords"):
                        filtered_accounts = [acc for acc in filtered_accounts if self.is_password_weak(acc.get('password', ''))]

                def _update_ui():
                    loading_label.destroy()
                    if not filtered_accounts:
                        msg = self.lang_manager.get_string("no_accounts_found_search") if query else self.lang_manager.get_string("no_accounts_found")
                        self.show_no_accounts_message(msg)
                    else:
                        for account in sorted(filtered_accounts, key=lambda x: x.get('updated_at'), reverse=True):
                            self.create_account_card(account)

                self.root.after(0, _update_ui)

            except Exception as e:
                def _show_error():
                    loading_label.destroy()
                    self.show_error_message(f"Error loading accounts: {e}")
                self.root.after(0, _show_error)

        threading.Thread(target=_load_in_background, daemon=True).start()

    def search_accounts(self, event=None):
        query = self.search_entry.get().strip()
        self.load_password_cards(query=query)

    def filter_accounts(self, selected_filter: str):
        self.load_password_cards(filter_option=selected_filter)

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

    def create_account_card(self, account: dict):
        password = account.get('password', '')
        score, strength, _ = self.password_generator.assess_strength(password)
        
        account_id = account.get('id')
        name = account.get('name', 'N/A')
        username = account.get('username', '')
        email = account.get('email', '')
        url = account.get('url', '')

        reminded_accounts = set()
        if self.password_reminder:
            reminded_accounts = self.password_reminder.get_reminded_accounts()

        card_fg_color = "#470500" if account_id in reminded_accounts else None

        card = ctk.CTkFrame(self.passwords_container, corner_radius=10, fg_color=card_fg_color)
        card.pack(fill="x", padx=10, pady=8)

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=20, pady=20)

        logo_mapping = {
            # Social Media (English + Arabic)
            "facebook": "icons/facebook.png",
            "fb.com": "icons/facebook.png",
            "فيسبوك": "icons/facebook.png",
            "whatsapp": "icons/whatsapp.png",
            "واتساب": "icons/whatsapp.png",
            "واتس اب": "icons/whatsapp.png",
            "instagram": "icons/instagram.png",
            "انستقرام": "icons/instagram.png",
            "انستغرام": "icons/instagram.png",
            "twitter": "icons/x.png",
            "x.com": "icons/x.png",
            "تويتر": "icons/x.png",
            "اكس": "icons/x.png",
            "linkedin": "icons/linkedin.png",
            "لينكد ان": "icons/linkedin.png",
            "لينكدإن": "icons/linkedin.png",
            "snapchat": "icons/snapchat.png",
            "سناب شات": "icons/snapchat.png",
            "سناب": "icons/snapchat.png",
            "tiktok": "icons/tiktok.png",
            "تيك توك": "icons/tiktok.png",
            "تيكتوك": "icons/tiktok.png",
            "pinterest": "icons/pinterest.png",
            "بينترست": "icons/pinterest.png",
            "reddit": "icons/reddit.png",
            "ريديت": "icons/reddit.png",
            "tumblr": "icons/tumblr.png",
            "تمبلر": "icons/tumblr.png",
            "discord": "icons/discord.png",
            "ديسكورد": "icons/discord.png",
            "telegram": "icons/telegram.png",
            "تيليجرام": "icons/telegram.png",
            "تليجرام": "icons/telegram.png",
            
            # Email & Communication (English + Arabic)
            "gmail": "icons/gmail.png",
            "google": "icons/gmail.png",
            "جيميل": "icons/gmail.png",
            "جوجل": "icons/gmail.png",
            "outlook": "icons/outlook.png",
            "hotmail": "icons/outlook.png",
            "اوتلوك": "icons/outlook.png",
            "هوتميل": "icons/outlook.png",
            "yahoo": "icons/yahoo.png",
            "ياهو": "icons/yahoo.png",
            "protonmail": "icons/protonmail.png",
            "بروتون": "icons/protonmail.png",
            "icloud": "icons/icloud.png",
            "اي كلاود": "icons/icloud.png",
            "ايكلاود": "icons/icloud.png",
            "slack": "icons/slack.png",
            "سلاك": "icons/slack.png",
            "teams": "icons/teams.png",
            "تيمز": "icons/teams.png",
            "zoom": "icons/zoom.png",
            "زوم": "icons/zoom.png",
            "skype": "icons/skype.png",
            "سكايب": "icons/skype.png",
            
            # Cloud Storage & Productivity (English + Arabic)
            "dropbox": "icons/dropbox.png",
            "دروب بوكس": "icons/dropbox.png",
            "دروببوكس": "icons/dropbox.png",
            "drive": "icons/drive.png",
            "درايف": "icons/drive.png",
            "onedrive": "icons/onedrive.png",
            "وان درايف": "icons/onedrive.png",
            "وان درايڤ": "icons/onedrive.png",
            "box": "icons/box.png",
            "بوكس": "icons/box.png",
            "notion": "icons/notion.png",
            "نوشن": "icons/notion.png",
            "evernote": "icons/evernote.png",
            "ايفرنوت": "icons/evernote.png",
            "trello": "icons/trello.png",
            "تريلو": "icons/trello.png",
            "asana": "icons/asana.png",
            "اسانا": "icons/asana.png",
            
            # Streaming & Entertainment (English + Arabic)
            "netflix": "icons/netflix.png",
            "نتفليكس": "icons/netflix.png",
            "نيتفليكس": "icons/netflix.png",
            "spotify": "icons/spotify.png",
            "سبوتيفاي": "icons/spotify.png",
            "سبوتيفي": "icons/spotify.png",
            "youtube": "icons/youtube.png",
            "يوتيوب": "icons/youtube.png",
            "يوتوب": "icons/youtube.png",
            "twitch": "icons/twitch.png",
            "تويتش": "icons/twitch.png",
            "hulu": "icons/hulu.png",
            "هولو": "icons/hulu.png",
            "disney": "icons/disney.png",
            "ديزني": "icons/disney.png",
            "amazon": "icons/amazon.png",
            "prime": "icons/amazon.png",
            "امازون": "icons/amazon.png",
            "برايم": "icons/amazon.png",
            "apple": "icons/apple.png",
            "itunes": "icons/apple.png",
            "ابل": "icons/apple.png",
            "ايتونز": "icons/apple.png",
            
            # Shopping & E-commerce (English + Arabic)
            "ebay": "icons/ebay.png",
            "ايباي": "icons/ebay.png",
            "paypal": "icons/paypal.png",
            "باي بال": "icons/paypal.png",
            "بايبال": "icons/paypal.png",
            "stripe": "icons/stripe.png",
            "سترايب": "icons/stripe.png",
            "shopify": "icons/shopify.png",
            "شوبيفاي": "icons/shopify.png",
            "etsy": "icons/etsy.png",
            "ايتسي": "icons/etsy.png",
            "alibaba": "icons/alibaba.png",
            "علي بابا": "icons/alibaba.png",
            "علي بابة": "icons/alibaba.png",
            
            # Banking & Finance (English + Arabic)
            "payoneer": "icons/payoneer.png",
            "بايونير": "icons/payoneer.png",
            "بايونيير": "icons/payoneer.png",
            "revolut": "icons/revolut.png",
            "ريفولوت": "icons/revolut.png",
            "venmo": "icons/venmo.png",
            "فينمو": "icons/venmo.png",
            "cashapp": "icons/cashapp.png",
            "كاش اب": "icons/cashapp.png",
            "coinbase": "icons/coinbase.png",
            "كوين بيس": "icons/coinbase.png",
            "كوينبيس": "icons/coinbase.png",
            "binance": "icons/binance.png",
            "بينانس": "icons/binance.png",
            "بايننس": "icons/binance.png",
            
            # Development & Tech (English + Arabic)
            "github": "icons/github.png",
            "جيت هاب": "icons/github.png",
            "جيتهاب": "icons/github.png",
            "gitlab": "icons/gitlab.png",
            "جيت لاب": "icons/gitlab.png",
            "جيتلاب": "icons/gitlab.png",
            "bitbucket": "icons/bitbucket.png",
            "بت باكت": "icons/bitbucket.png",
            "stackoverflow": "icons/stackoverflow.png",
            "ستاك اوفرفلو": "icons/stackoverflow.png",
            "docker": "icons/docker.png",
            "دوكر": "icons/docker.png",
            "aws": "icons/aws.png",
            "ايه دبليو اس": "icons/aws.png",
            "azure": "icons/azure.png",
            "ازور": "icons/azure.png",
            "ازر": "icons/azure.png",
            "heroku": "icons/heroku.png",
            "هيروكو": "icons/heroku.png",
            "digitalocean": "icons/digitalocean.png",
            "ديجيتال اوشن": "icons/digitalocean.png",
            
            # Gaming (English + Arabic)
            "steam": "icons/steam.png",
            "ستيم": "icons/steam.png",
            "epic": "icons/epic.png",
            "ايبك": "icons/epic.png",
            "playstation": "icons/playstation.png",
            "بلايستيشن": "icons/playstation.png",
            "بلاي ستيشن": "icons/playstation.png",
            "xbox": "icons/xbox.png",
            "اكسبوكس": "icons/xbox.png",
            "اكس بوكس": "icons/xbox.png",
            "nintendo": "icons/nintendo.png",
            "نينتندو": "icons/nintendo.png",
            "battle.net": "icons/battlenet.png",
            "باتل نت": "icons/battlenet.png",
            "origin": "icons/origin.png",
            "اوريجن": "icons/origin.png",
            
            # Education & Learning (English + Arabic)
            "udemy": "icons/udemy.png",
            "يوديمي": "icons/udemy.png",
            "يودمي": "icons/udemy.png",
            "coursera": "icons/coursera.png",
            "كورسيرا": "icons/coursera.png",
            "khan": "icons/khan.png",
            "خان": "icons/khan.png",
            "duolingo": "icons/duolingo.png",
            "دولينجو": "icons/duolingo.png",
            "ديولينجو": "icons/duolingo.png",
            "skillshare": "icons/skillshare.png",
            "سكيل شير": "icons/skillshare.png",
            
            # Other Popular Services (English + Arabic)
            "wordpress": "icons/wordpress.png",
            "ووردبريس": "icons/wordpress.png",
            "وورد بريس": "icons/wordpress.png",
            "medium": "icons/medium.png",
            "ميديوم": "icons/medium.png",
            "canva": "icons/canva.png",
            "كانفا": "icons/canva.png",
            "figma": "icons/figma.png",
            "فيجما": "icons/figma.png",
            "adobe": "icons/adobe.png",
            "ادوبي": "icons/adobe.png",
            "ادوبى": "icons/adobe.png",
        }
        
        logo_path = None
        # Check both the name and the URL for keywords
        search_text = f"{name.lower()} {url.lower()}"
        for domain, path in logo_mapping.items():
            # Use word boundaries for more precise matching
            if re.search(f"\\b{re.escape(domain)}\\b", search_text):
                logo_path = path
                break
        
        if not logo_path:
            logo_path = "icons/unknown.png"

        try:
            logo_image = Image.open(logo_path)
            logo_icon = ctk.CTkImage(light_image=logo_image, size=(64, 64))
            logo_label = ctk.CTkLabel(content, image=logo_icon, text="")
            logo_label.pack(side="left", padx=(0, 20))
        except Exception as e:
            logger.warning(f"Could not display logo for {url}: {e}")

        left_frame = ctk.CTkFrame(content, fg_color="transparent")
        left_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(left_frame, text=name, 
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        display_username = username or email or self.lang_manager.get_string("no_username")
        ctk.CTkLabel(left_frame, text=f"👤 {display_username}", 
                     text_color="#888888", font=ctk.CTkFont(size=14)).pack(anchor="w", pady=2)
        if url:
            ctk.CTkLabel(left_frame, text=f"🌐 {url}", 
                         text_color="#888888", font=ctk.CTkFont(size=14)).pack(anchor="w", pady=2)

        right_frame = ctk.CTkFrame(content, fg_color="transparent")
        right_frame.pack(side="right")
        strength_color = self.get_strength_color(strength)
        strength_text = self.lang_manager.get_string("strength_template", strength=strength)
        if strength in ["Weak", "Very Weak"]:
            strength_text += f" {self.lang_manager.get_string('weak_password_recommendation')}"
        ctk.CTkLabel(right_frame, text=strength_text, 
                     text_color=strength_color, font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(0, 10))
        
        self.create_action_buttons(right_frame, account)

    def get_strength_color(self, strength):
        colors = {
            "Excellent": "green", "Very Strong": "green", "Strong": "green",
            "Medium": "orange", "Weak": "red", "Very Weak": "red", "Unknown": "#888888"
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
            (self.lang_manager.get_string("view_action"), lambda: self.view_account_details(account['id'])),
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

    def delete_account(self, account: dict):
        if not self.verify_master_password_dialog():
            return

        account_name = account.get('name', 'this account')
        result = self.show_message("delete_confirm_title", "delete_confirm_message", ask="yesno", account_name=account_name)
        if result:
            try:
                self.database.delete_account(account['id'])
                if self.password_reminder:
                    self.password_reminder.mark_as_changed(account['id'])
                self.update_expired_passwords_count()
                self.show_message("delete_success_title", "delete_success_message", account_name=account_name)
                self.load_password_cards()
            except Exception as e:
                self.show_message("error", "delete_failed_message", msg_type="error", error=str(e))

    def view_account_details(self, account_id: str):
        if not self.verify_master_password_dialog():
            return
        
        account = self.database.get_account_by_id(account_id)
        if not account:
            self.show_message("error", "account_not_found", msg_type="error")
            return
        
        dialog = ThemedToplevel(self.root)
        dialog.title(self.lang_manager.get_string("account_details_title", account_name=account.get('name', '')))
        dialog.geometry("600x800")
        dialog.grab_set()

        main_frame = ctk.CTkScrollableFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(main_frame, text=account.get('name', ''), font=ctk.CTkFont(size=24, weight="bold")).pack(pady=10)

        details = {
            "Username": account.get('username', 'N/A'),
            "Password": account.get('password', 'N/A'),
            "Email": account.get('email', 'N/A'),
            "Recovery Email": account.get('recovery_email', 'N/A'),
            "Phone Number": account.get('phone_number', 'N/A'),
            "2FA Enabled": "Yes" if account.get('two_factor_enabled') else "No",
            "Website URL": account.get('url', 'N/A'),
            "Category": account.get('category', 'N/A'),
            "Notes": account.get('notes', 'N/A'),
            "Date Created": account.get('created_at'),
            "Last Modified": account.get('updated_at')
        }

        for label, value in details.items():
            is_password = label == "Password"
            self.create_detail_field(main_frame, label, value, is_password=is_password)

        close_btn = ctk.CTkButton(main_frame, text="Close", command=dialog.destroy, width=100)
        close_btn.pack(pady=20)
        
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

    def copy_password_to_clipboard(self, account: dict):
        if not self.verify_master_password_dialog():
            return
        
        password = account.get('password')
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.show_message("copied_title", "copy_success_message", account_name=account.get('name', ''))
            self.root.after(30000, self.root.clipboard_clear)
        else:
            self.show_message("error", "password_not_found", msg_type="error")

    def open_website(self, account: dict):
        url = account.get('url')
        if url:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            webbrowser.open_new_tab(url)
        else:
            self.show_message("error", "no_url_for_account", msg_type="error")


    def show_account_dialog(self, account: Optional[dict] = None):
        is_edit = account is not None
        title = self.lang_manager.get_string("edit_account_title", account_name=account['name']) if is_edit else self.lang_manager.get_string("add_account_title")
        
        dialog = ThemedToplevel(self.root)
        dialog.title(title)
        dialog.grab_set()
        self.center_window(dialog, 900, 950)
        
        main_frame = ctk.CTkScrollableFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=title, font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        
        entries = self._create_enhanced_account_form(main_frame, account)
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text=self.lang_manager.get_string("cancel_button"), 
                    command=dialog.destroy, width=120, height=45).pack(side="left", padx=15)
        
        save_text = self.lang_manager.get_string("update_account_button") if is_edit else self.lang_manager.get_string("add_account_button")
        ctk.CTkButton(button_frame, text=save_text, 
                    command=lambda: self.save_enhanced_account(dialog, entries, account),
                    width=150, height=45, font=ctk.CTkFont(size=16, weight="bold")).pack(side="right", padx=15)


    def _create_enhanced_account_form(self, parent, account: Optional[dict] = None):
        """Create enhanced form with multiple sections"""
        entries = {}
        
        # ===== BASIC INFORMATION SECTION =====
        self._create_form_section(parent, "🔐 Basic Information", "Enter the essential account details")
        
        entries["name"] = self._create_form_field(parent, "Account Name", "e.g., Gmail Personal, GitHub Work", account.get('name', '') if account else "", required=True)
        entries["account_type"] = self._create_form_field(parent, "Account Type", "Select the type of account", account.get('account_type', 'Email') if account else 'Email', field_type="dropdown", options=["Email", "Social Media", "Banking", "Shopping", "Work", "Gaming", "Other"])
        
        # ===== CREDENTIALS SECTION =====
        self._create_form_section(parent, "🔑 Credentials", "Your login information")
        
        entries["username"] = self._create_form_field(parent, "Username / Email", "The email or username used to log in", account.get('username', '') if account else "", required=True)
        entries["password"] = self._create_password_field_enhanced(parent, account.get('password', '') if account else "")
        
        # ===== SECURITY & RECOVERY SECTION =====
        self._create_form_section(parent, "🛡️ Security & Recovery", "Helpful for account recovery and security")
        
        entries["recovery_email"] = self._create_form_field(parent, "Recovery Email", "e.g., secondary@email.com", account.get('recovery_email', '') if account else "", field_type="email")
        entries["phone_number"] = self._create_form_field(parent, "Phone Number", "e.g., +1 555-123-4567", account.get('phone_number', '') if account else "", field_type="tel")
        entries["two_factor_enabled"] = self._create_form_field(parent, "2FA Status", "Is Two-Factor Authentication enabled?", account.get('two_factor_enabled', 0) if account else 0, field_type="checkbox")

        # ===== WEBSITE & NOTES SECTION =====
        self._create_form_section(parent, "🌐 Website & Notes", "Additional details")
        
        entries["url"] = self._create_form_field(parent, "Website URL", "e.g., https://www.gmail.com", account.get('url', '') if account else "", field_type="url")
        entries["notes"] = self._create_textarea_field(parent, "Notes", "Any extra information", account.get('notes', '') if account else "")
        
        # ===== ORGANIZATION SECTION =====
        self._create_form_section(parent, "📂 Organization", "Categorize this account")
        
        entries["category"] = self._create_form_field(parent, "Category / Priority", "Set a priority level for this account", account.get('category', 'Medium Priority') if account else 'Medium Priority', field_type="dropdown", options=["Critical", "High Priority", "Medium Priority", "Low Priority"])
        
        return entries


    def _create_form_section(self, parent, title, subtitle):
        """Create a form section header with title and description"""
        section_frame = ctk.CTkFrame(parent, fg_color="transparent")
        section_frame.pack(fill="x", padx=25, pady=(20, 10))
        
        title_label = ctk.CTkLabel(
            section_frame,
            text=title,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(anchor="w")
        
        subtitle_label = ctk.CTkLabel(
            section_frame,
            text=subtitle,
            font=ctk.CTkFont(size=11),
            text_color=("gray60", "gray40")
        )
        subtitle_label.pack(anchor="w", pady=(2, 0))
        
        # Divider line
        divider = ctk.CTkFrame(parent, height=1, fg_color=("gray80", "gray30"))
        divider.pack(fill="x", padx=25, pady=(8, 0))


    def _create_form_field(self, parent, label, hint, value="", field_type="text", options=None, required=False):
        """Create a labeled form field with helper text"""
        field_frame = ctk.CTkFrame(parent, fg_color="transparent")
        field_frame.pack(fill="x", padx=25, pady=10)
        
        # Label with required indicator
        label_frame = ctk.CTkFrame(field_frame, fg_color="transparent")
        label_frame.pack(fill="x", pady=(0, 5))
        
        label_text = f"{label}"
        if required:
            label_text += " *"
        
        ctk.CTkLabel(
            label_frame,
            text=label_text,
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(side="left", anchor="w")
        
        # Helper text
        ctk.CTkLabel(
            label_frame,
            text=hint,
            font=ctk.CTkFont(size=11),
            text_color=("gray60", "gray40")
        ).pack(side="left", anchor="w", padx=(10, 0))
        
        # Input field
        if field_type == "dropdown":
            entry = ctk.CTkComboBox(
                field_frame,
                values=options or [],
                state="readonly",
                width=450,
                height=40
            )
            if value in (options or []):
                entry.set(value)
            entry.pack(fill="x", pady=(0, 5))
        
        elif field_type == "checkbox":
            entry = ctk.CTkCheckBox(
                field_frame,
                text="Yes, this account has 2FA enabled",
                onvalue=1,
                offvalue=0
            )
            if value:
                entry.select()
            entry.pack(anchor="w")
        
        elif field_type == "email":
            entry = ctk.CTkEntry(
                field_frame,
                placeholder_text="example@email.com",
                width=450,
                height=40
            )
            if value:
                entry.insert(0, value)
            entry.pack(fill="x", pady=(0, 5))
        
        elif field_type == "tel":
            entry = ctk.CTkEntry(
                field_frame,
                placeholder_text="+1 (555) 123-4567",
                width=450,
                height=40
            )
            if value:
                entry.insert(0, value)
            entry.pack(fill="x", pady=(0, 5))
        
        elif field_type == "url":
            entry = ctk.CTkEntry(
                field_frame,
                placeholder_text="https://www.example.com",
                width=450,
                height=40
            )
            if value:
                entry.insert(0, value)
            entry.pack(fill="x", pady=(0, 5))
        
        else:  # text field (default)
            entry = ctk.CTkEntry(
                field_frame,
                placeholder_text=hint,
                width=450,
                height=40
            )
            if value:
                entry.insert(0, value)
            entry.pack(fill="x", pady=(0, 5))
        
        return entry


    def _create_textarea_field(self, parent, label, hint, value=""):
        """Create a textarea field"""
        field_frame = ctk.CTkFrame(parent, fg_color="transparent")
        field_frame.pack(fill="x", padx=25, pady=10)
        
        # Label
        ctk.CTkLabel(
            field_frame,
            text=f"{label}",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 5))
        
        # Helper text
        ctk.CTkLabel(
            field_frame,
            text=hint,
            font=ctk.CTkFont(size=11),
            text_color=("gray60", "gray40")
        ).pack(anchor="w", pady=(0, 5))
        
        # Textarea
        textarea = ctk.CTkTextbox(
            field_frame,
            width=450,
            height=100,
            font=ctk.CTkFont(size=12)
        )
        if value:
            textarea.insert("1.0", value)
        textarea.pack(fill="both", expand=True, pady=(0, 5))
        
        return textarea


    def _create_password_field_enhanced(self, parent, default_value=""):
        """Create an enhanced password field with generator and visibility toggle"""
        field_frame = ctk.CTkFrame(parent, fg_color="transparent")
        field_frame.pack(fill="x", padx=25, pady=10)
        
        # Label
        label_frame = ctk.CTkFrame(field_frame, fg_color="transparent")
        label_frame.pack(fill="x", pady=(0, 5))
        
        ctk.CTkLabel(
            label_frame,
            text="Password *",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(side="left", anchor="w")
        
        ctk.CTkLabel(
            label_frame,
            text="Your secure password (minimum 8 characters)",
            font=ctk.CTkFont(size=11),
            text_color=("gray60", "gray40")
        ).pack(side="left", anchor="w", padx=(10, 0))
        
        # Input area
        input_frame = ctk.CTkFrame(field_frame, fg_color="transparent")
        input_frame.pack(fill="x", pady=(0, 5))
        
        password_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="••••••••",
            show="*",
            width=280,
            height=40
        )
        password_entry.pack(side="left", padx=(0, 5), fill="x", expand=True)
        if default_value:
            password_entry.insert(0, default_value)
        
        # Toggle visibility button
        def toggle_password():
            if password_entry.cget("show") == "*":
                password_entry.configure(show="")
                eye_btn.configure(text="🙈")
            else:
                password_entry.configure(show="*")
                eye_btn.configure(text="👁️")
        
        eye_btn = ctk.CTkButton(
            input_frame,
            text="👁️",
            width=40,
            height=40,
            command=toggle_password,
            font=ctk.CTkFont(size=18)
        )
        eye_btn.pack(side="left", padx=(0, 5))
        
        # Generate button
        def generate_password():
            new_password = self.password_generator.generate_password(length=16)
            password_entry.delete(0, tk.END)
            password_entry.insert(0, new_password)
            password_entry.configure(show="")
            eye_btn.configure(text="🙈")
        
        gen_btn = ctk.CTkButton(
            input_frame,
            text="🎲",
            width=40,
            height=40,
            command=generate_password,
            font=ctk.CTkFont(size=18),
            fg_color="#10B981",
            hover_color="#059669"
        )
        gen_btn.pack(side="left")
        
        # Strength indicator
        strength_frame = ctk.CTkFrame(field_frame, fg_color="transparent")
        strength_frame.pack(fill="x", pady=(5, 0))
        
        strength_label = ctk.CTkLabel(
            strength_frame,
            text="",
            font=ctk.CTkFont(size=11)
        )
        strength_label.pack(anchor="w")
        
        def on_password_change(event=None):
            pwd = password_entry.get()
            if pwd:
                score, strength, _ = self.password_generator.assess_strength(pwd)
                color = self.get_strength_color(strength)
                strength_label.configure(text=f"💪 {strength} ({score}%)", text_color=color)
            else:
                strength_label.configure(text="")
        
        password_entry.bind("<KeyRelease>", on_password_change)
        
        return password_entry


    def save_enhanced_account(self, dialog, entries, account=None):
        """Save account with all enhanced fields to database"""
        try:
            # Validate required fields
            name = entries["name"].get().strip()
            username = entries["username"].get().strip()
            password = entries["password"].get()

            if not name:
                self.show_message("error", "account_name_required", msg_type="error")
                return
            if not username:
                self.show_message("error", "Please enter a username or email", msg_type="error")
                return
            if not password or (account and password == "••••••••"):
                self.show_message("error", "password_required", msg_type="error")
                return
            
            # Check for duplicate account name before proceeding
            all_accounts = self.database.get_all_decrypted_accounts()
            is_duplicate = any(
                acc['name'].lower() == name.lower() and (not account or acc['id'] != account['id'])
                for acc in all_accounts
            )
            if is_duplicate:
                self.show_message("error", "duplicate_account_name_error", msg_type="error")
                return

            # Consolidate all data from the form into a dictionary
            form_data = {
                "name": name,
                "username": username,
                "password": password,
                "account_type": entries["account_type"].get(),
                "recovery_email": entries["recovery_email"].get().strip(),
                "phone_number": entries["phone_number"].get().strip(),
                "two_factor_enabled": entries["two_factor_enabled"].get(),
                "url": entries["url"].get().strip(),
                "notes": entries["notes"].get("1.0", tk.END).strip(),
                "category": entries["category"].get(),
            }

            if account:  # Edit existing
                if not self.verify_master_password_dialog():
                    return

                # Fetch the full existing account data to merge with changes
                existing_account_data = self.database.get_account_by_id(account['id'])
                if not existing_account_data:
                    self.show_message("error", "account_not_found_on_save", msg_type="error")
                    return
                
                # Merge form data into existing data
                existing_account_data.update(form_data)
                
                self.database.update_account(account["id"], existing_account_data)
                
                if self.password_reminder:
                    self.password_reminder.mark_as_changed(account["id"])
                
                self.update_expired_passwords_count()
                self.show_message("success", "update_success_message", account_name=name)
            
            else:  # Create new
                # Generate unique ID and create a full account object
                account_id = secrets.token_urlsafe(16)
                
                new_account_obj = Account(
                    id=account_id,
                    name=name,
                    username=username,
                    email=form_data['recovery_email'], # Using recovery as primary email for simplicity
                    url=form_data['url'],
                    notes=form_data['notes'],
                    created_at=datetime.now(),
                    updated_at=datetime.now(),
                    tags=[],
                    security_level=SecurityLevel.MEDIUM
                )
                
                # The add_account method now only handles the non-sensitive parts for the Account object
                # The password and other sensitive fields are passed in the form_data
                self.database.add_account(new_account_obj, username, password) # Pass all data
                self.show_message("success", "add_success_message", account_name=name)
            
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
        
        # Main container with better spacing
        main_container = ctk.CTkScrollableFrame(self.main_panel)
        main_container.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Header section with title and description
        header = ctk.CTkFrame(main_container, fg_color="transparent")
        header.pack(fill="x", padx=25, pady=(20, 10))
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(fill="x", anchor="w")
        
        ctk.CTkLabel(title_frame, text=self.lang_manager.get_string("password_generator_title"), 
                    font=ctk.CTkFont(size=28, weight="bold")).pack(side="left", anchor="w")
        
        desc_label = ctk.CTkLabel(title_frame, 
                                text="✨ Create secure, custom passwords with real-time strength analysis", 
                                font=ctk.CTkFont(size=12),
                                text_color="#888888")
        desc_label.pack(side="left", padx=(15, 0), anchor="w")
        
        # Quick Presets Section
        presets_frame = ctk.CTkFrame(main_container, fg_color=("gray90", "gray15"), corner_radius=12)
        presets_frame.pack(fill="x", padx=25, pady=15)
        
        presets_header = ctk.CTkLabel(presets_frame, text="🎯 Quick Presets", 
                                    font=ctk.CTkFont(size=14, weight="bold"))
        presets_header.pack(anchor="w", padx=15, pady=(12, 8))
        
        presets_btn_frame = ctk.CTkFrame(presets_frame, fg_color="transparent")
        presets_btn_frame.pack(fill="x", padx=15, pady=(0, 12))
        
        preset_configs = [
            ("🌐 Web", {"length": 16, "uppercase": True, "lowercase": True, "digits": True, "symbols": True, "ambiguous": False}),
            ("💼 Business", {"length": 20, "uppercase": True, "lowercase": True, "digits": True, "symbols": False, "ambiguous": True}),
            ("🔒 Banking", {"length": 24, "uppercase": True, "lowercase": True, "digits": True, "symbols": True, "ambiguous": False}),
            ("🎮 Social", {"length": 14, "uppercase": True, "lowercase": True, "digits": True, "symbols": False, "ambiguous": False}),
            ("🗄️ Database", {"length": 52, "uppercase": True, "lowercase": True, "digits": True, "symbols": True, "ambiguous": False}),
            ("🖥️ Server", {"length": 56, "uppercase": True, "lowercase": True, "digits": True, "symbols": True, "ambiguous": False}),
            ("🔐 Encryption Key", {"length": 64, "uppercase": True, "lowercase": True, "digits": True, "symbols": True, "ambiguous": False}),
            ("🏛️ Admin Account", {"length": 48, "uppercase": True, "lowercase": True, "digits": True, "symbols": True, "ambiguous": False}),
            ("☁️ Cloud Storage", {"length": 50, "uppercase": True, "lowercase": True, "digits": True, "symbols": True, "ambiguous": False}),
        ]
        
        for preset_name, preset_config in preset_configs:
            ctk.CTkButton(presets_btn_frame, text=preset_name, width=100, height=32,
                        command=lambda cfg=preset_config: self._apply_preset(cfg),
                        font=ctk.CTkFont(size=11)).pack(side="left", padx=5)
        
        # Main content with two columns
        content = ctk.CTkFrame(main_container, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=25, pady=15)
        
        # Left column - Settings
        settings_frame = ctk.CTkFrame(content, fg_color=("gray90", "gray15"), corner_radius=12)
        settings_frame.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=0)
        
        settings_title = ctk.CTkLabel(settings_frame, text="⚙️ " + self.lang_manager.get_string("generator_settings"), 
                    font=ctk.CTkFont(size=16, weight="bold"))
        settings_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        # Password Length with visual indicator
        length_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        length_frame.pack(fill="x", padx=20, pady=(10, 5))
        
        length_label_frame = ctk.CTkFrame(length_frame, fg_color="transparent")
        length_label_frame.pack(fill="x", pady=(0, 5))
        
        ctk.CTkLabel(length_label_frame, text=self.lang_manager.get_string("password_length"), 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", anchor="w")
        
        self.length_var = tk.IntVar(value=16)
        self.length_label = ctk.CTkLabel(length_label_frame, 
                                        text="16 characters", 
                                        font=ctk.CTkFont(size=12, weight="bold"),
                                        text_color="#3B82F6")
        self.length_label.pack(side="right", anchor="e")
        
        self.length_slider = ctk.CTkSlider(length_frame, from_=8, to=100, 
                                        variable=self.length_var, width=250,
                                        button_length=20)
        self.length_slider.pack(fill="x", pady=8)
        
        # Length indicator
        length_info = ctk.CTkLabel(length_frame, text="8 ─────────────────────────────────── 100", 
                                font=ctk.CTkFont(size=10),
                                text_color="#666666")
        length_info.pack(fill="x", pady=(5, 10))
        
        def update_length_label(value):
            length_val = int(float(value))
            self.length_label.configure(text=f"{length_val} characters")
            self.generate_password_gui()  # Auto-generate on slider change
        
        self.length_slider.configure(command=update_length_label)
        
        # Character types with better layout
        char_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        char_frame.pack(fill="x", padx=20, pady=15)
        
        char_title = ctk.CTkLabel(char_frame, text=self.lang_manager.get_string("character_types"), 
                    font=ctk.CTkFont(size=13, weight="bold"))
        char_title.pack(anchor="w", pady=(0, 10))
        
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
            ("Exclude Ambiguous (0,O,1,l,I)", self.exclude_ambiguous)
        ]
        
        for text, var in checkbox_options:
            check_frame = ctk.CTkFrame(char_frame, fg_color="transparent")
            check_frame.pack(fill="x", pady=4)
            check_box = ctk.CTkCheckBox(check_frame, text=text, variable=var,
                                    command=self.generate_password_gui,
                                    font=ctk.CTkFont(size=12))
            check_box.pack(anchor="w")
        
        # Generate button - More prominent
        gen_btn_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        gen_btn_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkButton(gen_btn_frame, text="🎲 Generate Password", 
                    command=self.generate_password_gui, height=50,
                    font=ctk.CTkFont(size=14, weight="bold"),
                    fg_color="#3B82F6",
                    hover_color="#2563EB").pack(fill="x")
        
        # Right column - Results
        result_frame = ctk.CTkFrame(content, fg_color=("gray90", "gray15"), corner_radius=12)
        result_frame.pack(side="right", fill="both", expand=True, padx=(12, 0), pady=0)
        
        result_title = ctk.CTkLabel(result_frame, text="🔐 " + self.lang_manager.get_string("generated_password"), 
                    font=ctk.CTkFont(size=16, weight="bold"))
        result_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        # Password display with enhanced styling
        password_display_frame = ctk.CTkFrame(result_frame, fg_color="transparent")
        password_display_frame.pack(fill="x", padx=20, pady=10)
        
        self.generated_password_entry = ctk.CTkEntry(password_display_frame, width=300, height=55,
                                                    font=ctk.CTkFont(size=16, family="monospace"),
                                                    border_width=2,
                                                    border_color="#3B82F6")
        self.generated_password_entry.pack(fill="x", pady=(0, 12))
        
        # Action buttons
        button_frame = ctk.CTkFrame(password_display_frame, fg_color="transparent")
        button_frame.pack(fill="x")
        
        ctk.CTkButton(button_frame, text="Copy", 
                    height=40,
                    command=self.copy_generated_password,
                    font=ctk.CTkFont(size=12),
                    fg_color="#10B981",
                    hover_color="#059669").pack(side="left", padx=(0, 8), fill="x", expand=True)
        
        ctk.CTkButton(button_frame, text="🔄 Regenerate", 
                    height=40,
                    command=self.generate_password_gui,
                    font=ctk.CTkFont(size=12),
                    fg_color="#F59E0B",
                    hover_color="#D97706").pack(side="left", padx=4, fill="x", expand=True)
        
        ctk.CTkButton(button_frame, text="👁️ Show", 
                    height=40,
                    command=self._toggle_password_visibility,
                    font=ctk.CTkFont(size=12)).pack(side="right", padx=(8, 0), fill="x", expand=True)
        
        # Strength Analysis with visual meter
        self.strength_frame = ctk.CTkFrame(result_frame, fg_color="transparent")
        self.strength_frame.pack(fill="x", padx=20, pady=20)
        
        strength_title = ctk.CTkLabel(self.strength_frame, 
                                    text=self.lang_manager.get_string("strength_analysis_title"), 
                                    font=ctk.CTkFont(size=14, weight="bold"))
        strength_title.pack(anchor="w", pady=(0, 10))
        
        # Strength meter background
        self.strength_meter_bg = ctk.CTkFrame(self.strength_frame, fg_color=("gray70", "gray40"), 
                                            height=8, corner_radius=4)
        self.strength_meter_bg.pack(fill="x", pady=(0, 8))
        self.strength_meter_bg.pack_propagate(False)
        
        # Strength meter fill (will be updated dynamically)
        self.strength_meter = ctk.CTkFrame(self.strength_meter_bg, fg_color="#D1D5DB", 
                                        height=8, corner_radius=4)
        self.strength_meter.pack(side="left", fill="y", expand=False)
        
        # Strength details
        self.strength_details = ctk.CTkLabel(self.strength_frame, 
                                            text=self.lang_manager.get_string("generate_to_see_analysis"),
                                            font=ctk.CTkFont(size=12),
                                            justify="left")
        self.strength_details.pack(anchor="w", pady=5)
        
        # Password statistics
        self.stats_frame = ctk.CTkFrame(result_frame, fg_color="transparent")
        self.stats_frame.pack(fill="x", padx=20, pady=10)
        
        self.stats_label = ctk.CTkLabel(self.stats_frame, text="", font=ctk.CTkFont(size=11),
                                    text_color="#888888")
        self.stats_label.pack(anchor="w")
        
        # Generate initial password
        self.generate_password_gui()
    
    def _apply_preset(self, preset_config):
        """Apply preset configuration to the generator settings"""
        self.length_var.set(preset_config["length"])
        self.use_uppercase.set(preset_config["uppercase"])
        self.use_lowercase.set(preset_config["lowercase"])
        self.use_digits.set(preset_config["digits"])
        self.use_symbols.set(preset_config["symbols"])
        self.exclude_ambiguous.set(preset_config["ambiguous"])
        self.generate_password_gui()
    
    def _toggle_password_visibility(self):
        """Toggle password visibility in the generator"""
        if self.generated_password_entry.cget("show") == "*":
            self.generated_password_entry.configure(show="")
        else:
            self.generated_password_entry.configure(show="*")

    def generate_password_gui(self):
        try:
            # Validate that at least one character type is selected
            if not any([self.use_uppercase.get(), self.use_lowercase.get(), 
                    self.use_digits.get(), self.use_symbols.get()]):
                self.show_message("error", "Please select at least one character type", msg_type="error")
                return
            
            password = self.password_generator.generate_password(
                length=self.length_var.get(),
                use_uppercase=self.use_uppercase.get(),
                use_lowercase=self.use_lowercase.get(),
                use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(),
                exclude_ambiguous=self.exclude_ambiguous.get()
            )
            
            # Clear and insert with visual feedback
            self.generated_password_entry.delete(0, tk.END)
            self.generated_password_entry.insert(0, password)
            
            # Update border color to indicate successful generation
            self.generated_password_entry.configure(border_color="#10B981")
            # Check if widget still exists before scheduling the update
            try:
                self.root.after(1500, lambda: self._reset_entry_border())
            except Exception as e:
                logger.debug(f"Could not schedule border reset: {e}")
            
            self.update_strength_analysis(password)
        except Exception as e:
            self.show_message("Error", f"Failed to generate password: {str(e)}", msg_type="error")


    def _reset_entry_border(self):
        """Safely reset the entry border color after password generation."""
        try:
            # Check if widget still exists and is valid
            if hasattr(self, 'generated_password_entry') and self.generated_password_entry.winfo_exists():
                self.generated_password_entry.configure(border_color="#3B82F6")
        except Exception as e:
            logger.debug(f"Could not reset entry border: {e}")

    def update_strength_analysis(self, password):
        score, strength, recommendations = self.password_generator.assess_strength(password)
        strength_color = self.get_strength_color(strength)
        
        # Update strength meter
        meter_width = int((score / 100) * 300)  # Max width 300px
        if score < 40:
            meter_color = "#EF4444"  # Red
        elif score < 60:
            meter_color = "#F59E0B"  # Orange
        elif score < 80:
            meter_color = "#FBBF24"  # Yellow
        else:
            meter_color = "#10B981"  # Green
        
        self.strength_meter.configure(fg_color=meter_color)
        self.strength_meter.configure(width=meter_width)
        
        # Build strength details text
        strength_emoji = "🔴" if score < 40 else "🟠" if score < 60 else "🟡" if score < 80 else "🟢"
        strength_text = f"{strength_emoji} {strength} ({score}%)"
        
        stats_text = f"Length: {len(password)} | Unique: {len(set(password))} | Entropy: {score}%"
        
        # Build recommendations if weak
        detail_text = strength_text + "\n" + stats_text
        if recommendations:
            detail_text += "\n\n💡 Suggestions:\n"
            for rec in recommendations[:3]:  # Show top 3 recommendations
                detail_text += f"• {rec}\n"
        
        self.strength_details.configure(
            text=detail_text,
            text_color=strength_color,
            justify="left"
        )
        
        # Update stats label
        char_types = []
        if any(c.isupper() for c in password):
            char_types.append("Uppercase")
        if any(c.islower() for c in password):
            char_types.append("Lowercase")
        if any(c.isdigit() for c in password):
            char_types.append("Digits")
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            char_types.append("Symbols")
        
        self.stats_label.configure(
            text=f"📊 Character Types: {', '.join(char_types) if char_types else 'None'}"
        )

    def copy_generated_password(self):
        password = self.generated_password_entry.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            
            # Create temporary success feedback
            self.show_message("copied_title", "✅ Password copied to clipboard!", msg_type="info")
            
            # Auto-clear clipboard after 30 seconds for security
            self.root.after(30000, lambda: self.root.clipboard_clear())
        else:
            self.show_message("error", "no_password_to_copy", msg_type="error")

    def show_security_report(self):
        """Enhanced security report with modern UI, charts, and actionable insights"""
        for widget in self.main_panel.winfo_children():
            widget.destroy()

        # Header with refresh button
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)

        ctk.CTkLabel(header, text=self.lang_manager.get_string("security_report_title"),
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)

        def refresh_report():
            self.show_security_report()

        ctk.CTkButton(header, text="🔄 Refresh", command=refresh_report,
                      width=120, height=45, font=ctk.CTkFont(size=16)).pack(side="right", padx=25)

        # Main scrollable content
        content = ctk.CTkScrollableFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)

        try:
            # Collect all decrypted account data at once
            all_accounts = self.database.get_all_decrypted_accounts()

            # Initialize counters and lists
            total_accounts = len(all_accounts)
            weak_passwords = []
            medium_passwords = []
            strong_passwords = []
            duplicate_passwords = []
            reused_passwords = []
            old_passwords = []  # Passwords not changed in 90+ days
            very_old_passwords = []  # Passwords not changed in 180+ days
            password_counts = {}
            password_ages = {}

            # Analyze each account
            from datetime import datetime, timedelta
            now = datetime.now()

            for account in all_accounts:
                name = account.get('name', 'N/A')
                password = account.get('password')
                updated_at = account.get('updated_at')

                if password:
                    # Check password strength
                    score, strength, recommendations = self.password_generator.assess_strength(password)

                    if score < 40:
                        # Store the whole account dict to have access to the ID later
                        weak_passwords.append((account, strength, score, recommendations))
                    elif score < 70:
                        medium_passwords.append((name, strength, score))
                    else:
                        strong_passwords.append((name, strength, score))

                    # Check for duplicates
                    if password in password_counts:
                        password_counts[password].append(name)
                    else:
                        password_counts[password] = [name]

                    # Check password age
                    if updated_at:
                        try:
                            updated = datetime.fromisoformat(updated_at)
                            age_days = (now - updated).days
                            password_ages[name] = age_days

                            if age_days >= 180:
                                very_old_passwords.append((name, age_days))
                            elif age_days >= 90:
                                old_passwords.append((name, age_days))
                        except:
                            pass
            
            # Identify duplicate and reused passwords
            for password, names in password_counts.items():
                if len(names) > 1:
                    duplicate_passwords.extend(names)
                    reused_passwords.append((password, names))
            
            # Calculate security score (0-100)
            security_score = 0
            if total_accounts > 0:
                strong_percentage = (len(strong_passwords) / total_accounts) * 40
                no_duplicates = (1 - (len(set(duplicate_passwords)) / total_accounts)) * 30
                password_freshness = (1 - (len(old_passwords + very_old_passwords) / total_accounts)) * 30
                security_score = int(strong_percentage + no_duplicates + password_freshness)
            
            # ============= OVERALL SECURITY SCORE CARD =============
            score_card = ctk.CTkFrame(content, fg_color=("gray90", "gray15"), corner_radius=15)
            score_card.pack(fill="x", padx=20, pady=(0, 20))
            
            score_header = ctk.CTkFrame(score_card, fg_color="transparent")
            score_header.pack(fill="x", padx=20, pady=(20, 10))
            
            ctk.CTkLabel(score_header, text="🛡️ Overall Security Score", 
                        font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
            
            # Visual score indicator
            score_display = ctk.CTkFrame(score_card, fg_color="transparent")
            score_display.pack(fill="x", padx=20, pady=15)
            
            # Determine color and rating
            if security_score >= 80:
                score_color = "#10B981"  # Green
                rating = "Excellent"
                emoji = "🟢"
            elif security_score >= 60:
                score_color = "#F59E0B"  # Orange
                rating = "Good"
                emoji = "🟡"
            elif security_score >= 40:
                score_color = "#FF6B6B"  # Light Red
                rating = "Fair"
                emoji = "🟠"
            else:
                score_color = "#EF4444"  # Red
                rating = "Poor"
                emoji = "🔴"
            
            # Large score display
            score_frame = ctk.CTkFrame(score_display, fg_color="transparent")
            score_frame.pack(side="left", padx=(0, 30))
            
            ctk.CTkLabel(score_frame, text=f"{security_score}", 
                        font=ctk.CTkFont(size=72, weight="bold"),
                        text_color=score_color).pack()
            
            ctk.CTkLabel(score_frame, text="/100", 
                        font=ctk.CTkFont(size=24),
                        text_color="gray").pack()
            
            # Rating and breakdown
            details_frame = ctk.CTkFrame(score_display, fg_color="transparent")
            details_frame.pack(side="left", fill="both", expand=True)
            
            ctk.CTkLabel(details_frame, text=f"{emoji} {rating}", 
                        font=ctk.CTkFont(size=18, weight="bold"),
                        text_color=score_color).pack(anchor="w", pady=(0, 10))
            
            ctk.CTkLabel(details_frame, 
                        text=f"📊 {total_accounts} Total Accounts\n"
                            f"✅ {len(strong_passwords)} Strong Passwords\n"
                            f"⚠️ {len(weak_passwords)} Weak Passwords\n"
                            f"🔄 {len(set(duplicate_passwords))} Reused Passwords",
                        font=ctk.CTkFont(size=13),
                        justify="left").pack(anchor="w")
            
            # ============= QUICK STATS GRID =============
            stats_grid = ctk.CTkFrame(content, fg_color="transparent")
            stats_grid.pack(fill="x", padx=20, pady=(0, 20))
            
            def create_stat_card(parent, title, value, subtitle, color, row, col):
                card = ctk.CTkFrame(parent, fg_color=("gray90", "gray15"), corner_radius=12)
                card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
                
                ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12),
                            text_color="gray").pack(pady=(15, 5))
                
                ctk.CTkLabel(card, text=str(value), font=ctk.CTkFont(size=32, weight="bold"),
                            text_color=color).pack(pady=5)
                
                ctk.CTkLabel(card, text=subtitle, font=ctk.CTkFont(size=11),
                            text_color="gray").pack(pady=(0, 15))
            
            # Configure grid weights
            for i in range(4):
                stats_grid.columnconfigure(i, weight=1)
            
            create_stat_card(stats_grid, "Strong", len(strong_passwords), "passwords", "#10B981", 0, 0)
            create_stat_card(stats_grid, "Medium", len(medium_passwords), "passwords", "#F59E0B", 0, 1)
            create_stat_card(stats_grid, "Weak", len(weak_passwords), "passwords", "#EF4444", 0, 2)
            create_stat_card(stats_grid, "Reused", len(set(duplicate_passwords)), "passwords", "#FF6B6B", 0, 3)
            
            # ============= WEAK PASSWORDS SECTION =============
            if weak_passwords:
                weak_frame = ctk.CTkFrame(content, fg_color=("gray90", "gray15"), corner_radius=12)
                weak_frame.pack(fill="x", padx=20, pady=(0, 20))
                
                weak_header = ctk.CTkFrame(weak_frame, fg_color="transparent")
                weak_header.pack(fill="x", padx=20, pady=(15, 10))
                
                ctk.CTkLabel(weak_header, text="⚠️ Accounts with Weak Passwords", 
                            font=ctk.CTkFont(size=18, weight="bold"),
                            text_color="#FF6B6B").pack(side="left")
                
                ctk.CTkLabel(weak_header, text=f"{len(weak_passwords)} accounts need attention", 
                            font=ctk.CTkFont(size=12),
                            text_color="gray").pack(side="right")
                
                # List weak passwords
                for account_data, strength, score, recommendations in weak_passwords:
                    name = account_data.get('name', 'N/A')
                    account_id = account_data.get('id')
                    
                    account_frame = ctk.CTkFrame(weak_frame, fg_color=("gray85", "gray20"), corner_radius=8)
                    account_frame.pack(fill="x", padx=15, pady=8)
                    
                    info_frame = ctk.CTkFrame(account_frame, fg_color="transparent")
                    info_frame.pack(fill="x", padx=15, pady=12)
                    
                    # Account name and strength
                    left_info = ctk.CTkFrame(info_frame, fg_color="transparent")
                    left_info.pack(side="left", fill="both", expand=True)
                    
                    ctk.CTkLabel(left_info, text=name, 
                                font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
                    
                    ctk.CTkLabel(left_info, text=f"Strength: {strength} ({score}%)", 
                                font=ctk.CTkFont(size=12),
                                text_color=self.get_strength_color(strength)).pack(anchor="w", pady=(3, 0))
                    
                    # Recommendations
                    if recommendations:
                        rec_text = "💡 " + ", ".join(recommendations[:2])
                        ctk.CTkLabel(left_info, text=rec_text, 
                                    font=ctk.CTkFont(size=11),
                                    text_color="gray",
                                    wraplength=400).pack(anchor="w", pady=(5, 0))
                    
                    # Quick fix button
                    def make_edit_wrapper(acc_id):
                        def edit_account_wrapper():
                            # Find the full account data from the already fetched list
                            account_to_edit = next((acc for acc in all_accounts if acc['id'] == acc_id), None)
                            if account_to_edit:
                                self.show_account_dialog(account_to_edit)
                        return edit_account_wrapper
                    
                    if account_id:
                        ctk.CTkButton(info_frame, text="🔧 Fix Now", 
                                    command=make_edit_wrapper(account_id),
                                    width=100, height=35,
                                    fg_color="#3B82F6",
                                    hover_color="#2563EB").pack(side="right")
            
            # ============= REUSED PASSWORDS SECTION =============
            if reused_passwords:
                reused_frame = ctk.CTkFrame(content, fg_color=("gray90", "gray15"), corner_radius=12)
                reused_frame.pack(fill="x", padx=20, pady=(0, 20))
                
                reused_header = ctk.CTkFrame(reused_frame, fg_color="transparent")
                reused_header.pack(fill="x", padx=20, pady=(15, 10))
                
                ctk.CTkLabel(reused_header, text="🔄 Reused Passwords", 
                            font=ctk.CTkFont(size=18, weight="bold"),
                            text_color="#FF6B6B").pack(side="left")
                
                ctk.CTkLabel(reused_header, text=f"{len(reused_passwords)} password(s) used multiple times", 
                            font=ctk.CTkFont(size=12),
                            text_color="gray").pack(side="right")
                
                for password, names in reused_passwords:
                    dup_frame = ctk.CTkFrame(reused_frame, fg_color=("gray85", "gray20"), corner_radius=8)
                    dup_frame.pack(fill="x", padx=15, pady=8)
                    
                    ctk.CTkLabel(dup_frame, 
                                text=f"Shared by {len(names)} accounts: {', '.join(names)}", 
                                font=ctk.CTkFont(size=13),
                                wraplength=700,
                                justify="left").pack(anchor="w", padx=15, pady=12)
            
            # ============= PASSWORD AGE SECTION =============
            if old_passwords or very_old_passwords:
                age_frame = ctk.CTkFrame(content, fg_color=("gray90", "gray15"), corner_radius=12)
                age_frame.pack(fill="x", padx=20, pady=(0, 20))
                
                age_header = ctk.CTkFrame(age_frame, fg_color="transparent")
                age_header.pack(fill="x", padx=20, pady=(15, 10))
                
                ctk.CTkLabel(age_header, text="⏰ Outdated Passwords", 
                            font=ctk.CTkFont(size=18, weight="bold"),
                            text_color="#F59E0B").pack(side="left")
                
                total_old = len(old_passwords) + len(very_old_passwords)
                ctk.CTkLabel(age_header, text=f"{total_old} password(s) need updating", 
                            font=ctk.CTkFont(size=12),
                            text_color="gray").pack(side="right")
                
                # Very old passwords (180+ days)
                if very_old_passwords:
                    for name, age_days in sorted(very_old_passwords, key=lambda x: x[1], reverse=True):
                        old_frame = ctk.CTkFrame(age_frame, fg_color=("gray85", "gray20"), corner_radius=8)
                        old_frame.pack(fill="x", padx=15, pady=5)
                        
                        ctk.CTkLabel(old_frame, 
                                    text=f"🔴 {name} - Not changed in {age_days} days", 
                                    font=ctk.CTkFont(size=13)).pack(anchor="w", padx=15, pady=10)
                
                # Old passwords (90-179 days)
                if old_passwords:
                    for name, age_days in sorted(old_passwords, key=lambda x: x[1], reverse=True):
                        old_frame = ctk.CTkFrame(age_frame, fg_color=("gray85", "gray20"), corner_radius=8)
                        old_frame.pack(fill="x", padx=15, pady=5)
                        
                        ctk.CTkLabel(old_frame, 
                                    text=f"🟡 {name} - Not changed in {age_days} days", 
                                    font=ctk.CTkFont(size=13)).pack(anchor="w", padx=15, pady=10)
            
            # ============= SECURITY TIPS SECTION =============
            tips_frame = ctk.CTkFrame(content, fg_color=("gray90", "gray15"), corner_radius=12)
            tips_frame.pack(fill="x", padx=20, pady=(0, 20))
            
            tips_header = ctk.CTkFrame(tips_frame, fg_color="transparent")
            tips_header.pack(fill="x", padx=20, pady=(15, 10))
            
            ctk.CTkLabel(tips_header, text="💡 Security Recommendations", 
                        font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w")
            
            # Generate personalized tips based on analysis
            tips = []
            
            if len(weak_passwords) > 0:
                tips.append(("⚠️ Urgent", f"Update {len(weak_passwords)} weak password(s) immediately", "#EF4444"))
            
            if len(reused_passwords) > 0:
                tips.append(("🔄 Important", "Use unique passwords for each account to prevent cascading breaches", "#FF6B6B"))
            
            if len(very_old_passwords) > 0:
                tips.append(("⏰ Recommended", "Change passwords that haven't been updated in 6+ months", "#F59E0B"))
            
            # General tips
            general_tips = [
                ("🔐 Best Practice", "Use passwords with at least 16 characters", "#3B82F6"),
                ("🎲 Best Practice", "Use the password generator for stronger passwords", "#3B82F6"),
                ("✅ Best Practice", "Enable 2FA on all accounts that support it", "#10B981"),
            ]
            
            # Add 2-3 general tips
            import random
            tips.extend(random.sample(general_tips, min(3, len(general_tips))))
            
            for priority, tip, color in tips:
                tip_item = ctk.CTkFrame(tips_frame, fg_color=("gray85", "gray20"), corner_radius=8)
                tip_item.pack(fill="x", padx=15, pady=5)
                
                tip_content = ctk.CTkFrame(tip_item, fg_color="transparent")
                tip_content.pack(fill="x", padx=15, pady=10)
                
                ctk.CTkLabel(tip_content, text=priority, 
                            font=ctk.CTkFont(size=12, weight="bold"),
                            text_color=color).pack(side="left", padx=(0, 10))
                
                ctk.CTkLabel(tip_content, text=tip, 
                            font=ctk.CTkFont(size=12),
                            wraplength=600).pack(side="left", fill="x", expand=True)
            
            # ============= QUICK ACTIONS =============
            actions_frame = ctk.CTkFrame(content, fg_color="transparent")
            actions_frame.pack(fill="x", padx=20, pady=(0, 20))
            
            ctk.CTkLabel(actions_frame, text="⚡ Quick Actions", 
                        font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", pady=(0, 10))
            
            button_grid = ctk.CTkFrame(actions_frame, fg_color="transparent")
            button_grid.pack(fill="x")
            
            for i in range(3):
                button_grid.columnconfigure(i, weight=1)
            
            # The weak_passwords list now contains the full account dictionary
            ctk.CTkButton(button_grid, text="🔧 Fix All Weak Passwords",
                        command=lambda: self.fix_weak_passwords(weak_passwords),
                        height=45, font=ctk.CTkFont(size=14)).grid(row=0, column=0, padx=5, sticky="ew")
            
            ctk.CTkButton(button_grid, text="🎲 Generate Strong Password",
                        command=self.show_password_generator,
                        height=45, font=ctk.CTkFont(size=14)).grid(row=0, column=1, padx=5, sticky="ew")
            
        except Exception as e:
            error_frame = ctk.CTkFrame(content, fg_color=("gray90", "gray15"))
            error_frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            ctk.CTkLabel(error_frame, 
                        text=f"❌ Error generating security report:\n\n{str(e)}", 
                        font=ctk.CTkFont(size=14),
                        text_color="#FF4444",
                        justify="center").pack(pady=50)

    def fix_weak_passwords(self, weak_passwords_list):
        """Helper method to guide user through fixing weak passwords"""
        if not weak_passwords_list:
            self.show_message("info", "No weak passwords to fix!", msg_type="info")
            return
        
        # Show dialog with list of accounts to fix
        dialog = ThemedToplevel(self.root)
        dialog.title("Fix Weak Passwords")
        dialog.geometry("600x500")
        dialog.grab_set()
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🔧 Fix Weak Passwords", 
                    font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(0, 10))
        
        ctk.CTkLabel(main_frame, 
                    text=f"You have {len(weak_passwords_list)} account(s) with weak passwords.\n"
                        "Click on any account below to update its password.",
                    font=ctk.CTkFont(size=12),
                    justify="center").pack(pady=(0, 20))
        
        # Scrollable list of accounts
        accounts_frame = ctk.CTkScrollableFrame(main_frame, height=300)
        accounts_frame.pack(fill="both", expand=True, pady=(0, 15))
        
        for account_data, strength, score, recommendations in weak_passwords_list:
            account_item = ctk.CTkFrame(accounts_frame, fg_color=("gray85", "gray20"), corner_radius=8)
            account_item.pack(fill="x", pady=5, padx=5)
            
            def make_edit_wrapper(account_to_edit):
                def edit_this_account():
                    dialog.destroy()
                    self.show_account_dialog(account_to_edit)
                return edit_this_account
            
            name = account_data.get('name', 'N/A')
            btn = ctk.CTkButton(account_item, text=f"📝 {name} ({strength} - {score}%)",
                                command=make_edit_wrapper(account_data),
                                height=40,
                                anchor="w",
                                fg_color="transparent",
                                hover_color=("gray75", "gray30"))
            btn.pack(fill="x", padx=10, pady=8)
        
        ctk.CTkButton(main_frame, text="Close", command=dialog.destroy,
                    width=120, height=40).pack(pady=(10, 0))
        
        
    def show_update_checker(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()

        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text=self.lang_manager.get_string("check_for_updates_title"), 
                    font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)

        content = ctk.CTkFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)

        info_label = ctk.CTkLabel(content, text=f"Current Version: {self.version_data.get('version', 'N/A')}",
                                font=ctk.CTkFont(size=14))
        info_label.pack(pady=20)

        update_button = ctk.CTkButton(content, text=self.lang_manager.get_string("check_updates_now"),
                                    command=self.check_for_updates_action,
                                    width=200, height=50, font=ctk.CTkFont(size=16))
        update_button.pack(pady=10)

        url_entry = ctk.CTkEntry(content, width=350)
        url_entry.insert(0, self.lang_manager.get_string("update_url_placeholder"))
        url_entry.configure(state="readonly")
        url_entry.pack(pady=10)


        contact_button = ctk.CTkButton(content, text=self.lang_manager.get_string("contact_developer"),
                                    command=self.contact_developer,
                                    width=200, height=50, font=ctk.CTkFont(size=16))
        contact_button.pack(pady=10)

        self.update_status_label = ctk.CTkLabel(content, text="", font=ctk.CTkFont(size=14))
        self.update_status_label.pack(pady=20)

    def check_for_updates_action(self):
        self.update_status_label.configure(text=self.lang_manager.get_string("checking_for_updates"), text_color=("#3B82F6", "#1E40AF"))
        
        # --- Simulated Update Check ---
        hardcoded_latest_version = "1.0.1" 
        current_version = self.version_data.get("version", "0.0.0")

        def perform_check():
            if hardcoded_latest_version > current_version:
                update_message = self.lang_manager.get_string("update_available", latest_version=hardcoded_latest_version)
                update_color = "#FFA500"  # Orange for "update available"
            else:
                update_message = self.lang_manager.get_string("no_updates_available")
                update_color = "#44FF44" # Green for "up-to-date"
            
            self.update_status_label.configure(text=update_message, text_color=update_color)

        # Simulate a network request delay
        self.root.after(2000, perform_check)

    def contact_developer(self):
        webbrowser.open_new_tab("https://wa.me/212623422858")

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
            self.show_message("error", "Account locked", msg_type="error")
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

    def secure_logout(self):
        """Securely logout: sync data, clear memory, close application safely"""
        logger.info("===== SECURE LOGOUT INITIATED =====")
        
        try:
            # Step 1: Confirm logout with user
            if not messagebox.askyesno(
                "Confirm Logout",
                "Are you sure you want to logout?"
            ):
                logger.info("Logout cancelled by user")
                return
            
            logger.info("User confirmed logout")
            
            # Step 3: Stop password reminder thread
            try:
                if self.password_reminder:
                    self.password_reminder.stop()
                    logger.info("Password reminder thread stopped")
            except Exception as e:
                logger.error(f"Error stopping password reminder: {e}")
            
            # Step 4: Update trial manager status (non-blocking)
            try:
                def update_status_bg():
                    try:
                        if hasattr(self, 'tamper_manager'):
                            logger.info("Updating tamper manager shutdown status")
                            self.tamper_manager.update_shutdown_status('SHUTDOWN_CLEAN')
                    except Exception as e:
                        logger.error(f"Error updating shutdown status: {e}")
                
                # Run in background thread to prevent blocking
                import threading
                status_thread = threading.Thread(target=update_status_bg, daemon=True)
                status_thread.start()
                status_thread.join(timeout=2.0)  # Wait max 2 seconds
            except Exception as e:
                logger.error(f"Error updating shutdown status: {e}")
            
            # Step 5: Update tamper manager status (already handled in step 4)
            # Removed duplicate code
            
            # Step 6: Sync all files to secure storage
            try:
                if self.secure_file_manager and self.authenticated and self.database:
                    logger.info("Starting file synchronization to secure storage...")
                    # Ensure all database changes are flushed to disk
                    self.database._checkpoint_databases()
                    logger.info("Databases checkpointed")
                    
                    self.secure_file_manager.sync_all_files()
                    logger.info("All files synced to secure storage")
            except Exception as e:
                logger.error(f"Error syncing files: {e}")
            
            # Step 7: Clear sensitive data from memory
            try:
                logger.info("Clearing sensitive data from memory...")
                
                # Clear master password and authentication
                self.authenticated = False
                if hasattr(self, 'master_password_entry'):
                    self.master_password_entry.delete(0, "end")
                
                # Clear crypto manager
                if self.crypto:
                    self.crypto.key = None
                    logger.info("Crypto manager cleared")
                
                # Clear database
                if self.database:
                    if hasattr(self.database, 'close'):
                        self.database.close()
                    self.database = None
                    logger.info("Database cleared")
                
                # Clear accounts list
                self.accounts = []
                logger.info("Accounts list cleared")
                
                # Clear secure file manager keys
                if self.secure_file_manager:
                    self.secure_file_manager.encryption_key = None
                    if hasattr(self.secure_file_manager, 'master_password'):
                        self.secure_file_manager.master_password = None
                    logger.info("Secure file manager keys cleared")
                
                # Clear settings
                self.settings = {}
                logger.info("Settings cleared")
                
                # Clear cached passwords/data
                import gc
                gc.collect()  # Force garbage collection to free memory
                logger.info("Garbage collection performed")
                
            except Exception as e:
                logger.error(f"Error clearing sensitive data: {e}")
            
            # Step 8: Clean temporary files
            try:
                logger.info("Cleaning temporary files...")
                if self.secure_file_manager:
                    temp_dir = self.secure_file_manager.temp_dir if hasattr(self.secure_file_manager, 'temp_dir') else None
                    if temp_dir and os.path.exists(temp_dir):
                        import shutil
                        # Securely delete temp directory
                        for root, dirs, files in os.walk(temp_dir, topdown=False):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    # Overwrite file with random data before deletion (secure deletion)
                                    with open(file_path, 'rb+') as f:
                                        size = os.path.getsize(file_path)
                                        f.write(os.urandom(size))
                                    os.remove(file_path)
                                    logger.info(f"Securely deleted: {file_path}")
                                except Exception as e:
                                    logger.error(f"Error securely deleting {file_path}: {e}")
                                    try:
                                        os.remove(file_path)
                                    except:
                                        pass
                            for dir in dirs:
                                try:
                                    os.rmdir(os.path.join(root, dir))
                                except:
                                    pass
                        logger.info("Temporary files cleaned")
            except Exception as e:
                logger.error(f"Error cleaning temporary files: {e}")
            
            # Step 9: Show logout success message and close application
            logger.info("Logout completed successfully")
            logger.info("===== SECURE LOGOUT COMPLETED =====")
            
            messagebox.showinfo(
                "Logout Successful",
                "All sensitive data has been cleared from memory and temporary files.\n\n"
                "The application will now close safely...."
            )
            
            self.root.destroy()
            
        except Exception as e:
            logger.error(f"Unexpected error during secure logout: {e}", exc_info=True)
            messagebox.showerror(
                "Logout Error",
                f"An error occurred during logout:\n{str(e)}\n\n"
                "The application will now close anyway for security."
            )
            self.root.destroy()

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
                    if self.authenticated and self.database:
                        # Ensure all database changes are flushed to disk
                        self.database._checkpoint_databases()
                        self.secure_file_manager.sync_all_files()
                    self.secure_file_manager.cleanup_temp_files()
                    logger.info("Secure cleanup completed")
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")

import sys
import subprocess

def build_executable():
    """Builds the executable using PyInstaller."""
    import platform
    
    # Correct --add-data syntax for different platforms
    if platform.system() == 'Windows':
        add_data_arg = 'icons;icons'  # Windows uses semicolon
    else:
        add_data_arg = 'icons:icons'  # Unix-like systems use colon
    
    command = [
        'pyinstaller',
        '--name', 'SecureVault Pro',
        '--noconfirm',
        '--onefile',
        '--windowed',
        '--hidden-import', 'desktop_notifier.resources',
        '--add-data', add_data_arg,
        'main.py'
    ]
    
    print(f"Running command: {' '.join(command)}")
    
    try:
        proc = subprocess.run(command, check=True, capture_output=True, text=True,
                              cwd=os.path.dirname(os.path.abspath(__file__)))
        print(proc.stdout)
        print("\nBuild successful! Executable is in the 'dist' folder.")
    except subprocess.CalledProcessError as e:
        print(f"\nBuild failed with error: {e}")
        print("STDOUT:")
        print(e.stdout)
        print("STDERR:")
        print(e.stderr)
    except FileNotFoundError:
        print("\nPyInstaller is not installed. Please install it using: pip install pyinstaller")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        
def main():
    # Check if program is already running
    lock = check_single_instance()
    if lock is None:
        # Another instance is already running
        try:
            import tkinter.messagebox as msgbox
            msgbox.showwarning(
                "Program Already Running",
                "⚠️ SecureVault Pro is already running!\n\n"
                "Multiple instances cannot be opened simultaneously.\n\n"
                "Please close the existing instance and try again."
            )
        except Exception as e:
            print(f"Warning: {e}")
        return
    
    if len(sys.argv) > 1 and sys.argv[1] == 'build':
        print("Build process started...")
        build_executable()
        return

    try:
        setup_logging()
        logger.info("Starting SecureVault Pro...")
        app = ModernPasswordManagerGUI()
        app.root.app = app  # Attach app instance to root
        logger.info("Application initialized successfully")
        app.run()
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        logger.info("Please ensure all required dependencies are installed:")
        logger.info("pip install customtkinter cryptography pillow desktop_notifier pyotp qrcode[pil]")
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Startup Error",
                           f"Failed to start SecureVault Pro:\n\n{str(e)}\n\n"
                           f"Please check the console for more details.")
        except:
            pass

if __name__ == "__main__":
    main()