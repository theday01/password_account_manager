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
from secure_backup_manager import SecureBackupManager, BackupGUI, BackupScheduler

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
            self.metadata_db = secure_file_manager.get_metadata_db_path()
            self.sensitive_db = secure_file_manager.get_sensitive_db_path()
            self.salt_path = secure_file_manager.get_salt_path()
            self.integrity_path = secure_file_manager.get_integrity_path()
        else:
            self.metadata_db = f"{db_path}_metadata.db"
            self.sensitive_db = f"{db_path}_sensitive.db"
            self.salt_path = f"{db_path}_salt"
            self.integrity_path = f"{db_path}_integrity"
        self.integrity_key = None
        self.encryption_key = None
        self.last_integrity_error = False
        
    def initialize_database(self, master_password: str):
        print("🔧 DATABASE: Starting database initialization...")
        salt = self.crypto.generate_salt()
        self.encryption_key = self.crypto.generate_key_from_password(master_password, salt)
        self.integrity_key = self.crypto.generate_key_from_password(master_password + "_integrity", salt)
        print(f"✅ DATABASE: Generated salt ({len(salt)} bytes) and encryption keys")
        try:
            with open(self.salt_path, "wb") as f:
                f.write(salt)
            print(f"✅ DATABASE: Salt saved to {self.salt_path}")
        except Exception as e:
            print(f"❌ DATABASE: Failed to save salt: {e}")
            raise
        try:
            metadata_conn = sqlite3.connect(self.metadata_db)
            metadata_conn.execute("""
                CREATE TABLE accounts (
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
                CREATE TABLE audit_log (
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
            print("✅ DATABASE: Metadata database created")
        except Exception as e:
            print(f"❌ DATABASE: Failed to create metadata database: {e}")
            raise
        try:
            sensitive_conn = sqlite3.connect(self.sensitive_db)
            sensitive_conn.execute("""
                CREATE TABLE credentials (
                    account_id TEXT PRIMARY KEY,
                    encrypted_username BLOB,
                    encrypted_password BLOB
                )
            """)
            sensitive_conn.commit()
            sensitive_conn.close()
            print("✅ DATABASE: Sensitive database created")
        except Exception as e:
            print(f"❌ DATABASE: Failed to create sensitive database: {e}")
            raise
        try:
            print("🔑 DATABASE: Creating master account for authentication...")
            encrypted_username = self.crypto.encrypt_data("master", self.encryption_key)
            encrypted_password = self.crypto.encrypt_data(master_password, self.encryption_key)
            metadata_conn = sqlite3.connect(self.metadata_db)
            metadata_conn.execute("""
                INSERT INTO accounts (id, name, email, url, notes, created_at, updated_at, tags, security_level)
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
                INSERT INTO credentials (account_id, encrypted_username, encrypted_password)
                VALUES (?, ?, ?)
            """, ("master_account", encrypted_username, encrypted_password))
            sensitive_conn.commit()
            sensitive_conn.close()
            print("✅ DATABASE: Master account created successfully")
        except Exception as e:
            print(f"❌ DATABASE: Failed to create master account: {e}")
            raise
        try:
            self.update_integrity_signature()
            print("✅ DATABASE: Integrity signature created")
        except Exception as e:
            print(f"❌ DATABASE: Failed to create integrity signature: {e}")
            raise
        try:
            print("🧪 DATABASE: Testing authentication with new password...")
            if self.authenticate(master_password):
                print("✅ DATABASE: Authentication test successful")
            else:
                print("❌ DATABASE: Authentication test failed")
                raise Exception("Authentication test failed after initialization")
        except Exception as e:
            print(f"❌ DATABASE: Authentication test error: {e}")
            raise
        self.log_action("CREATE", "SYSTEM", "database", "Database initialized successfully")
        print("🎉 DATABASE: Database initialization completed successfully!")  
                
    def authenticate(self, master_password: str) -> bool:
        try:
            print(f"🔐 AUTH: Attempting authentication...")
            print(f"🔐 AUTH: Salt path: {self.salt_path}")
            print(f"🔐 AUTH: Metadata DB path: {self.metadata_db}")
            print(f"🔐 AUTH: Sensitive DB path: {self.sensitive_db}")
            print(f"🔐 AUTH: Integrity path: {self.integrity_path}")
            required_files = [self.salt_path, self.metadata_db, self.sensitive_db]
            missing_files = [f for f in required_files if not os.path.exists(f)]
            if missing_files:
                print(f"❌ AUTH: Missing required files: {missing_files}")
                return False
            if not os.path.exists(self.salt_path):
                print(f"❌ AUTH: Salt file not found at {self.salt_path}")
                return False
            with open(self.salt_path, "rb") as f:
                salt = f.read()
            print(f"✅ AUTH: Salt loaded successfully ({len(salt)} bytes)")
            self.encryption_key = self.crypto.generate_key_from_password(master_password, salt)
            self.integrity_key = self.crypto.generate_key_from_password(master_password + "_integrity", salt)
            print("✅ AUTH: Encryption keys generated")
            integrity_valid = self.verify_database_integrity()
            print(f"🔐 AUTH: Database integrity check: {'✅ PASSED' if integrity_valid else '❌ FAILED'}")
            if not integrity_valid:
                print("❌ AUTH: Database integrity check failed")
                self.last_integrity_error = True
                print("🔄 AUTH: Attempting integrity recovery...")
                try:
                    if self.update_integrity_signature():
                        print("✅ AUTH: Integrity signature regenerated, retrying verification...")
                        integrity_valid = self.verify_database_integrity()
                        if integrity_valid:
                            print("✅ AUTH: Integrity recovery successful")
                            self.last_integrity_error = False
                        else:
                            print("❌ AUTH: Integrity recovery failed")
                            return False
                    else:
                        print("❌ AUTH: Failed to regenerate integrity signature")
                        return False
                except Exception as recovery_error:
                    print(f"❌ AUTH: Integrity recovery error: {recovery_error}")
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
                        print("✅ AUTH: Test decryption successful")
                    except Exception as decrypt_error:
                        print(f"❌ AUTH: Test decryption failed: {decrypt_error}")
                        return False
                else:
                    print("⚠️ AUTH: No master account found for test decryption")
            except Exception as test_error:
                print(f"❌ AUTH: Database test failed: {test_error}")
                return False
            print("🎉 AUTH: Authentication successful!")
            return True
        except FileNotFoundError as e:
            print(f"❌ AUTH: Required file not found: {e}")
            return False
        except Exception as e:
            print(f"❌ AUTH: Authentication error: {e}")
            print(f"🔍 AUTH: Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return False
                
    def verify_database_integrity(self) -> bool:
        try:
            print(f"🔍 INTEGRITY: Checking database integrity...")
            print(f"🔍 INTEGRITY: Integrity file path: {self.integrity_path}")
            if not os.path.exists(self.integrity_path):
                print(f"🔍 INTEGRITY: No integrity file found, creating new signature...")
                self.update_integrity_signature()
                return True
            try:
                with open(self.integrity_path, "rb") as f:
                    stored_signature = f.read()
                print(f"🔍 INTEGRITY: Stored signature loaded ({len(stored_signature)} bytes)")
            except Exception as e:
                print(f"❌ INTEGRITY: Failed to read stored signature: {e}")
                return False
            try:
                current_signature = self.calculate_database_signature()
                print(f"🔍 INTEGRITY: Current signature calculated ({len(current_signature)} bytes)")
            except Exception as e:
                print(f"❌ INTEGRITY: Failed to calculate current signature: {e}")
                return False
            try:
                is_valid = self.crypto.verify_hmac(current_signature, stored_signature, self.integrity_key)
                print(f"🔍 INTEGRITY: HMAC verification: {'✅ PASSED' if is_valid else '❌ FAILED'}")
                if not is_valid:
                    print(f"⚠️ INTEGRITY: Signature mismatch detected, attempting to regenerate...")
                    try:
                        self.update_integrity_signature()
                        print(f"✅ INTEGRITY: Signature regenerated successfully")
                        return True
                    except Exception as regen_error:
                        print(f"❌ INTEGRITY: Failed to regenerate signature: {regen_error}")
                        return False
                return is_valid
            except Exception as e:
                print(f"❌ INTEGRITY: HMAC verification error: {e}")
                return False
        except Exception as e:
            print(f"❌ INTEGRITY: Integrity check failed: {e}")
            return False
    
    def calculate_database_signature(self) -> bytes:
        hasher = hashlib.sha256()
        if os.path.exists(self.metadata_db):
            with open(self.metadata_db, "rb") as f:
                hasher.update(f.read())
        if os.path.exists(self.sensitive_db):
            with open(self.sensitive_db, "rb") as f:
                hasher.update(f.read())
        return hasher.digest()
    
    def update_integrity_signature(self):
        try:
            if not self.integrity_key:
                print(f"❌ INTEGRITY: Cannot update signature - no integrity key available")
                return False
            print(f"🔍 INTEGRITY: Updating database integrity signature...")
            signature_data = self.calculate_database_signature()
            print(f"🔍 INTEGRITY: Signature data calculated ({len(signature_data)} bytes)")
            signature = self.crypto.generate_hmac(signature_data, self.integrity_key)
            print(f"🔍 INTEGRITY: HMAC signature generated ({len(signature)} bytes)")
            with open(self.integrity_path, "wb") as f:
                f.write(signature)
            print(f"✅ INTEGRITY: Signature updated successfully to {self.integrity_path}")
            return True
        except Exception as e:
            print(f"❌ INTEGRITY: Failed to update signature: {e}")
            return False
    
    def force_integrity_reset(self):
        try:
            print(f"⚠️ INTEGRITY: Force resetting integrity signature...")
            if os.path.exists(self.integrity_path):
                os.remove(self.integrity_path)
                print(f"✅ INTEGRITY: Old integrity file removed")
            if self.integrity_key:
                success = self.update_integrity_signature()
                if success:
                    print(f"✅ INTEGRITY: New integrity signature created")
                    return True
                else:
                    print(f"❌ INTEGRITY: Failed to create new integrity signature")
                    return False
            else:
                print(f"❌ INTEGRITY: No integrity key available for reset")
                return False
        except Exception as e:
            print(f"❌ INTEGRITY: Force reset failed: {e}")
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
            self.update_integrity_signature()
            print(f"✅ DATABASE: Account '{account.name}' created successfully with ID: {account.id}")
            
        except sqlite3.IntegrityError as e:
            print(f"❌ DATABASE: Integrity error while creating account: {e}")
            try:
                if metadata_conn:
                    metadata_conn.execute("DELETE FROM accounts WHERE id = ?", (account.id,))
                    metadata_conn.commit()
                if sensitive_conn:
                    sensitive_conn.execute("DELETE FROM credentials WHERE account_id = ?", (account.id,))
                    sensitive_conn.commit()
            except Exception as cleanup_error:
                print(f"❌ DATABASE: Error during cleanup: {cleanup_error}")
            raise e
        except Exception as e:
            print(f"❌ DATABASE: Error creating account: {e}")
            try:
                if metadata_conn:
                    metadata_conn.execute("DELETE FROM accounts WHERE id = ?", (account.id,))
                    metadata_conn.commit()
                if sensitive_conn:
                    sensitive_conn.execute("DELETE FROM credentials WHERE account_id = ?", (account.id,))
                    sensitive_conn.commit()
            except Exception as cleanup_error:
                print(f"❌ DATABASE: Error during cleanup: {cleanup_error}")
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
        self.update_integrity_signature()
    
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
        self.update_integrity_signature()
    
    def change_master_password(self, current_password: str, new_password: str):
        if not self.authenticate(current_password):
            raise ValueError("Current password is incorrect")
        print("🔑 PASSWORD: Starting master password change process...")
        new_salt = self.crypto.generate_salt()
        new_encryption_key = self.crypto.generate_key_from_password(new_password, new_salt)
        new_integrity_key = self.crypto.generate_key_from_password(new_password + "_integrity", new_salt)
        print("🔑 PASSWORD: Generated new encryption keys")
        sensitive_conn = sqlite3.connect(self.sensitive_db)
        cursor = sensitive_conn.execute("SELECT account_id, encrypted_username, encrypted_password FROM credentials")
        credentials = cursor.fetchall()
        print(f"🔑 PASSWORD: Found {len(credentials)} accounts to re-encrypt")
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
                
                print(f"✅ PASSWORD: Re-encrypted credentials for account {account_id}")
            except Exception as e:
                print(f"❌ PASSWORD: Failed to re-encrypt account {account_id}: {e}")
                sensitive_conn.close()
                raise ValueError(f"Failed to re-encrypt account {account_id}: {e}")
        sensitive_conn.commit()
        sensitive_conn.close()
        print("✅ PASSWORD: All credentials re-encrypted successfully")
        self.encryption_key = new_encryption_key
        self.integrity_key = new_integrity_key
        try:
            with open(self.salt_path, "wb") as f:
                f.write(new_salt)
            print(f"✅ PASSWORD: New salt written to {self.salt_path}")
        except Exception as e:
            print(f"❌ PASSWORD: Failed to write salt file: {e}")
            raise ValueError(f"Failed to write salt file: {e}")
        try:
            self.update_integrity_signature()
            print("✅ PASSWORD: Integrity signature updated")
        except Exception as e:
            print(f"❌ PASSWORD: Failed to update integrity signature: {e}")
            raise ValueError(f"Failed to update integrity signature: {e}")
        self.log_action("UPDATE", "SYSTEM", "master_password", "Master password changed successfully")
        if self.secure_file_manager:
            try:
                self.secure_file_manager.sync_all_files()
                print("✅ PASSWORD: Changes synced to secure storage")
            except Exception as e:
                print(f"⚠️ PASSWORD: Warning - failed to sync to secure storage: {e}")
        print("🎉 PASSWORD: Master password change completed successfully!")
        try:
            test_encryption_key = self.crypto.generate_key_from_password(new_password, new_salt)
            if test_encryption_key == self.encryption_key:
                print("✅ PASSWORD: New password verification successful")
            else:
                print("❌ PASSWORD: New password verification failed")
                raise ValueError("Password change verification failed")
        except Exception as e:
            print(f"❌ PASSWORD: Verification error: {e}")
            raise ValueError(f"Password change verification failed: {e}")    

    def log_action(self, action: str, entity_type: str, entity_id: str, details: str):
        metadata_conn = sqlite3.connect(self.metadata_db)
        metadata_conn.execute("""
            INSERT INTO audit_log (timestamp, action, entity_type, entity_id, details)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), action, entity_type, entity_id, details))
        metadata_conn.commit()
        metadata_conn.close()

class BackupManager:
    def __init__(self, crypto_manager: CryptoManager, secure_file_manager=None):
        self.crypto = crypto_manager
        self.secure_file_manager = secure_file_manager
    
    def create_backup(self, db_path: str, backup_path: str, master_password: str) -> bool:
        try:
            backup_salt = self.crypto.generate_salt()
            backup_key = self.crypto.generate_key_from_password(master_password, backup_salt)
            if hasattr(self, 'secure_file_manager') and self.secure_file_manager:
                files_to_backup = [
                    self.secure_file_manager.get_metadata_db_path(),
                    self.secure_file_manager.get_sensitive_db_path(),
                    self.secure_file_manager.get_salt_path(),
                    self.secure_file_manager.get_integrity_path()
                ]
            else:
                files_to_backup = [
                    f"{db_path}_metadata.db",
                    f"{db_path}_sensitive.db",
                    f"{db_path}_salt",
                    f"{db_path}_integrity"
                ]
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'files': {}
            }
            for file_path in files_to_backup:
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    encrypted_file = self.crypto.encrypt_data(
                        base64.b64encode(file_data).decode(), 
                        backup_key
                    )
                    backup_data['files'][os.path.basename(file_path)] = base64.b64encode(encrypted_file).decode()
            backup_json = json.dumps(backup_data)
            final_encrypted_backup = self.crypto.encrypt_data(backup_json, backup_key)
            with open(backup_path, 'wb') as f:
                f.write(backup_salt + final_encrypted_backup)
            return True
        except Exception as e:
            print(f"Backup creation failed: {e}")
            return False
    
    def restore_backup(self, backup_path: str, restore_path: str, master_password: str) -> bool:
        try:
            with open(backup_path, 'rb') as f:
                backup_content = f.read()
            backup_salt = backup_content[:32]
            encrypted_backup = backup_content[32:]
            backup_key = self.crypto.generate_key_from_password(master_password, backup_salt)
            decrypted_json = self.crypto.decrypt_data(encrypted_backup, backup_key)
            backup_data = json.loads(decrypted_json)
            for filename, encrypted_file_data in backup_data['files'].items():
                encrypted_file = base64.b64decode(encrypted_file_data.encode())
                decrypted_file_data = self.crypto.decrypt_data(encrypted_file, backup_key)
                file_data = base64.b64decode(decrypted_file_data.encode())
                
                restore_file_path = os.path.join(restore_path, filename)
                with open(restore_file_path, 'wb') as f:
                    f.write(file_data)
            return True
        except Exception as e:
            print(f"Backup restoration failed: {e}")
            return False

class ModernPasswordManagerGUI:
    def __init__(self):
        self.crypto = CryptoManager()
        self.password_generator = PasswordGenerator()
        self.database = None
        self.secure_file_manager = None
        self.security_monitor = None
        self.backup_manager = BackupManager(self.crypto)
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
        self._setup_secure_file_manager()
        self.load_settings()
        self.validate_lockout_integrity()
        self.setup_ui()
        self.start_lockout_validation_timer()
        self.backup_gui = None
        self._initialize_backup_system()

    def _initialize_backup_system(self):
        try:
            print("🔧 BACKUP: Initializing enhanced backup system...")
            self.backup_gui = BackupGUI(self)
            print("✅ BACKUP: Enhanced backup system initialized successfully")
        except Exception as e:
            print(f"❌ BACKUP: Failed to initialize backup system: {e}")
            self.backup_gui = None

    def _setup_secure_file_manager(self):
        try:
            print("🔧 SECURITY: Initializing secure file management system...")
            self.secure_file_manager = SecureFileManager()
            print("✅ SECURITY: Secure file manager initialized")
        except Exception as e:
            print(f"❌ SECURITY: Failed to initialize secure file manager: {e}")
            self.secure_file_manager = None

    def load_settings(self):
        default_settings = {
            'theme': 'dark',
            'font_size': 12,
            'lockout_until': None,
            'failed_attempts': 0,
            'consecutive_lockouts': 0,
            'last_modified': None,
            'secure_storage_enabled': True
        }
        if self.secure_file_manager:
            try:
                loaded_settings = self.secure_file_manager.read_settings()
                if loaded_settings:
                    self.settings = {**default_settings, **loaded_settings}
                    self.restore_lockout_state()
                    return
            except Exception as e:
                print(f"Failed to load secure settings: {e}")
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
                                print("🔒 SECURITY: Settings file modification time mismatch detected")
                                loaded_settings['lockout_until'] = None
                                loaded_settings['failed_attempts'] = 0
                                loaded_settings['consecutive_lockouts'] = 0
                        except (ValueError, TypeError):
                            print("🔒 SECURITY: Invalid modification time in settings")
                            loaded_settings['lockout_until'] = None
                            loaded_settings['failed_attempts'] = 0
                            loaded_settings['consecutive_lockouts'] = 0
                    self.settings = {**default_settings, **loaded_settings}
                    self.restore_lockout_state()
            else:
                self.settings = default_settings
                self.save_settings_to_file()
        except Exception as e:
            print(f"Error loading settings: {e}")
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
                    print(f"🔒 SECURITY: Lockout state restored - {lockout_minutes} minutes remaining")
                else:
                    self.clear_lockout_state()
                    print("🔓 SECURITY: Lockout period expired, state cleared")
            except Exception as e:
                print(f"❌ ERROR: Error parsing lockout time: {e}")
                self.clear_lockout_state()
        else:
            self.failed_attempts = self.settings.get('failed_attempts', 0)
            self.consecutive_lockouts = self.settings.get('consecutive_lockouts', 0)

    def clear_lockout_state(self):
        print("🔓 SECURITY: Clearing lockout state")
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
            print(f"🔒 SECURITY: Saving lockout state - {minutes:02d}:{seconds:02d} remaining")
        else:
            self.settings['lockout_until'] = None
        self.settings['failed_attempts'] = self.failed_attempts
        self.settings['consecutive_lockouts'] = self.consecutive_lockouts
        self.save_settings_to_file()

    def save_settings_to_file(self):
        self.settings['last_modified'] = time.time()
        if self.secure_file_manager:
            try:
                if self.secure_file_manager.write_settings(self.settings):
                    return
            except Exception as e:
                print(f"Failed to save secure settings: {e}")
        try:
            settings_file = "vault_settings.json"
            with open(settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def validate_lockout_integrity(self):
        print("🔒 SECURITY: Validating lockout state integrity...")
        if self.lockout_until:
            current_time = datetime.now()
            if current_time >= self.lockout_until:
                print("🔒 SECURITY: Lockout period has expired, clearing state")
                self.clear_lockout_state()
            else:
                if self.failed_attempts < 0:
                    self.failed_attempts = 0
                if self.consecutive_lockouts < 0:
                    self.consecutive_lockouts = 0
                max_lockout_duration = timedelta(hours=24)
                if self.lockout_until - current_time > max_lockout_duration:
                    print("🔒 SECURITY: Lockout time exceeds maximum duration, resetting")
                    self.clear_lockout_state()
                    return
        else:
            if self.failed_attempts < 0:
                self.failed_attempts = 0
            if self.consecutive_lockouts < 0:
                self.consecutive_lockouts = 0

    def log_security_event(self, event_type: str, details: str):
        timestamp = datetime.now().isoformat()
        security_log = f"[{timestamp}] SECURITY: {event_type} - {details}"
        print(security_log)
        try:
            with open("security_audit.log", "a") as f:
                f.write(security_log + "\n")
        except Exception as e:
            print(f"Error writing to security log: {e}")

    def start_lockout_validation_timer(self):
        def validate_periodically():
            if self.lockout_until:
                current_time = datetime.now()
                if current_time >= self.lockout_until:
                    print("🔒 SECURITY: Periodic check - lockout period expired")
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
            secure_exists = self.secure_file_manager.file_exists('salt_file')
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
                print("🔄 MIGRATION: Legacy files detected, starting migration...")
                if not legacy_setup.migrate_legacy_files(master_password):
                    messagebox.showerror("Migration Error", "Failed to migrate legacy files")
                    return
        if self.secure_file_manager:
            if not self.secure_file_manager.initialize_encryption(master_password):
                messagebox.showerror("Error", "Failed to initialize secure storage")
                return
            print("🔧 SECURITY: Loading files from secure storage...")
            if not self.secure_file_manager.load_files_to_temp():
                diagnostic_report = self.diagnose_secure_storage_issues()
                error_msg = "Failed to load files from secure storage.\n\n"
                error_msg += "🔍 Diagnostic Report:\n" + diagnostic_report
                self.show_secure_storage_error_dialog(error_msg)
                return
        db_path = "manageyouraccount"
        self.database = DatabaseManager(db_path, self.crypto, self.secure_file_manager)
        if self.database.authenticate(master_password):
            self.authenticated = True
            self.failed_attempts = 0
            self.consecutive_lockouts = 0
            self.clear_lockout_state()
            if self.secure_file_manager:
                self.security_monitor = SecurityMonitor(self.secure_file_manager)
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
        def monitor_worker():
            while self.authenticated and self.security_monitor:
                try:
                    time.sleep(60)
                    if not self.security_monitor.monitor_file_access():
                        threat_level = self.security_monitor.get_threat_level()
                        if threat_level in ["HIGH", "CRITICAL"]:
                            print(f"🚨 SECURITY ALERT: Threat level {threat_level}")
                except Exception as e:
                    print(f"Security monitoring error: {e}")
                    break
        
        if self.security_monitor:
            monitor_thread = threading.Thread(target=monitor_worker, daemon=True)
            monitor_thread.start()

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
            temp_db = DatabaseManager(self.database.db_path, self.crypto)
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
            text="🔒 Logout", 
            width=100, 
            height=55,
            command=self.lock_vault,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)
        
        ctk.CTkButton(
            toolbar, 
            text="⚙️ Settings", 
            width=120, 
            height=55,
            command=self.show_settings,
            font=ctk.CTkFont(size=18)
        ).pack(side="right", padx=10, pady=8)
        
        content_frame = ctk.CTkFrame(self.main_frame)
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.create_sidebar(content_frame)
        self.main_panel = ctk.CTkFrame(content_frame)
        self.main_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        self.show_passwords()

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
        
        sidebar_configs = [
            ("🗝️ Your Accounts", self.show_passwords),
            ("🛠️ Password Generator", self.show_password_generator),
            ("🛡️ Security Report", self.show_security_report),
            ("💾 Backup & Restore", self.show_backup_restore_enhanced),  # Enhanced backup
            ("📜 Audit Log", self.show_audit_log),
            ("📁 Backup Manager", self.show_backup_folder_manager)  # New backup manager
        ]
        for text, command in sidebar_configs:
            btn = ctk.CTkButton(
                self.sidebar, 
                text=text, 
                command=lambda cmd=command, txt=text: self.handle_sidebar_click(cmd, txt),
                height=60,
                font=ctk.CTkFont(size=20),
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


    def show_backup_restore_enhanced(self):
        if self.backup_gui:
            self.backup_gui.show_backup_restore_enhanced()
        else:
            messagebox.showerror("Error", "Enhanced backup system is not available. Please restart the application.")
            self.show_backup_restore_fallback()
    
    def show_backup_folder_manager(self):
        if self.backup_gui:
            self.backup_gui.open_backup_folder()
        else:
            messagebox.showinfo("Backup Folder", "Enhanced backup system is not available.")
    
    def show_backup_restore_fallback(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text="♻️ Backup & Restore", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        
        content = ctk.CTkFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        
        backup_frame = ctk.CTkFrame(content)
        backup_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(backup_frame, text="💾 Create Backup", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        ctk.CTkLabel(backup_frame, text="Create an encrypted backup of all your data", 
                     text_color="#888888").pack(pady=5)
        ctk.CTkButton(backup_frame, text="Create Backup", 
                      command=self.create_backup_dialog_simple, height=45,
                      font=ctk.CTkFont(size=16)).pack(pady=15)
        restore_frame = ctk.CTkFrame(content)
        restore_frame.pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(restore_frame, text="📥 Restore from Backup", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        ctk.CTkLabel(restore_frame, text="Restore your data from an encrypted backup file", 
                     text_color="#888888").pack(pady=5)
        ctk.CTkButton(restore_frame, text="Restore Backup", 
                      command=self.restore_backup_dialog_simple, height=45,
                      font=ctk.CTkFont(size=16)).pack(pady=15)
    
    def create_backup_dialog_simple(self):
        backup_path = filedialog.asksaveasfilename(
            title="Save Backup File",
            defaultextension=".vault",
            filetypes=[("Vault Backup", "*.vault"), ("All Files", "*.*")]
        )
        if backup_path:
            if not self.verify_master_password_dialog():
                return
            master_password = self.get_master_password_for_backup()
            if master_password:
                try:
                    success = self.backup_manager.create_backup(self.database.db_path, backup_path, master_password)
                    if success:
                        messagebox.showinfo("Success", f"Backup created successfully!\n\nSaved to: {backup_path}")
                    else:
                        messagebox.showerror("Error", "Failed to create backup")
                except Exception as e:
                    messagebox.showerror("Error", f"Backup creation failed: {str(e)}")

    def restore_backup_dialog_simple(self):
        backup_path = filedialog.askopenfilename(
            title="Select Backup File",
            filetypes=[("Vault Backup", "*.vault"), ("SecureVault Backup", "*.svault"), ("All Files", "*.*")]
        )
        if backup_path:
            result = messagebox.askyesnocancel(
                "Restore Backup",
                "Restoring from backup will replace ALL current data.\n\nThis action cannot be undone!\n\nDo you want to continue?"
            )
            if result:
                master_password = self.get_master_password_for_backup()
                if master_password:
                    try:
                        restore_dir = os.path.dirname(self.database.db_path)
                        success = self.backup_manager.restore_backup(backup_path, restore_dir, master_password)
                        if success:
                            messagebox.showinfo("Success", "Backup restored successfully!\n\nPlease restart the application.")
                            self.root.quit()
                        else:
                            messagebox.showerror("Error", "Failed to restore backup")
                    except Exception as e:
                        messagebox.showerror("Error", f"Backup restoration failed: {str(e)}")
    
    def get_master_password_for_backup(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Enter Master Password")
        dialog.geometry("400x200")
        dialog.grab_set()
        result = {"password": None}
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="Enter Master Password for Backup",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
        password_entry = ctk.CTkEntry(main_frame, width=300, height=40, show="*")
        password_entry.pack(pady=15)
        password_entry.focus()
        
        def on_ok():
            result["password"] = password_entry.get()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        password_entry.bind('<Return>', lambda e: on_ok())
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=10)
        
        ctk.CTkButton(button_frame, text="Cancel", command=on_cancel, width=100).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="OK", command=on_ok, width=100).pack(side="right", padx=10)
        
        dialog.wait_window()
        return result["password"]
    
    def lock_vault(self):
        try:
            if self.backup_gui and hasattr(self.backup_gui, 'backup_scheduler') and self.backup_gui.backup_scheduler:
                self.backup_gui.backup_scheduler.stop_automatic_backups()
                print("🛑 BACKUP: Stopped automatic backups during vault lock")
            if self.secure_file_manager and self.authenticated:
                print("🔒 SECURITY: Syncing files to secure storage before lock...")
                self.secure_file_manager.sync_all_files()
                
                if not self.secure_file_manager.perform_integrity_check():
                    print("❌ SECURITY: Integrity check failed during vault lock")
                    messagebox.showwarning("Security Warning", 
                                        "File integrity check failed.")
                
                self.secure_file_manager.cleanup_temp_files()
                print("🧹 SECURITY: Temporary files cleaned up")
            self.authenticated = False
            self.database = None
            self.security_monitor = None
            self.show_login_screen()
            
            print("✅ SECURITY: Vault locked successfully")
            
        except Exception as e:
            print(f"Error during vault lock: {e}")
            self.authenticated = False
            self.database = None
            self.show_login_screen()
    
    def run(self):
        try:
            self.root.mainloop()
        finally:
            if self.backup_gui and hasattr(self.backup_gui, 'backup_scheduler') and self.backup_gui.backup_scheduler:
                print("🛑 BACKUP: Stopping automatic backups...")
                self.backup_gui.backup_scheduler.stop_automatic_backups()
            
            if self.secure_file_manager:
                print("🧹 CLEANUP: Performing final sync and cleanup...")
                try:
                    if self.authenticated:
                        self.secure_file_manager.sync_all_files()
                    self.secure_file_manager.cleanup_temp_files()
                    print("✅ CLEANUP: Secure cleanup completed")
                except Exception as e:
                    print(f"Cleanup error: {e}")

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
                    print("🔗 SHORTCUT: Windows desktop shortcut created")
                except ImportError:
                    batch_content = f"""@echo off
    cd /d "{app_dir}"
    "{app_path}"
    pause
    """
                    with open(desktop_path / "SecureVault Password Manager.bat", "w") as f:
                        f.write(batch_content)
                    print("🔗 SHORTCUT: Windows batch file created")
                    
            elif sys.platform == "darwin":  # macOS
                try:
                    script = f'''
                    tell application "Finder"
                        make alias file to file POSIX file "{app_path}" at desktop
                        set name of result to "SecureVault Password Manager"
                    end tell
                    '''
                    subprocess.run(["osascript", "-e", script], check=True)
                    print("🔗 SHORTCUT: macOS alias created")
                except:
                    print("⚠️ SHORTCUT: Could not create macOS shortcut automatically")
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
                print("🔗 SHORTCUT: Linux desktop file created")
            return True
        except Exception as e:
            print(f"Warning: Could not create desktop integration: {e}")
            return False

    def show_security_status(self):
        if not self.secure_file_manager:
            messagebox.showinfo("Security Status", "Secure file management is not available")
            return
        
        status_window = ctk.CTkToplevel(self.root)
        status_window.title("Security Status")
        status_window.geometry("600x500")
        status_window.grab_set()
        
        main_frame = ctk.CTkFrame(status_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🛡️ Security Status", 
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)
        
        status = self.secure_file_manager.get_security_status()
        
        status_text = f"""
Secure Storage Location: {status.get('secure_location', 'Unknown')}
Protected Files Count: {status.get('files_count', 0)}
Last Integrity Check: {status.get('last_integrity_check', 'Never')}
Permissions Secure: {'✅ Yes' if status.get('permissions_secure', False) else '❌ No'}
        """
        
        if self.security_monitor:
            threat_level = self.security_monitor.get_threat_level()
            status_text += f"\nThreat Level: {threat_level}"
        
        ctk.CTkLabel(main_frame, text=status_text, 
                    font=ctk.CTkFont(size=14, family="monospace"),
                    justify="left").pack(pady=20, padx=20)
        
        def run_integrity_check():
            if self.secure_file_manager.perform_integrity_check():
                messagebox.showinfo("Integrity Check", "✅ All files passed integrity verification")
            else:
                messagebox.showerror("Integrity Check", "❌ File integrity check failed!")
        
        ctk.CTkButton(main_frame, text="🔍 Run Integrity Check", 
                    command=run_integrity_check, height=40).pack(pady=10)
        
        ctk.CTkButton(main_frame, text="Close", 
                    command=status_window.destroy, height=40).pack(pady=20)

    def show_settings(self):
        settings_window = ctk.CTkToplevel(self.root)
        settings_window.title("Password Vault Settings")
        settings_window.geometry("500x400")
        settings_window.grab_set()
        settings_window.resizable(False, False)
        
        main_frame = ctk.CTkFrame(settings_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🔐 Security Settings", 
                    font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)
        
        security_frame = ctk.CTkFrame(main_frame)
        security_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(security_frame, text="Security Status", 
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        ctk.CTkButton(security_frame, text="🛡️ View Security Status",
                    command=self.show_security_status,
                    height=40).pack(pady=10)
        
        password_frame = ctk.CTkFrame(main_frame)
        password_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(password_frame, text="Master Password", 
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        ctk.CTkButton(password_frame, text="Change Master Password",
                    command=self.change_master_password_dialog,
                    height=40).pack(pady=10)

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
                print(f"❌ PASSWORD CHANGE ERROR: {error_msg}")
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
            print("🔄 RESTART: Initiating secure program restart...")
            if self.secure_file_manager and self.authenticated:
                print("🔄 RESTART: Syncing files to secure storage...")
                self.secure_file_manager.sync_all_files()
                if not self.secure_file_manager.perform_integrity_check():
                    print("⚠️ RESTART: Integrity check failed during restart")
                    messagebox.showwarning("Security Warning", 
                                        "File integrity check failed during restart.")
                self.secure_file_manager.cleanup_temp_files()
                print("🧹 RESTART: Temporary files cleaned up")
            
            self.authenticated = False
            self.database = None
            self.security_monitor = None
            
            print("✅ RESTART: Secure shutdown completed")
            if getattr(sys, 'frozen', False):
                script_path = sys.executable
            else:
                script_path = sys.argv[0]
            
            print(f"🔄 RESTART: Restarting program: {script_path}")
            
            self.root.destroy()
            
            if getattr(sys, 'frozen', False):
                subprocess.Popen([script_path])
            else:
                subprocess.Popen([sys.executable, script_path])
            
            sys.exit(0)
        except Exception as e:
            print(f"❌ RESTART: Error during program restart: {e}")
            messagebox.showerror("Restart Error", 
                            f"Failed to restart program automatically: {str(e)}\n\n"
                            "Please manually restart the application.")
            try:
                self.root.quit()
            except:
                sys.exit(1)
                
    def verify_new_password(self, new_password):
        try:
            print("🧪 TESTING: Verifying new password works...")
            temp_db = DatabaseManager(self.database.db_path, self.crypto, self.secure_file_manager)
            if temp_db.authenticate(new_password):
                print("✅ TESTING: New password verification successful")
                messagebox.showinfo("Verification", 
                                "Password change verified successfully!\n"
                                "Your new password is working correctly.")
            else:
                print("❌ TESTING: New password verification failed")
                messagebox.showwarning("Verification Warning", 
                                    "Password was changed but verification failed.\n"
                                    "Please try logging in again.")
        except Exception as e:
            print(f"❌ TESTING: Password verification error: {e}")
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
            ("📋 Copy", lambda: self.copy_password_to_clipboard(account)),
            ("✏️ Edit", lambda: self.show_account_dialog(account)),
            ("🗑️ Delete", lambda: self.delete_account(account))
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
                        print(f"Error checking account ID uniqueness: {e}")
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
                    print(f"Error checking account name uniqueness: {e}")
                
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
            print(f"Full error details: {e}")
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

    def show_backup_restore(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text="♻️ Backup & Restore", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        
        content = ctk.CTkFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        backup_frame = ctk.CTkFrame(content)
        backup_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(backup_frame, text="💾 Create Backup", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        ctk.CTkLabel(backup_frame, text="Create an encrypted backup of all your data", 
                     text_color="#888888").pack(pady=5)
        ctk.CTkButton(backup_frame, text="Create Backup", 
                      command=self.create_backup_dialog, height=45,
                      font=ctk.CTkFont(size=16)).pack(pady=15)
        
        restore_frame = ctk.CTkFrame(content)
        restore_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(restore_frame, text="📥 Restore from Backup", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        ctk.CTkLabel(restore_frame, text="Restore your data from an encrypted backup file", 
                     text_color="#888888").pack(pady=5)
        ctk.CTkButton(restore_frame, text="Restore Backup", 
                      command=self.restore_backup_dialog, height=45,
                      font=ctk.CTkFont(size=16)).pack(pady=15)

    def create_backup_dialog(self):
        backup_path = filedialog.asksaveasfilename(
            title="Save Backup File",
            defaultextension=".vault",
            filetypes=[("Vault Backup", "*.vault"), ("All Files", "*.*")]
        )
        if backup_path:
            if not self.verify_master_password_dialog():
                return
            master_password = self.get_master_password_for_backup()
            if master_password:
                try:
                    success = self.backup_manager.create_backup(self.database.db_path, backup_path, master_password)
                    if success:
                        messagebox.showinfo("Success", f"Backup created successfully!\n\nSaved to: {backup_path}")
                    else:
                        messagebox.showerror("Error", "Failed to create backup")
                except Exception as e:
                    messagebox.showerror("Error", f"Backup creation failed: {str(e)}")

    def restore_backup_dialog(self):
        backup_path = filedialog.askopenfilename(
            title="Select Backup File",
            filetypes=[("Vault Backup", "*.vault"), ("All Files", "*.*")]
        )
        if backup_path:
            result = messagebox.askyesnocancel(
                "Restore Backup",
                "Restoring from backup will replace ALL current data.\n\nThis action cannot be undone!\n\nDo you want to continue?"
            )
            if result:
                master_password = self.get_master_password_for_backup()
                if master_password:
                    try:
                        restore_dir = os.path.dirname(self.database.db_path)
                        success = self.backup_manager.restore_backup(backup_path, restore_dir, master_password)
                        if success:
                            messagebox.showinfo("Success", "Backup restored successfully!\n\nPlease restart the application.")
                            self.root.quit()
                        else:
                            messagebox.showerror("Error", "Failed to restore backup")
                    except Exception as e:
                        messagebox.showerror("Error", f"Backup restoration failed: {str(e)}")

    def get_master_password_for_backup(self):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Enter Master Password")
        dialog.geometry("400x200")
        dialog.grab_set()
        result = {"password": None}
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="Enter Master Password for Backup",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
        
        password_entry = ctk.CTkEntry(main_frame, width=300, height=40, show="*")
        password_entry.pack(pady=15)
        password_entry.focus()
        
        def on_ok():
            result["password"] = password_entry.get()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        password_entry.bind('<Return>', lambda e: on_ok())
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=10)
        
        ctk.CTkButton(button_frame, text="Cancel", command=on_cancel, width=100).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="OK", command=on_ok, width=100).pack(side="right", padx=10)
        dialog.wait_window()
        return result["password"]

    def show_audit_log(self):
        for widget in self.main_panel.winfo_children():
            widget.destroy()
        header = ctk.CTkFrame(self.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        ctk.CTkLabel(header, text="📑 Audit Log", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        content = ctk.CTkScrollableFrame(self.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        
        try:
            metadata_conn = sqlite3.connect(self.database.metadata_db)
            cursor = metadata_conn.execute("""
                SELECT timestamp, action, entity_type, entity_id, details
                FROM audit_log 
                ORDER BY timestamp DESC 
                LIMIT 100
            """)
            logs = cursor.fetchall()
            metadata_conn.close()
            if not logs:
                ctk.CTkLabel(content, text="No audit log entries found", 
                             font=ctk.CTkFont(size=16), text_color="#888888").pack(pady=50)
                return
            for timestamp, action, entity_type, entity_id, details in logs:
                log_frame = ctk.CTkFrame(content)
                log_frame.pack(fill="x", padx=10, pady=5)
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    time_str = timestamp
                action_colors = {
                    "CREATE": "#00FF00",
                    "UPDATE": "#FFAA44", 
                    "DELETE": "#FF4444",
                    "LOGIN": "#44FF44",
                    "VIEW": "#44AAFF"
                }
                action_color = action_colors.get(action, "#FFFFFF")
                log_text = f"[{time_str}] {action} {entity_type}: {details}"
                ctk.CTkLabel(log_frame, text=log_text, 
                             text_color=action_color, 
                             font=ctk.CTkFont(family="monospace")).pack(anchor="w", padx=15, pady=8)
        except Exception as e:
            ctk.CTkLabel(content, text=f"Error loading audit log: {str(e)}", 
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
            self.log_security_event("LOCKOUT_ENFORCED", f"Login attempt blocked - user locked out")
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
            print(f"🔒 SECURITY: User is locked out on startup - {minutes:02d}:{seconds:02d} remaining")
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
                print("🧹 CLEANUP: Performing final sync and cleanup...")
                try:
                    if self.authenticated:
                        self.secure_file_manager.sync_all_files()
                    self.secure_file_manager.cleanup_temp_files()
                    print("✅ CLEANUP: Secure cleanup completed")
                except Exception as e:
                    print(f"Cleanup error: {e}")

def main():
    """Enhanced main function with backup system and desktop integration"""
    try:
        print("🚀 STARTUP: Starting SecureVault Password Manager...")
        ModernPasswordManagerGUI.create_desktop_integration()
        app = ModernPasswordManagerGUI()
        print("✅ STARTUP: Application initialized successfully")
        print("💾 BACKUP: Enhanced backup system ready")
        print("📁 FOLDER: Backup folder shortcuts created")
        app.run()
        
    except Exception as e:
        print(f"❌ STARTUP: Failed to start application: {e}")
        print("Please ensure all required dependencies are installed:")
        print("pip install customtkinter cryptography pillow")
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Startup Error", 
                           f"Failed to start SecureVault:\n\n{str(e)}\n\n"
                           f"Please check the console for more details.")
        except:
            pass

if __name__ == "__main__":
    main()