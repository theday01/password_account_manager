import os
import json
import secrets
import hashlib
import hmac
import base64
import sqlite3
import threading
import time
import shutil
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

class BackupMetadata:
    def __init__(self):
        self.version = "2.0"
        self.created_at = datetime.now().isoformat()
        self.total_accounts = 0
        self.file_count = 0
        self.checksum = ""
        self.encryption_method = "AES-256-GCM"
        self.key_derivation = "PBKDF2-SHA256"
        self.iterations = 200000

class SecureBackupManager:
    def __init__(self, crypto_manager, secure_file_manager=None):
        self.crypto = crypto_manager
        self.secure_file_manager = secure_file_manager
        self.backup_folder = self.create_backup_folder()
        
    def create_backup_folder(self):
        """Create a dedicated backup folder with proper structure"""
        backup_dir = Path.home() / "SecureVault_Backups"
        
        try:
            backup_dir.mkdir(exist_ok=True)
            
            # Create subfolders
            (backup_dir / "automatic").mkdir(exist_ok=True)
            (backup_dir / "manual").mkdir(exist_ok=True)
            (backup_dir / "temp").mkdir(exist_ok=True)
            
            # Create README file
            readme_content = """SecureVault Backup Directory
============================

This directory contains encrypted backups of your SecureVault password manager.

Directory Structure:
- automatic/    : Automatic scheduled backups
- manual/      : Manual backups created by user
- temp/        : Temporary files (automatically cleaned)

Security Notice:
- All backup files are encrypted with AES-256-GCM
- Backups require your master password to decrypt
- Keep backups in a secure location
- Regular backup verification is recommended

Created: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(backup_dir / "README.txt", "w") as f:
                f.write(readme_content)
                
            print(f"📁 BACKUP: Backup directory created at {backup_dir}")
            return backup_dir
            
        except Exception as e:
            print(f"❌ BACKUP: Failed to create backup directory: {e}")
            return Path.cwd() / "backups"  # Fallback to current directory
    
    def verify_master_password(self, master_password: str, database_manager) -> bool:
        """Verify master password before backup operations"""
        try:
            print("🔐 BACKUP: Verifying master password...")
            
            # Create temporary database manager for verification
            temp_db = type(database_manager)(
                database_manager.db_path, 
                self.crypto, 
                database_manager.secure_file_manager
            )
            
            # Test authentication
            if temp_db.authenticate(master_password):
                print("✅ BACKUP: Master password verified successfully")
                return True
            else:
                print("❌ BACKUP: Master password verification failed")
                return False
                
        except Exception as e:
            print(f"❌ BACKUP: Password verification error: {e}")
            return False
    
    def create_comprehensive_backup(self, database_manager, master_password: str, 
                                  backup_name: str = None, is_automatic: bool = False) -> Tuple[bool, str]:
        """Create a comprehensive encrypted backup of all vault data"""
        
        try:
            print("💾 BACKUP: Starting comprehensive backup creation...")
            
            # Verify master password first
            if not self.verify_master_password(master_password, database_manager):
                return False, "Master password verification failed"
            
            # Generate backup filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if backup_name:
                safe_name = "".join(c for c in backup_name if c.isalnum() or c in (' ', '-', '_')).strip()
                filename = f"SecureVault_{safe_name}_{timestamp}.svault"
            else:
                filename = f"SecureVault_Backup_{timestamp}.svault"
            
            # Choose backup directory
            if is_automatic:
                backup_path = self.backup_folder / "automatic" / filename
            else:
                backup_path = self.backup_folder / "manual" / filename
            
            print(f"💾 BACKUP: Creating backup at {backup_path}")
            
            # Generate strong encryption key from master password
            backup_salt = secrets.token_bytes(32)
            backup_key = self.crypto.generate_key_from_password(master_password + "_backup", backup_salt)
            integrity_key = self.crypto.generate_key_from_password(master_password + "_backup_integrity", backup_salt)
            
            # Collect all files to backup
            files_to_backup = self._collect_vault_files(database_manager)
            
            if not files_to_backup:
                return False, "No vault files found to backup"
            
            # Create backup metadata
            metadata = BackupMetadata()
            metadata.total_accounts = self._count_accounts(database_manager)
            metadata.file_count = len(files_to_backup)
            
            # Create temporary backup directory
            temp_backup_dir = self.backup_folder / "temp" / f"backup_{timestamp}"
            temp_backup_dir.mkdir(parents=True, exist_ok=True)
            
            try:
                # Copy and encrypt each file
                encrypted_files = {}
                total_size = 0
                
                print(f"💾 BACKUP: Processing {len(files_to_backup)} files...")
                
                for file_path, file_type in files_to_backup:
                    if os.path.exists(file_path):
                        print(f"💾 BACKUP: Processing {file_type}: {os.path.basename(file_path)}")
                        
                        # Read file data
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        
                        total_size += len(file_data)
                        
                        # Encrypt file data
                        encrypted_data = self.crypto.encrypt_data(
                            base64.b64encode(file_data).decode(), 
                            backup_key
                        )
                        
                        # Store encrypted file info
                        encrypted_files[file_type] = {
                            'data': base64.b64encode(encrypted_data).decode(),
                            'original_size': len(file_data),
                            'original_name': os.path.basename(file_path),
                            'checksum': hashlib.sha256(file_data).hexdigest()
                        }
                    else:
                        print(f"⚠️ BACKUP: File not found: {file_path}")
                
                if not encrypted_files:
                    return False, "No files could be processed for backup"
                
                # Create backup package
                backup_package = {
                    'metadata': {
                        'version': metadata.version,
                        'created_at': metadata.created_at,
                        'total_accounts': metadata.total_accounts,
                        'file_count': len(encrypted_files),
                        'total_size': total_size,
                        'encryption_method': metadata.encryption_method,
                        'key_derivation': metadata.key_derivation,
                        'iterations': metadata.iterations,
                        'backup_name': backup_name or f"Backup_{timestamp}",
                        'is_automatic': is_automatic
                    },
                    'files': encrypted_files,
                    'checksum_list': {file_type: info['checksum'] 
                                    for file_type, info in encrypted_files.items()}
                }
                
                # Calculate overall checksum
                package_json = json.dumps(backup_package, sort_keys=True)
                metadata.checksum = hashlib.sha256(package_json.encode()).hexdigest()
                backup_package['metadata']['package_checksum'] = metadata.checksum
                
                # Final encryption of entire package
                final_package_json = json.dumps(backup_package, indent=2)
                final_encrypted_package = self.crypto.encrypt_data(final_package_json, backup_key)
                
                # Generate HMAC for integrity
                integrity_signature = self.crypto.generate_hmac(final_encrypted_package, integrity_key)
                
                # Create final backup file
                with open(backup_path, 'wb') as f:
                    # Write file header
                    header = b"SVAULT_BACKUP_V2"  # 16 bytes
                    f.write(header)
                    
                    # Write salt (32 bytes)
                    f.write(backup_salt)
                    
                    # Write integrity signature length and data
                    f.write(len(integrity_signature).to_bytes(4, 'big'))
                    f.write(integrity_signature)
                    
                    # Write encrypted package
                    f.write(final_encrypted_package)
                
                # Verify backup integrity immediately
                if self.verify_backup_integrity(backup_path, master_password):
                    print(f"✅ BACKUP: Backup created and verified successfully")
                    print(f"💾 BACKUP: Backup location: {backup_path}")
                    print(f"📊 BACKUP: {metadata.total_accounts} accounts, {len(encrypted_files)} files, {total_size} bytes")
                    
                    # Create backup log entry
                    self._log_backup_operation("CREATE", backup_path, metadata.total_accounts, total_size)
                    
                    return True, str(backup_path)
                else:
                    os.remove(backup_path)
                    return False, "Backup verification failed"
                    
            finally:
                # Cleanup temporary files
                if temp_backup_dir.exists():
                    shutil.rmtree(temp_backup_dir, ignore_errors=True)
                    
        except Exception as e:
            print(f"❌ BACKUP: Backup creation failed: {e}")
            import traceback
            traceback.print_exc()
            return False, f"Backup creation failed: {str(e)}"
    
    def restore_from_backup(self, backup_path: str, master_password: str, 
                           database_manager, restore_location: str = None) -> Tuple[bool, str]:
        """Restore vault data from an encrypted backup"""
        
        try:
            print(f"📥 RESTORE: Starting restore from {backup_path}")
            
            if not os.path.exists(backup_path):
                return False, "Backup file not found"
            
            # Verify backup file integrity first
            if not self.verify_backup_integrity(backup_path, master_password):
                return False, "Backup file integrity verification failed"
            
            # Read backup file
            with open(backup_path, 'rb') as f:
                # Read header
                header = f.read(16)
                if header != b"SVAULT_BACKUP_V2":
                    return False, "Invalid backup file format"
                
                # Read salt
                backup_salt = f.read(32)
                
                # Read integrity signature
                sig_length = int.from_bytes(f.read(4), 'big')
                integrity_signature = f.read(sig_length)
                
                # Read encrypted package
                encrypted_package = f.read()
            
            # Regenerate keys
            backup_key = self.crypto.generate_key_from_password(master_password + "_backup", backup_salt)
            integrity_key = self.crypto.generate_key_from_password(master_password + "_backup_integrity", backup_salt)
            
            # Verify HMAC
            if not self.crypto.verify_hmac(encrypted_package, integrity_signature, integrity_key):
                return False, "Backup file authentication failed"
            
            # Decrypt package
            try:
                decrypted_json = self.crypto.decrypt_data(encrypted_package, backup_key)
                backup_package = json.loads(decrypted_json)
            except Exception as e:
                return False, f"Failed to decrypt backup: {str(e)}"
            
            # Verify package structure
            if 'metadata' not in backup_package or 'files' not in backup_package:
                return False, "Invalid backup package structure"
            
            metadata = backup_package['metadata']
            files_data = backup_package['files']
            
            print(f"📥 RESTORE: Found backup with {metadata.get('total_accounts', 0)} accounts")
            print(f"📥 RESTORE: Backup created: {metadata.get('created_at', 'Unknown')}")
            
            # Confirm restoration
            confirm_msg = (f"This will restore a backup containing:\n\n"
                          f"• {metadata.get('total_accounts', 0)} accounts\n"
                          f"• {metadata.get('file_count', 0)} files\n"
                          f"• Created: {metadata.get('created_at', 'Unknown')}\n\n"
                          f"⚠️ This will REPLACE all current data!\n\n"
                          f"Do you want to continue?")
            
            # Determine restore location
            if restore_location is None:
                restore_location = os.path.dirname(database_manager.db_path)
            
            # Create backup of current data before restore
            current_backup_name = f"PreRestore_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            current_backup_success, current_backup_path = self.create_comprehensive_backup(
                database_manager, master_password, current_backup_name, is_automatic=True
            )
            
            if current_backup_success:
                print(f"✅ RESTORE: Current data backed up to {current_backup_path}")
            else:
                print("⚠️ RESTORE: Warning - Could not backup current data")
            
            # Restore files
            restored_files = []
            
            print(f"📥 RESTORE: Restoring {len(files_data)} files...")
            
            for file_type, file_info in files_data.items():
                try:
                    # Decrypt file data
                    encrypted_data = base64.b64decode(file_info['data'].encode())
                    decrypted_data = self.crypto.decrypt_data(encrypted_data, backup_key)
                    file_data = base64.b64decode(decrypted_data.encode())
                    
                    # Verify file checksum
                    calculated_checksum = hashlib.sha256(file_data).hexdigest()
                    if calculated_checksum != file_info['checksum']:
                        print(f"⚠️ RESTORE: Checksum mismatch for {file_type}")
                        continue
                    
                    # Determine restore file path
                    restore_file_path = self._get_restore_file_path(
                        file_type, restore_location, file_info['original_name']
                    )
                    
                    # Create directory if needed
                    os.makedirs(os.path.dirname(restore_file_path), exist_ok=True)
                    
                    # Write restored file
                    with open(restore_file_path, 'wb') as f:
                        f.write(file_data)
                    
                    restored_files.append(restore_file_path)
                    print(f"✅ RESTORE: Restored {file_type} -> {restore_file_path}")
                    
                except Exception as e:
                    print(f"❌ RESTORE: Failed to restore {file_type}: {e}")
                    continue
            
            if not restored_files:
                return False, "No files could be restored"
            
            # Log restore operation
            self._log_backup_operation("RESTORE", backup_path, 
                                     metadata.get('total_accounts', 0), 
                                     sum(f.get('original_size', 0) for f in files_data.values()))
            
            print(f"✅ RESTORE: Successfully restored {len(restored_files)} files")
            
            return True, f"Restore completed successfully. {len(restored_files)} files restored."
            
        except Exception as e:
            print(f"❌ RESTORE: Restore operation failed: {e}")
            import traceback
            traceback.print_exc()
            return False, f"Restore failed: {str(e)}"
    
    def verify_backup_integrity(self, backup_path: str, master_password: str) -> bool:
        """Verify backup file integrity and authenticity"""
        
        try:
            print(f"🔍 VERIFY: Checking backup integrity: {backup_path}")
            
            if not os.path.exists(backup_path):
                print("❌ VERIFY: Backup file not found")
                return False
            
            with open(backup_path, 'rb') as f:
                # Read and verify header
                header = f.read(16)
                if header != b"SVAULT_BACKUP_V2":
                    print("❌ VERIFY: Invalid backup file header")
                    return False
                
                # Read components
                backup_salt = f.read(32)
                sig_length = int.from_bytes(f.read(4), 'big')
                integrity_signature = f.read(sig_length)
                encrypted_package = f.read()
            
            # Regenerate keys
            backup_key = self.crypto.generate_key_from_password(master_password + "_backup", backup_salt)
            integrity_key = self.crypto.generate_key_from_password(master_password + "_backup_integrity", backup_salt)
            
            # Verify HMAC signature
            if not self.crypto.verify_hmac(encrypted_package, integrity_signature, integrity_key):
                print("❌ VERIFY: HMAC signature verification failed")
                return False
            
            # Try to decrypt and parse package
            try:
                decrypted_json = self.crypto.decrypt_data(encrypted_package, backup_key)
                backup_package = json.loads(decrypted_json)
                
                # Verify required fields
                required_fields = ['metadata', 'files', 'checksum_list']
                for field in required_fields:
                    if field not in backup_package:
                        print(f"❌ VERIFY: Missing required field: {field}")
                        return False
                
                # Verify metadata structure
                metadata = backup_package['metadata']
                required_metadata = ['version', 'created_at', 'file_count']
                for field in required_metadata:
                    if field not in metadata:
                        print(f"❌ VERIFY: Missing metadata field: {field}")
                        return False
                
                # Verify file count consistency
                expected_files = metadata.get('file_count', 0)
                actual_files = len(backup_package['files'])
                if expected_files != actual_files:
                    print(f"❌ VERIFY: File count mismatch: expected {expected_files}, found {actual_files}")
                    return False
                
                print("✅ VERIFY: Backup integrity verification passed")
                return True
                
            except Exception as e:
                print(f"❌ VERIFY: Failed to decrypt/parse backup: {e}")
                return False
                
        except Exception as e:
            print(f"❌ VERIFY: Integrity check failed: {e}")
            return False
    
    def list_available_backups(self) -> List[Dict[str, Any]]:
        """List all available backups with their metadata"""
        
        backups = []
        
        # Check both automatic and manual backup folders
        for folder_name in ["automatic", "manual"]:
            folder_path = self.backup_folder / folder_name
            
            if not folder_path.exists():
                continue
            
            for backup_file in folder_path.glob("*.svault"):
                try:
                    # Quick metadata extraction without full decryption
                    backup_info = {
                        'name': backup_file.name,
                        'path': str(backup_file),
                        'type': folder_name,
                        'size': backup_file.stat().st_size,
                        'modified': datetime.fromtimestamp(backup_file.stat().st_mtime),
                        'is_valid': False,
                        'metadata': {}
                    }
                    
                    # Try to read basic info from file
                    try:
                        with open(backup_file, 'rb') as f:
                            header = f.read(16)
                            if header == b"SVAULT_BACKUP_V2":
                                backup_info['is_valid'] = True
                                backup_info['version'] = 2
                            else:
                                backup_info['version'] = 1  # Legacy format
                    except:
                        backup_info['is_valid'] = False
                    
                    backups.append(backup_info)
                    
                except Exception as e:
                    print(f"Error reading backup {backup_file}: {e}")
                    continue
        
        # Sort by modification time (newest first)
        backups.sort(key=lambda x: x['modified'], reverse=True)
        
        return backups
    
    def get_backup_details(self, backup_path: str, master_password: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific backup"""
        
        try:
            if not self.verify_backup_integrity(backup_path, master_password):
                return None
            
            with open(backup_path, 'rb') as f:
                # Read header and components
                header = f.read(16)
                backup_salt = f.read(32)
                sig_length = int.from_bytes(f.read(4), 'big')
                integrity_signature = f.read(sig_length)
                encrypted_package = f.read()
            
            # Regenerate keys and decrypt
            backup_key = self.crypto.generate_key_from_password(master_password + "_backup", backup_salt)
            decrypted_json = self.crypto.decrypt_data(encrypted_package, backup_key)
            backup_package = json.loads(decrypted_json)
            
            # Extract detailed information
            metadata = backup_package['metadata']
            files_info = backup_package['files']
            
            details = {
                'metadata': metadata,
                'file_details': [],
                'total_original_size': 0,
                'is_encrypted': True,
                'encryption_method': metadata.get('encryption_method', 'AES-256-GCM'),
                'key_derivation': metadata.get('key_derivation', 'PBKDF2-SHA256')
            }
            
            # Process file details
            for file_type, file_info in files_info.items():
                file_detail = {
                    'type': file_type,
                    'original_name': file_info.get('original_name', 'Unknown'),
                    'size': file_info.get('original_size', 0),
                    'checksum': file_info.get('checksum', 'Unknown')
                }
                details['file_details'].append(file_detail)
                details['total_original_size'] += file_detail['size']
            
            return details
            
        except Exception as e:
            print(f"Error getting backup details: {e}")
            return None
    
    def delete_backup(self, backup_path: str) -> Tuple[bool, str]:
        """Securely delete a backup file"""
        
        try:
            if not os.path.exists(backup_path):
                return False, "Backup file not found"
            
            # Secure deletion by overwriting with random data
            file_size = os.path.getsize(backup_path)
            
            with open(backup_path, 'r+b') as f:
                # Overwrite with random data (3 passes)
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
            
            # Actually delete the file
            os.remove(backup_path)
            
            self._log_backup_operation("DELETE", backup_path, 0, 0)
            
            print(f"✅ BACKUP: Securely deleted backup: {backup_path}")
            return True, "Backup deleted successfully"
            
        except Exception as e:
            print(f"❌ BACKUP: Failed to delete backup: {e}")
            return False, f"Failed to delete backup: {str(e)}"
    
    def cleanup_old_backups(self, max_automatic: int = 10, max_manual: int = 50, 
                          max_age_days: int = 90) -> Tuple[int, int]:
        """Clean up old backups based on retention policy"""
        
        deleted_count = 0
        error_count = 0
        
        try:
            # Get all backups
            all_backups = self.list_available_backups()
            
            # Separate automatic and manual backups
            automatic_backups = [b for b in all_backups if b['type'] == 'automatic']
            manual_backups = [b for b in all_backups if b['type'] == 'manual']
            
            # Sort by modification time (oldest first for deletion)
            automatic_backups.sort(key=lambda x: x['modified'])
            manual_backups.sort(key=lambda x: x['modified'])
            
            # Delete excess automatic backups
            if len(automatic_backups) > max_automatic:
                excess_auto = automatic_backups[:-max_automatic]
                for backup in excess_auto:
                    success, _ = self.delete_backup(backup['path'])
                    if success:
                        deleted_count += 1
                    else:
                        error_count += 1
            
            # Delete excess manual backups
            if len(manual_backups) > max_manual:
                excess_manual = manual_backups[:-max_manual]
                for backup in excess_manual:
                    success, _ = self.delete_backup(backup['path'])
                    if success:
                        deleted_count += 1
                    else:
                        error_count += 1
            
            # Delete old backups (age-based)
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            
            for backup in all_backups:
                if backup['modified'] < cutoff_date:
                    success, _ = self.delete_backup(backup['path'])
                    if success:
                        deleted_count += 1
                    else:
                        error_count += 1
            
            print(f"🧹 CLEANUP: Deleted {deleted_count} old backups, {error_count} errors")
            
            return deleted_count, error_count
            
        except Exception as e:
            print(f"❌ CLEANUP: Backup cleanup failed: {e}")
            return 0, 1
    
    def _collect_vault_files(self, database_manager) -> List[Tuple[str, str]]:
        """Collect all vault files that need to be backed up"""
        
        files_to_backup = []
        
        # Get file paths from database manager
        if hasattr(database_manager, 'secure_file_manager') and database_manager.secure_file_manager:
            # Secure file manager paths
            file_mappings = {
                'metadata_db': database_manager.secure_file_manager.get_metadata_db_path(),
                'sensitive_db': database_manager.secure_file_manager.get_sensitive_db_path(),
                'salt_file': database_manager.secure_file_manager.get_salt_path(),
                'integrity_file': database_manager.secure_file_manager.get_integrity_path()
            }
        else:
            # Legacy file paths
            file_mappings = {
                'metadata_db': f"{database_manager.db_path}_metadata.db",
                'sensitive_db': f"{database_manager.db_path}_sensitive.db",
                'salt_file': f"{database_manager.db_path}_salt",
                'integrity_file': f"{database_manager.db_path}_integrity"
            }
        
        # Add settings file
        file_mappings['settings'] = "vault_settings.json"
        
        # Collect existing files
        for file_type, file_path in file_mappings.items():
            if os.path.exists(file_path):
                files_to_backup.append((file_path, file_type))
                print(f"📁 BACKUP: Found {file_type}: {file_path}")
        
        return files_to_backup
    
    def _count_accounts(self, database_manager) -> int:
        """Count the total number of accounts in the database"""
        
        try:
            metadata_conn = sqlite3.connect(database_manager.metadata_db)
            cursor = metadata_conn.execute("""
                SELECT COUNT(*) FROM accounts 
                WHERE id != 'master_account'
            """)
            count = cursor.fetchone()[0]
            metadata_conn.close()
            return count
            
        except Exception as e:
            print(f"Warning: Could not count accounts: {e}")
            return 0
    
    def _get_restore_file_path(self, file_type: str, restore_location: str, original_name: str) -> str:
        """Get the correct restore path for a file based on its type"""
        
        if file_type == 'metadata_db':
            return os.path.join(restore_location, "manageyouraccount_metadata.db")
        elif file_type == 'sensitive_db':
            return os.path.join(restore_location, "manageyouraccount_sensitive.db")
        elif file_type == 'salt_file':
            return os.path.join(restore_location, "manageyouraccount_salt")
        elif file_type == 'integrity_file':
            return os.path.join(restore_location, "manageyouraccount_integrity")
        elif file_type == 'settings':
            return os.path.join(restore_location, "vault_settings.json")
        else:
            return os.path.join(restore_location, original_name)
    
    def _log_backup_operation(self, operation: str, backup_path: str, 
                             account_count: int, file_size: int):
        """Log backup operations for audit trail"""
        
        try:
            log_file = self.backup_folder / "backup_log.txt"
            
            log_entry = (f"[{datetime.now().isoformat()}] {operation}: "
                        f"{os.path.basename(backup_path)} - "
                        f"{account_count} accounts, {file_size} bytes\n")
            
            with open(log_file, 'a') as f:
                f.write(log_entry)
                
        except Exception as e:
            print(f"Warning: Could not log backup operation: {e}")

class BackupScheduler:
    """Automatic backup scheduling system"""
    
    def __init__(self, backup_manager: SecureBackupManager, database_manager):
        self.backup_manager = backup_manager
        self.database_manager = database_manager
        self.is_running = False
        self.scheduler_thread = None
        self.last_backup = None
        
    def start_automatic_backups(self, master_password: str, interval_hours: int = 24):
        """Start automatic backup scheduler"""
        
        if self.is_running:
            print("⚠️ SCHEDULER: Automatic backups already running")
            return
        
        self.is_running = True
        
        def backup_worker():
            while self.is_running:
                try:
                    # Wait for the specified interval
                    time.sleep(interval_hours * 3600)  # Convert hours to seconds
                    
                    if self.is_running:  # Check again in case we were stopped
                        print("🔄 SCHEDULER: Starting automatic backup...")
                        
                        success, result = self.backup_manager.create_comprehensive_backup(
                            self.database_manager, 
                            master_password, 
                            "Automatic", 
                            is_automatic=True
                        )
                        
                        if success:
                            print(f"✅ SCHEDULER: Automatic backup completed: {result}")
                            self.last_backup = datetime.now()
                            
                            # Clean up old backups
                            deleted, errors = self.backup_manager.cleanup_old_backups()
                            if deleted > 0:
                                print(f"🧹 SCHEDULER: Cleaned up {deleted} old backups")
                        else:
                            print(f"❌ SCHEDULER: Automatic backup failed: {result}")
                            
                except Exception as e:
                    print(f"❌ SCHEDULER: Backup scheduler error: {e}")
                    
        self.scheduler_thread = threading.Thread(target=backup_worker, daemon=True)
        self.scheduler_thread.start()
        
        print(f"✅ SCHEDULER: Automatic backups started (interval: {interval_hours} hours)")
    
    def stop_automatic_backups(self):
        """Stop automatic backup scheduler"""
        
        self.is_running = False
        
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            print("🛑 SCHEDULER: Stopping automatic backups...")
            # Thread will stop on next iteration
        
        print("✅ SCHEDULER: Automatic backups stopped")
    
    def get_scheduler_status(self) -> Dict[str, Any]:
        """Get current scheduler status"""
        
        return {
            'is_running': self.is_running,
            'last_backup': self.last_backup.isoformat() if self.last_backup else None,
            'thread_alive': self.scheduler_thread.is_alive() if self.scheduler_thread else False
        }

class BackupGUI:
    """Enhanced GUI for backup management with folder integration"""
    
    def __init__(self, parent_gui):
        self.parent_gui = parent_gui
        self.backup_manager = SecureBackupManager(
            parent_gui.crypto, 
            parent_gui.secure_file_manager
        )
        self.backup_scheduler = None
        
        # Create backup folder icon/shortcut on desktop
        self.create_backup_folder_shortcut()
    
    def create_backup_folder_shortcut(self):
        """Create a shortcut to the backup folder on desktop"""
        
        try:
            desktop_path = Path.home() / "Desktop"
            
            if not desktop_path.exists():
                # Try alternate desktop locations
                desktop_path = Path.home() / "OneDrive" / "Desktop"
                if not desktop_path.exists():
                    desktop_path = Path.home()  # Fallback to home directory
            
            shortcut_path = desktop_path / "SecureVault Backups"
            backup_folder = self.backup_manager.backup_folder
            
            # Create shortcut based on OS
            import sys
            
            if sys.platform == "win32":
                # Windows shortcut
                try:
                    import win32com.client
                    shell = win32com.client.Dispatch("WScript.Shell")
                    shortcut = shell.CreateShortCut(str(shortcut_path) + ".lnk")
                    shortcut.Targetpath = str(backup_folder)
                    shortcut.IconLocation = str(backup_folder / "README.txt")
                    shortcut.Description = "SecureVault Backup Directory"
                    shortcut.save()
                    print(f"🔗 SHORTCUT: Windows shortcut created at {shortcut_path}.lnk")
                except ImportError:
                    # Fallback: create a simple text file with the path
                    with open(str(shortcut_path) + "_Path.txt", "w") as f:
                        f.write(f"SecureVault Backup Directory\n\nPath: {backup_folder}\n\n")
                        f.write("Copy and paste this path into your file manager to access your backups.")
                    print(f"🔗 SHORTCUT: Path file created at {shortcut_path}_Path.txt")
                    
            elif sys.platform == "darwin":  # macOS
                # Create an alias
                try:
                    import subprocess
                    script = f'''
                    tell application "Finder"
                        make alias file to folder POSIX file "{backup_folder}" at desktop
                        set name of result to "SecureVault Backups"
                    end tell
                    '''
                    subprocess.run(["osascript", "-e", script], check=True)
                    print(f"🔗 SHORTCUT: macOS alias created on desktop")
                except:
                    # Fallback: create symbolic link
                    try:
                        if shortcut_path.exists():
                            shortcut_path.unlink()
                        shortcut_path.symlink_to(backup_folder)
                        print(f"🔗 SHORTCUT: Symbolic link created at {shortcut_path}")
                    except Exception as e:
                        print(f"Warning: Could not create shortcut: {e}")
                        
            else:  # Linux and other Unix-like systems
                # Create symbolic link
                try:
                    if shortcut_path.exists():
                        shortcut_path.unlink()
                    shortcut_path.symlink_to(backup_folder)
                    print(f"🔗 SHORTCUT: Symbolic link created at {shortcut_path}")
                except Exception as e:
                    print(f"Warning: Could not create shortcut: {e}")
                    
        except Exception as e:
            print(f"Warning: Could not create backup folder shortcut: {e}")
    
    def show_backup_restore_enhanced(self):
        """Enhanced backup and restore interface"""
        
        for widget in self.parent_gui.main_panel.winfo_children():
            widget.destroy()
        
        # Header
        header = ctk.CTkFrame(self.parent_gui.main_panel)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text="💾 Backup & Restore Center", 
                     font=ctk.CTkFont(size=24, weight="bold")).pack(side="left", padx=25, pady=15)
        
        folder_btn = ctk.CTkButton(header, text="📁 Open Backup Folder",
                                   command=self.open_backup_folder,
                                   width=180, height=40,
                                   font=ctk.CTkFont(size=16))
        folder_btn.pack(side="right", padx=25, pady=15)
        
        # Main content
        content = ctk.CTkScrollableFrame(self.parent_gui.main_panel)
        content.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Quick Actions Section
        self.create_quick_actions_section(content)
        
        # Backup List Section
        self.create_backup_list_section(content)
        
        # Automatic Backup Section
        self.create_automatic_backup_section(content)
        
        # Statistics Section
        self.create_statistics_section(content)
    
    def create_quick_actions_section(self, parent):
        """Create quick actions section"""
        
        actions_frame = ctk.CTkFrame(parent)
        actions_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(actions_frame, text="🚀 Quick Actions", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        button_frame = ctk.CTkFrame(actions_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=10)
        
        # Create Backup Button
        backup_btn = ctk.CTkButton(
            button_frame, 
            text="💾 Create Backup Now",
            command=self.create_backup_dialog_enhanced,
            width=200, height=60,
            font=ctk.CTkFont(size=18, weight="bold"),
            fg_color="#2E8B57",
            hover_color="#228B22"
        )
        backup_btn.pack(side="left", padx=10)
        
        # Restore Backup Button
        restore_btn = ctk.CTkButton(
            button_frame,
            text="📥 Restore from Backup",
            command=self.restore_backup_dialog_enhanced,
            width=200, height=60,
            font=ctk.CTkFont(size=18, weight="bold"),
            fg_color="#4169E1",
            hover_color="#1E90FF"
        )
        restore_btn.pack(side="left", padx=10)
        
        # Verify Backup Button
        verify_btn = ctk.CTkButton(
            button_frame,
            text="🔍 Verify Backup",
            command=self.verify_backup_dialog,
            width=200, height=60,
            font=ctk.CTkFont(size=18),
            fg_color="#FF8C00",
            hover_color="#FF7F50"
        )
        verify_btn.pack(side="left", padx=10)
    
    def create_backup_list_section(self, parent):
        """Create backup list section"""
        
        list_frame = ctk.CTkFrame(parent)
        list_frame.pack(fill="both", expand=True, padx=20, pady=15)
        
        header_frame = ctk.CTkFrame(list_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header_frame, text="📋 Available Backups", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(side="left")
        
        refresh_btn = ctk.CTkButton(header_frame, text="🔄 Refresh",
                                    command=self.refresh_backup_list,
                                    width=100, height=35)
        refresh_btn.pack(side="right", padx=10)
        
        cleanup_btn = ctk.CTkButton(header_frame, text="🧹 Cleanup Old",
                                    command=self.cleanup_old_backups_dialog,
                                    width=120, height=35)
        cleanup_btn.pack(side="right")
        
        # Backup list container
        self.backup_list_container = ctk.CTkScrollableFrame(list_frame, height=200)
        self.backup_list_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self.refresh_backup_list()
    
    def create_automatic_backup_section(self, parent):
        """Create automatic backup section"""
        
        auto_frame = ctk.CTkFrame(parent)
        auto_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(auto_frame, text="⏰ Automatic Backups", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        settings_frame = ctk.CTkFrame(auto_frame, fg_color="transparent")
        settings_frame.pack(fill="x", padx=20, pady=10)
        
        # Enable/Disable automatic backups
        self.auto_backup_enabled = tk.BooleanVar(value=False)
        auto_checkbox = ctk.CTkCheckBox(settings_frame, 
                                        text="Enable Automatic Backups",
                                        variable=self.auto_backup_enabled,
                                        command=self.toggle_automatic_backups,
                                        font=ctk.CTkFont(size=16))
        auto_checkbox.pack(anchor="w", pady=5)
        
        # Backup interval
        interval_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        interval_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(interval_frame, text="Backup Interval (hours):", 
                     font=ctk.CTkFont(size=14)).pack(side="left")
        
        self.interval_var = tk.IntVar(value=24)
        interval_slider = ctk.CTkSlider(interval_frame, from_=1, to=168,  # 1 hour to 1 week
                                        variable=self.interval_var, width=200)
        interval_slider.pack(side="left", padx=10)
        
        self.interval_label = ctk.CTkLabel(interval_frame, text="24 hours")
        self.interval_label.pack(side="left", padx=10)
        
        def update_interval_label(value):
            hours = int(float(value))
            if hours < 24:
                self.interval_label.configure(text=f"{hours} hours")
            else:
                days = hours // 24
                remaining_hours = hours % 24
                if remaining_hours == 0:
                    self.interval_label.configure(text=f"{days} days")
                else:
                    self.interval_label.configure(text=f"{days}d {remaining_hours}h")
        
        interval_slider.configure(command=update_interval_label)
        
        # Status display
        self.auto_status_label = ctk.CTkLabel(auto_frame, text="Automatic backups: Disabled",
                                              font=ctk.CTkFont(size=14),
                                              text_color="#888888")
        self.auto_status_label.pack(pady=10)
    
    def create_statistics_section(self, parent):
        """Create backup statistics section"""
        
        stats_frame = ctk.CTkFrame(parent)
        stats_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(stats_frame, text="📊 Backup Statistics", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        self.stats_container = ctk.CTkFrame(stats_frame, fg_color="transparent")
        self.stats_container.pack(fill="x", padx=20, pady=10)
        
        self.update_statistics()
    
    def refresh_backup_list(self):
        """Refresh the backup list display"""
        
        # Clear existing items
        for widget in self.backup_list_container.winfo_children():
            widget.destroy()
        
        # Get available backups
        backups = self.backup_manager.list_available_backups()
        
        if not backups:
            no_backups_label = ctk.CTkLabel(
                self.backup_list_container,
                text="📭 No backups found\n\nCreate your first backup using the 'Create Backup Now' button above.",
                font=ctk.CTkFont(size=16),
                text_color="#888888",
                justify="center"
            )
            no_backups_label.pack(pady=50)
            return
        
        # Display backups
        for backup in backups:
            self.create_backup_item(self.backup_list_container, backup)
    
    def create_backup_item(self, parent, backup_info):
        """Create a backup item in the list"""
        
        item_frame = ctk.CTkFrame(parent, corner_radius=10)
        item_frame.pack(fill="x", padx=10, pady=5)
        
        # Main info frame
        info_frame = ctk.CTkFrame(item_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)
        
        # Backup name and type
        name_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        name_frame.pack(fill="x", anchor="w")
        
        # Type icon and name
        type_icon = "🤖" if backup_info['type'] == 'automatic' else "👤"
        name_text = f"{type_icon} {backup_info['name']}"
        
        name_label = ctk.CTkLabel(name_frame, text=name_text,
                                  font=ctk.CTkFont(size=16, weight="bold"))
        name_label.pack(side="left", anchor="w")
        
        # Validation status
        status_icon = "✅" if backup_info['is_valid'] else "❌"
        status_text = "Valid" if backup_info['is_valid'] else "Invalid"
        status_color = "#00AA00" if backup_info['is_valid'] else "#AA0000"
        
        status_label = ctk.CTkLabel(name_frame, text=f"{status_icon} {status_text}",
                                    font=ctk.CTkFont(size=12),
                                    text_color=status_color)
        status_label.pack(side="right")
        
        # Details
        details_text = (f"📅 {backup_info['modified'].strftime('%Y-%m-%d %H:%M:%S')} | "
                       f"💾 {self.format_file_size(backup_info['size'])}")
        
        details_label = ctk.CTkLabel(info_frame, text=details_text,
                                     font=ctk.CTkFont(size=12),
                                     text_color="#888888")
        details_label.pack(anchor="w", pady=(5, 0))
        
        # Action buttons
        button_frame = ctk.CTkFrame(item_frame, fg_color="transparent")
        button_frame.pack(side="right", padx=10, pady=10)
        
        buttons = [
            ("🔍 Details", lambda p=backup_info['path']: self.show_backup_details(p)),
            ("📥 Restore", lambda p=backup_info['path']: self.restore_specific_backup(p)),
            ("🗑️ Delete", lambda p=backup_info['path']: self.delete_backup_confirm(p))
        ]
        
        for text, command in buttons:
            btn = ctk.CTkButton(button_frame, text=text, width=90, height=35,
                                command=command, font=ctk.CTkFont(size=12))
            if "Delete" in text:
                btn.configure(fg_color="#DC143C", hover_color="#B22222")
            btn.pack(pady=2)
    
    def format_file_size(self, size_bytes):
        """Format file size in human-readable format"""
        
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def create_backup_dialog_enhanced(self):
        """Enhanced backup creation dialog"""
        
        dialog = ctk.CTkToplevel(self.parent_gui.root)
        dialog.title("💾 Create New Backup")
        dialog.geometry("500x550")
        dialog.grab_set()
        dialog.resizable(False, False)
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        ctk.CTkLabel(main_frame, text="💾 Create New Backup",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        
        # Backup name
        ctk.CTkLabel(main_frame, text="Backup Name (Optional):",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        
        name_entry = ctk.CTkEntry(main_frame, width=400, height=40,
                                  placeholder_text="e.g., Before_Password_Change, Monthly_Backup")
        name_entry.pack(padx=20, pady=(0, 15))
        
        # Master password verification
        ctk.CTkLabel(main_frame, text="Master Password:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))
        
        password_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        password_frame.pack(padx=20, pady=(0, 20))
        
        password_entry = ctk.CTkEntry(password_frame, width=350, height=40,
                                      placeholder_text="Enter your master password",
                                      show="*")
        password_entry.pack(side="left", padx=(0, 10))
        
        def toggle_password():
            if password_entry.cget("show") == "*":
                password_entry.configure(show="")
                eye_btn.configure(text="🙈")
            else:
                password_entry.configure(show="*")
                eye_btn.configure(text="👁️")
        
        eye_btn = ctk.CTkButton(password_frame, text="👁️", width=40, height=40,
                                command=toggle_password)
        eye_btn.pack(side="right")
        
        # Progress indicator
        progress_label = ctk.CTkLabel(main_frame, text="", font=ctk.CTkFont(size=12))
        progress_label.pack(pady=10)
        
        # Info text
        info_text = ("This will create an encrypted backup of all your vault data including:\n"
                    "• Account credentials and metadata\n"
                    "• Database files and security settings\n"
                    "• Configuration and audit logs")
        
        ctk.CTkLabel(main_frame, text=info_text,
                     font=ctk.CTkFont(size=12),
                     text_color="#888888",
                     justify="left").pack(padx=20, pady=15)
        
        def create_backup():
            name = name_entry.get().strip()
            password = password_entry.get().strip()
            
            if not password:
                progress_label.configure(text="❌ Master password is required", text_color="#FF4444")
                password_entry.focus()
                return
            
            try:
                progress_label.configure(text="🔐 Verifying password...", text_color="#FFAA00")
                dialog.update()
                
                # Verify password first
                if not self.backup_manager.verify_master_password(password, self.parent_gui.database):
                    progress_label.configure(text="❌ Invalid master password", text_color="#FF4444")
                    password_entry.focus()
                    password_entry.select_range(0, tk.END)
                    return
                
                progress_label.configure(text="💾 Creating backup...", text_color="#0088FF")
                dialog.update()
                
                # Create backup
                success, result = self.backup_manager.create_comprehensive_backup(
                    self.parent_gui.database, password, name, is_automatic=False
                )
                
                if success:
                    progress_label.configure(text="✅ Backup created successfully!", text_color="#00AA00")
                    dialog.update()
                    
                    # Show success dialog
                    success_msg = (f"Backup created successfully!\n\n"
                                  f"📂 Location: {os.path.basename(result)}\n"
                                  f"📁 Folder: {os.path.dirname(result)}")
                    
                    messagebox.showinfo("Backup Complete", success_msg)
                    
                    dialog.destroy()
                    self.refresh_backup_list()
                    self.update_statistics()
                else:
                    progress_label.configure(text=f"❌ {result}", text_color="#FF4444")
                    
            except Exception as e:
                progress_label.configure(text=f"❌ Error: {str(e)}", text_color="#FF4444")
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel",
                                   command=dialog.destroy,
                                   width=120, height=45)
        cancel_btn.pack(side="left", padx=15)
        
        create_btn = ctk.CTkButton(button_frame, text="💾 Create Backup",
                                   command=create_backup,
                                   width=150, height=45,
                                   font=ctk.CTkFont(size=16, weight="bold"),
                                   fg_color="#2E8B57",
                                   hover_color="#228B22")
        create_btn.pack(side="right", padx=15)
        
        password_entry.bind('<Return>', lambda e: create_backup())
        password_entry.focus()
    
    def restore_backup_dialog_enhanced(self):
        """Enhanced backup restoration dialog"""
        
        dialog = ctk.CTkToplevel(self.parent_gui.root)
        dialog.title("📥 Restore from Backup")
        dialog.geometry("600x500")
        dialog.grab_set()
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        ctk.CTkLabel(main_frame, text="📥 Restore from Backup",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        
        # File selection
        file_frame = ctk.CTkFrame(main_frame)
        file_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(file_frame, text="Select Backup File:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 5))
        
        selection_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        selection_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.selected_backup_var = tk.StringVar()
        file_entry = ctk.CTkEntry(selection_frame, textvariable=self.selected_backup_var,
                                  width=400, height=40, state="readonly")
        file_entry.pack(side="left", padx=(0, 10))
        
        def browse_backup():
            file_path = filedialog.askopenfilename(
                title="Select Backup File",
                initialdir=str(self.backup_manager.backup_folder),
                filetypes=[
                    ("SecureVault Backup", "*.svault"),
                    ("Legacy Vault Backup", "*.vault"),
                    ("All Files", "*.*")
                ]
            )
            if file_path:
                self.selected_backup_var.set(file_path)
                # Try to load backup info
                self.load_backup_preview(preview_frame, file_path)
        
        browse_btn = ctk.CTkButton(selection_frame, text="📁 Browse",
                                   command=browse_backup,
                                   width=100, height=40)
        browse_btn.pack(side="right")
        
        # Recent backups quick selection
        recent_frame = ctk.CTkFrame(main_frame)
        recent_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(recent_frame, text="Recent Backups:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        
        recent_backups = self.backup_manager.list_available_backups()[:5]  # Show last 5
        
        if recent_backups:
            for backup in recent_backups:
                backup_btn = ctk.CTkButton(
                    recent_frame,
                    text=f"{'🤖' if backup['type'] == 'automatic' else '👤'} {backup['name'][:40]}...",
                    command=lambda b=backup: self.select_recent_backup(b, preview_frame),
                    width=500, height=35,
                    anchor="w",
                    font=ctk.CTkFont(size=12)
                )
                backup_btn.pack(fill="x", padx=15, pady=2)
        else:
            ctk.CTkLabel(recent_frame, text="No recent backups found",
                         text_color="#888888").pack(padx=15, pady=10)
        
        # Backup preview
        preview_frame = ctk.CTkFrame(main_frame)
        preview_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(preview_frame, text="Backup Preview:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
        
        self.preview_text = ctk.CTkTextbox(preview_frame, height=120)
        self.preview_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.preview_text.insert("1.0", "Select a backup file to see preview information...")
        self.preview_text.configure(state="disabled")
        
        # Master password
        password_frame = ctk.CTkFrame(main_frame)
        password_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(password_frame, text="Master Password:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 5))
        
        pass_input_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        pass_input_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        password_entry = ctk.CTkEntry(pass_input_frame, width=400, height=40,
                                      placeholder_text="Enter your master password",
                                      show="*")
        password_entry.pack(side="left", padx=(0, 10))
        
        def toggle_password():
            if password_entry.cget("show") == "*":
                password_entry.configure(show="")
                eye_btn.configure(text="🙈")
            else:
                password_entry.configure(show="*")
                eye_btn.configure(text="👁️")
        
        eye_btn = ctk.CTkButton(pass_input_frame, text="👁️", width=40, height=40,
                                command=toggle_password)
        eye_btn.pack(side="right")
        
        # Progress indicator
        progress_label = ctk.CTkLabel(main_frame, text="", font=ctk.CTkFont(size=12))
        progress_label.pack(pady=10)
        
        def restore_backup():
            backup_path = self.selected_backup_var.get().strip()
            password = password_entry.get().strip()
            
            if not backup_path:
                progress_label.configure(text="❌ Please select a backup file", text_color="#FF4444")
                return
            
            if not password:
                progress_label.configure(text="❌ Master password is required", text_color="#FF4444")
                password_entry.focus()
                return
            
            # Final confirmation
            result = messagebox.askyesnocancel(
                "⚠️ Restore Confirmation",
                "This will REPLACE ALL current data with the backup!\n\n"
                "Your current data will be automatically backed up first.\n\n"
                "This action cannot be undone!\n\n"
                "Are you sure you want to continue?"
            )
            
            if not result:
                return
            
            try:
                progress_label.configure(text="🔍 Verifying backup and password...", text_color="#FFAA00")
                dialog.update()
                
                # Verify backup integrity first
                if not self.backup_manager.verify_backup_integrity(backup_path, password):
                    progress_label.configure(text="❌ Backup verification failed", text_color="#FF4444")
                    return
                
                progress_label.configure(text="📥 Restoring backup...", text_color="#0088FF")
                dialog.update()
                
                # Restore backup
                success, result_msg = self.backup_manager.restore_from_backup(
                    backup_path, password, self.parent_gui.database
                )
                
                if success:
                    progress_label.configure(text="✅ Restore completed!", text_color="#00AA00")
                    dialog.update()
                    
                    messagebox.showinfo(
                        "Restore Complete",
                        f"{result_msg}\n\n"
                        "🔄 The application will now restart to load the restored data."
                    )
                    
                    dialog.destroy()
                    self.parent_gui.restart_program()
                else:
                    progress_label.configure(text=f"❌ {result_msg}", text_color="#FF4444")
                    
            except Exception as e:
                progress_label.configure(text=f"❌ Error: {str(e)}", text_color="#FF4444")
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel",
                                   command=dialog.destroy,
                                   width=120, height=45)
        cancel_btn.pack(side="left", padx=15)
        
        restore_btn = ctk.CTkButton(button_frame, text="📥 Restore Backup",
                                    command=restore_backup,
                                    width=150, height=45,
                                    font=ctk.CTkFont(size=16, weight="bold"),
                                    fg_color="#DC143C",
                                    hover_color="#B22222")
        restore_btn.pack(side="right", padx=15)
        
        password_entry.bind('<Return>', lambda e: restore_backup())
    
    def select_recent_backup(self, backup_info, preview_frame):
        """Select a recent backup and show preview"""
        self.selected_backup_var.set(backup_info['path'])
        self.load_backup_preview(preview_frame, backup_info['path'])
    
    def load_backup_preview(self, preview_frame, backup_path):
        """Load and display backup preview information"""
        try:
            self.preview_text.configure(state="normal")
            self.preview_text.delete("1.0", tk.END)
            
            # Basic file information
            file_stat = os.stat(backup_path)
            file_size = self.format_file_size(file_stat.st_size)
            modified = datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            preview_info = f"📁 File: {os.path.basename(backup_path)}\n"
            preview_info += f"💾 Size: {file_size}\n"
            preview_info += f"📅 Modified: {modified}\n"
            preview_info += f"📂 Location: {os.path.dirname(backup_path)}\n\n"
            
            # Try to read basic header info without full decryption
            try:
                with open(backup_path, 'rb') as f:
                    header = f.read(16)
                    if header == b"SVAULT_BACKUP_V2":
                        preview_info += "✅ Format: SecureVault Backup v2.0\n"
                        preview_info += "🔐 Encryption: AES-256-GCM\n"
                    elif header.startswith(b"SVAULT"):
                        preview_info += "⚠️ Format: Legacy SecureVault Backup\n"
                    else:
                        preview_info += "❓ Format: Unknown/Custom\n"
                        
                preview_info += "\n💡 Enter master password and click restore to continue."
                        
            except Exception:
                preview_info += "⚠️ Could not read backup header\n"
            
            self.preview_text.insert("1.0", preview_info)
            self.preview_text.configure(state="disabled")
            
        except Exception as e:
            self.preview_text.configure(state="normal")
            self.preview_text.delete("1.0", tk.END)
            self.preview_text.insert("1.0", f"❌ Error loading preview: {str(e)}")
            self.preview_text.configure(state="disabled")
    
    def verify_backup_dialog(self):
        """Dialog to verify backup integrity"""
        
        dialog = ctk.CTkToplevel(self.parent_gui.root)
        dialog.title("🔍 Verify Backup")
        dialog.geometry("500x400")
        dialog.grab_set()
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🔍 Verify Backup Integrity",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        
        # File selection
        ctk.CTkLabel(main_frame, text="Select Backup File:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        selection_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        selection_frame.pack(fill="x", padx=15, pady=10)
        
        file_var = tk.StringVar()
        file_entry = ctk.CTkEntry(selection_frame, textvariable=file_var,
                                  width=350, height=40, state="readonly")
        file_entry.pack(side="left", padx=(0, 10))
        
        def browse_verify():
            file_path = filedialog.askopenfilename(
                title="Select Backup to Verify",
                initialdir=str(self.backup_manager.backup_folder),
                filetypes=[("SecureVault Backup", "*.svault"), ("All Files", "*.*")]
            )
            if file_path:
                file_var.set(file_path)
        
        browse_btn = ctk.CTkButton(selection_frame, text="📁 Browse",
                                   command=browse_verify, width=100, height=40)
        browse_btn.pack(side="right")
        
        # Master password
        ctk.CTkLabel(main_frame, text="Master Password:",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(20, 5))
        
        password_entry = ctk.CTkEntry(main_frame, width=400, height=40,
                                      placeholder_text="Enter your master password", show="*")
        password_entry.pack(padx=15, pady=10)
        
        # Results area
        results_frame = ctk.CTkFrame(main_frame)
        results_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        results_text = ctk.CTkTextbox(results_frame, height=150)
        results_text.pack(fill="both", expand=True, padx=10, pady=10)
        results_text.insert("1.0", "Select a backup file and enter master password to verify...")
        results_text.configure(state="disabled")
        
        def verify_backup():
            backup_path = file_var.get().strip()
            password = password_entry.get().strip()
            
            if not backup_path or not password:
                messagebox.showerror("Error", "Please select a backup file and enter master password")
                return
            
            results_text.configure(state="normal")
            results_text.delete("1.0", tk.END)
            results_text.insert("1.0", "🔍 Verifying backup integrity...\n\n")
            results_text.update()
            
            try:
                # Verify integrity
                is_valid = self.backup_manager.verify_backup_integrity(backup_path, password)
                
                if is_valid:
                    results_text.insert(tk.END, "✅ VERIFICATION PASSED\n\n")
                    results_text.insert(tk.END, "Backup file integrity: ✅ Valid\n")
                    results_text.insert(tk.END, "Password authentication: ✅ Correct\n")
                    results_text.insert(tk.END, "File structure: ✅ Valid\n")
                    results_text.insert(tk.END, "Encryption: ✅ Intact\n\n")
                    
                    # Try to get detailed info
                    details = self.backup_manager.get_backup_details(backup_path, password)
                    if details:
                        metadata = details['metadata']
                        results_text.insert(tk.END, "📊 Backup Details:\n")
                        results_text.insert(tk.END, f"• Created: {metadata.get('created_at', 'Unknown')}\n")
                        results_text.insert(tk.END, f"• Accounts: {metadata.get('total_accounts', 0)}\n")
                        results_text.insert(tk.END, f"• Files: {len(details.get('file_details', []))}\n")
                        results_text.insert(tk.END, f"• Original Size: {self.format_file_size(details.get('total_original_size', 0))}\n")
                    
                else:
                    results_text.insert(tk.END, "❌ VERIFICATION FAILED\n\n")
                    results_text.insert(tk.END, "This backup file is either:\n")
                    results_text.insert(tk.END, "• Corrupted or damaged\n")
                    results_text.insert(tk.END, "• Created with a different password\n")
                    results_text.insert(tk.END, "• Not a valid SecureVault backup\n")
                    results_text.insert(tk.END, "• Tampered with or modified\n")
                
            except Exception as e:
                results_text.insert(tk.END, f"❌ VERIFICATION ERROR\n\n")
                results_text.insert(tk.END, f"Error: {str(e)}\n")
            
            results_text.configure(state="disabled")
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Close",
                                   command=dialog.destroy, width=120, height=45)
        cancel_btn.pack(side="left", padx=15)
        
        verify_btn = ctk.CTkButton(button_frame, text="🔍 Verify",
                                   command=verify_backup, width=120, height=45,
                                   font=ctk.CTkFont(size=16, weight="bold"))
        verify_btn.pack(side="right", padx=15)
    
    def show_backup_details(self, backup_path):
        """Show detailed information about a backup"""
        
        # Get master password first
        password = self.get_master_password_for_operation("View Backup Details")
        if not password:
            return
        
        try:
            details = self.backup_manager.get_backup_details(backup_path, password)
            if not details:
                messagebox.showerror("Error", "Could not read backup details")
                return
            
            # Create details dialog
            dialog = ctk.CTkToplevel(self.parent_gui.root)
            dialog.title(f"📋 Backup Details - {os.path.basename(backup_path)}")
            dialog.geometry("600x500")
            dialog.grab_set()
            
            main_frame = ctk.CTkFrame(dialog)
            main_frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            ctk.CTkLabel(main_frame, text="📋 Backup Details",
                         font=ctk.CTkFont(size=22, weight="bold")).pack(pady=15)
            
            # Details text area
            details_text = ctk.CTkTextbox(main_frame)
            details_text.pack(fill="both", expand=True, padx=15, pady=15)
            
            # Format details
            metadata = details['metadata']
            info = f"📁 File Information:\n"
            info += f"• Name: {os.path.basename(backup_path)}\n"
            info += f"• Location: {os.path.dirname(backup_path)}\n"
            info += f"• Size: {self.format_file_size(os.path.getsize(backup_path))}\n\n"
            
            info += f"📊 Backup Metadata:\n"
            info += f"• Created: {metadata.get('created_at', 'Unknown')}\n"
            info += f"• Version: {metadata.get('version', 'Unknown')}\n"
            info += f"• Backup Name: {metadata.get('backup_name', 'Unnamed')}\n"
            info += f"• Type: {'Automatic' if metadata.get('is_automatic') else 'Manual'}\n"
            info += f"• Accounts: {metadata.get('total_accounts', 0)}\n"
            info += f"• Original Size: {self.format_file_size(details.get('total_original_size', 0))}\n\n"
            
            info += f"🔐 Security Information:\n"
            info += f"• Encryption: {details.get('encryption_method', 'Unknown')}\n"
            info += f"• Key Derivation: {details.get('key_derivation', 'Unknown')}\n"
            info += f"• Iterations: {metadata.get('iterations', 'Unknown')}\n\n"
            
            info += f"📂 Included Files:\n"
            for file_detail in details.get('file_details', []):
                info += f"• {file_detail['type']}: {file_detail['original_name']} "
                info += f"({self.format_file_size(file_detail['size'])})\n"
            
            details_text.insert("1.0", info)
            details_text.configure(state="disabled")
            
            # Close button
            ctk.CTkButton(main_frame, text="Close", command=dialog.destroy,
                         width=120, height=40).pack(pady=15)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show backup details: {str(e)}")
    
    def restore_specific_backup(self, backup_path):
        """Restore a specific backup file"""
        self.selected_backup_var.set(backup_path)
        self.restore_backup_dialog_enhanced()
    
    def delete_backup_confirm(self, backup_path):
        """Confirm and delete a backup file"""
        
        backup_name = os.path.basename(backup_path)
        
        result = messagebox.askyesnocancel(
            "🗑️ Delete Backup",
            f"Are you sure you want to permanently delete this backup?\n\n"
            f"📁 {backup_name}\n\n"
            f"⚠️ This action cannot be undone!"
        )
        
        if result:
            try:
                success, message = self.backup_manager.delete_backup(backup_path)
                if success:
                    messagebox.showinfo("Deleted", f"Backup '{backup_name}' has been securely deleted.")
                    self.refresh_backup_list()
                    self.update_statistics()
                else:
                    messagebox.showerror("Error", f"Failed to delete backup: {message}")
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting backup: {str(e)}")
    
    def cleanup_old_backups_dialog(self):
        """Dialog for cleaning up old backups"""
        
        dialog = ctk.CTkToplevel(self.parent_gui.root)
        dialog.title("🧹 Cleanup Old Backups")
        dialog.geometry("500x350")
        dialog.grab_set()
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text="🧹 Cleanup Old Backups",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        
        # Settings
        settings_frame = ctk.CTkFrame(main_frame)
        settings_frame.pack(fill="x", padx=15, pady=15)
        
        # Max automatic backups
        ctk.CTkLabel(settings_frame, text="Maximum Automatic Backups:",
                     font=ctk.CTkFont(size=14)).pack(anchor="w", padx=15, pady=(15, 5))
        
        auto_var = tk.IntVar(value=10)
        auto_slider = ctk.CTkSlider(settings_frame, from_=1, to=50, variable=auto_var)
        auto_slider.pack(fill="x", padx=15, pady=5)
        
        auto_label = ctk.CTkLabel(settings_frame, text="10 backups")
        auto_label.pack(anchor="w", padx=15)
        
        def update_auto_label(value):
            auto_label.configure(text=f"{int(float(value))} backups")
        auto_slider.configure(command=update_auto_label)
        
        # Max manual backups
        ctk.CTkLabel(settings_frame, text="Maximum Manual Backups:",
                     font=ctk.CTkFont(size=14)).pack(anchor="w", padx=15, pady=(15, 5))
        
        manual_var = tk.IntVar(value=50)
        manual_slider = ctk.CTkSlider(settings_frame, from_=1, to=100, variable=manual_var)
        manual_slider.pack(fill="x", padx=15, pady=5)
        
        manual_label = ctk.CTkLabel(settings_frame, text="50 backups")
        manual_label.pack(anchor="w", padx=15)
        
        def update_manual_label(value):
            manual_label.configure(text=f"{int(float(value))} backups")
        manual_slider.configure(command=update_manual_label)
        
        # Max age
        ctk.CTkLabel(settings_frame, text="Maximum Age (days):",
                     font=ctk.CTkFont(size=14)).pack(anchor="w", padx=15, pady=(15, 5))
        
        age_var = tk.IntVar(value=90)
        age_slider = ctk.CTkSlider(settings_frame, from_=7, to=365, variable=age_var)
        age_slider.pack(fill="x", padx=15, pady=5)
        
        age_label = ctk.CTkLabel(settings_frame, text="90 days")
        age_label.pack(anchor="w", padx=15, pady=(0, 15))
        
        def update_age_label(value):
            days = int(float(value))
            if days < 30:
                age_label.configure(text=f"{days} days")
            else:
                months = days // 30
                age_label.configure(text=f"{days} days (~{months} months)")
        age_slider.configure(command=update_age_label)
        
        def cleanup_backups():
            try:
                deleted, errors = self.backup_manager.cleanup_old_backups(
                    max_automatic=auto_var.get(),
                    max_manual=manual_var.get(),
                    max_age_days=age_var.get()
                )
                
                if deleted > 0 or errors == 0:
                    messagebox.showinfo("Cleanup Complete", 
                                       f"Cleanup completed!\n\n"
                                       f"✅ Deleted: {deleted} backups\n"
                                       f"❌ Errors: {errors}")
                else:
                    messagebox.showerror("Cleanup Failed", 
                                        f"Cleanup failed with {errors} errors")
                
                dialog.destroy()
                self.refresh_backup_list()
                self.update_statistics()
                
            except Exception as e:
                messagebox.showerror("Error", f"Cleanup failed: {str(e)}")
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel",
                                   command=dialog.destroy, width=120, height=45)
        cancel_btn.pack(side="left", padx=15)
        
        cleanup_btn = ctk.CTkButton(button_frame, text="🧹 Start Cleanup",
                                    command=cleanup_backups, width=150, height=45,
                                    font=ctk.CTkFont(size=16, weight="bold"),
                                    fg_color="#FF8C00", hover_color="#FF7F50")
        cleanup_btn.pack(side="right", padx=15)
    
    def toggle_automatic_backups(self):
        """Toggle automatic backup system"""
        
        if self.auto_backup_enabled.get():
            # Start automatic backups
            password = self.get_master_password_for_operation("Enable Automatic Backups")
            if not password:
                self.auto_backup_enabled.set(False)
                return
            
            try:
                if not self.backup_scheduler:
                    self.backup_scheduler = BackupScheduler(self.backup_manager, self.parent_gui.database)
                
                self.backup_scheduler.start_automatic_backups(password, self.interval_var.get())
                
                self.auto_status_label.configure(
                    text=f"✅ Automatic backups: Enabled (every {self.interval_var.get()} hours)",
                    text_color="#00AA00"
                )
                
                messagebox.showinfo("Automatic Backups", "Automatic backups have been enabled!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start automatic backups: {str(e)}")
                self.auto_backup_enabled.set(False)
        else:
            # Stop automatic backups
            if self.backup_scheduler:
                self.backup_scheduler.stop_automatic_backups()
            
            self.auto_status_label.configure(
                text="❌ Automatic backups: Disabled",
                text_color="#888888"
            )
            
            messagebox.showinfo("Automatic Backups", "Automatic backups have been disabled.")
    
    def update_statistics(self):
        """Update backup statistics display"""
        
        try:
            # Clear existing stats
            for widget in self.stats_container.winfo_children():
                widget.destroy()
            
            # Get backup statistics
            backups = self.backup_manager.list_available_backups()
            
            total_backups = len(backups)
            automatic_backups = len([b for b in backups if b['type'] == 'automatic'])
            manual_backups = len([b for b in backups if b['type'] == 'manual'])
            total_size = sum(b['size'] for b in backups)
            
            # Recent backup
            latest_backup = backups[0] if backups else None
            
            # Create statistics display
            stats_grid = ctk.CTkFrame(self.stats_container, fg_color="transparent")
            stats_grid.pack(fill="x", padx=10)
            
            # Stats items
            stats = [
                ("📊 Total Backups", str(total_backups)),
                ("🤖 Automatic", str(automatic_backups)),
                ("👤 Manual", str(manual_backups)),
                ("💾 Total Size", self.format_file_size(total_size)),
                ("📅 Latest Backup", latest_backup['modified'].strftime('%Y-%m-%d %H:%M') if latest_backup else "None"),
                ("📂 Backup Folder", str(self.backup_manager.backup_folder))
            ]
            
            # Display stats in a grid
            for i, (label, value) in enumerate(stats):
                row = i // 2
                col = i % 2
                
                stat_frame = ctk.CTkFrame(stats_grid)
                stat_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")
                
                ctk.CTkLabel(stat_frame, text=label, 
                             font=ctk.CTkFont(size=12, weight="bold")).pack(pady=(10, 5))
                ctk.CTkLabel(stat_frame, text=value, 
                             font=ctk.CTkFont(size=14),
                             text_color="#00AA88").pack(pady=(0, 10))
            
            # Configure grid weights
            stats_grid.grid_columnconfigure(0, weight=1)
            stats_grid.grid_columnconfigure(1, weight=1)
            
        except Exception as e:
            error_label = ctk.CTkLabel(self.stats_container, 
                                       text=f"Error loading statistics: {str(e)}",
                                       text_color="#FF4444")
            error_label.pack(pady=20)
    
    def open_backup_folder(self):
        """Open the backup folder in the system file manager"""
        
        try:
            import subprocess
            import sys
            
            backup_folder = str(self.backup_manager.backup_folder)
            
            if sys.platform == "win32":
                subprocess.run(["explorer", backup_folder])
            elif sys.platform == "darwin":  # macOS
                subprocess.run(["open", backup_folder])
            else:  # Linux and other Unix-like
                subprocess.run(["xdg-open", backup_folder])
            
            print(f"📁 FOLDER: Opened backup folder: {backup_folder}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not open backup folder: {str(e)}")
            # Fallback - show the path
            messagebox.showinfo("Backup Folder Location", 
                               f"Backup folder location:\n\n{self.backup_manager.backup_folder}")
    
    def get_master_password_for_operation(self, operation_name):
        """Get master password for backup operations"""
        
        dialog = ctk.CTkToplevel(self.parent_gui.root)
        dialog.title(f"🔐 Authentication Required")
        dialog.geometry("400x300")
        dialog.grab_set()
        dialog.resizable(False, False)
        
        result = {"password": None}
        
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(main_frame, text=f"🔐 {operation_name}",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        ctk.CTkLabel(main_frame, text="Please enter your master password:",
                     font=ctk.CTkFont(size=14)).pack(pady=(0, 15))
        
        password_entry = ctk.CTkEntry(main_frame, width=300, height=40,
                                      placeholder_text="Master Password", show="*")
        password_entry.pack(pady=10)
        password_entry.focus()
        
        def on_ok():
            result["password"] = password_entry.get().strip()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        password_entry.bind('<Return>', lambda e: on_ok())
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", 
                                   command=on_cancel, width=100, height=40)
        cancel_btn.pack(side="left", padx=15)
        
        ok_btn = ctk.CTkButton(button_frame, text="OK", 
                               command=on_ok, width=100, height=40,
                               font=ctk.CTkFont(size=14, weight="bold"))
        ok_btn.pack(side="right", padx=15)
        
        dialog.wait_window()
        return result["password"]

# Integration with main GUI - Add this to your main password manager class

def integrate_backup_system(password_manager_gui):
    """
    Integration function to add the enhanced backup system to the main GUI
    
    Add this to your ModernPasswordManagerGUI class:
    """
    
    # Initialize backup GUI
    backup_gui = BackupGUI(password_manager_gui)
    
    # Replace the existing show_backup_restore method
    password_manager_gui.show_backup_restore = backup_gui.show_backup_restore_enhanced
    
    # Add backup GUI reference
    password_manager_gui.backup_gui = backup_gui
    
    print("✅ INTEGRATION: Enhanced backup system integrated successfully")

# Example usage and setup instructions:
"""
To integrate this enhanced backup system into your existing password manager:

1. Add the SecureBackupManager and BackupGUI classes to your main file
2. In your ModernPasswordManagerGUI.__init__ method, add:
   
   # Initialize enhanced backup system
   self.backup_gui = BackupGUI(self)
   
3. Replace the existing show_backup_restore method:
   
   def show_backup_restore(self):
       self.backup_gui.show_backup_restore_enhanced()

4. The system will automatically:
   - Create a backup folder with proper structure
   - Create desktop shortcuts to the backup folder
   - Enable encrypted backups with master password verification
   - Provide comprehensive backup management interface
   - Support automatic scheduled backups
   - Include backup verification and restoration features

Features included:
✅ Secure AES-256-GCM encryption for all backups
✅ Master password verification before operations
✅ Desktop folder shortcuts with icons
✅ Comprehensive backup metadata and verification
✅ Automatic cleanup of old backups
✅ Scheduled automatic backups
✅ Backup integrity verification
✅ User-friendly GUI with progress indicators
✅ Support for both manual and automatic backups
✅ Secure deletion of backup files
✅ Cross-platform compatibility (Windows, macOS, Linux)
"""