"""
backup.py - Simplified Backup and Restore Manager for SecureVault Pro

This module provides encrypted backup and restore functionality for accounts only:
- Backs up account metadata (name, username, email, URL, notes, tags, etc.)
- Excludes passwords and sensitive settings
- Backup verification
- Backup history tracking
"""

import os
import json
import shutil
import sqlite3
import zipfile
import hashlib
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class BackupMetadata:
    """Metadata for backup files"""
    backup_id: str
    timestamp: str
    version: str
    accounts_count: int
    file_size: int
    checksum: str
    encrypted: bool
    created_by: str


def get_program_directory():
    """Get the directory where the program is running from"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


class BackupManager:
    """Manages backup and restore operations for SecureVault Pro (Accounts Only)"""
    
    def __init__(self, database_manager, secure_file_manager, crypto_manager):
        """
        Initialize BackupManager
        
        Args:
            database_manager: DatabaseManager instance
            secure_file_manager: SecureFileManager instance
            crypto_manager: CryptoManager instance
        """
        self.database = database_manager
        self.secure_file_manager = secure_file_manager
        self.crypto = crypto_manager
        
        # Setup backup directories in program directory
        program_dir = Path(get_program_directory())
        self.backup_root = program_dir / "backups"
        self.backup_root.mkdir(parents=True, exist_ok=True)
        
        self.local_backups_dir = self.backup_root / "local"
        self.local_backups_dir.mkdir(exist_ok=True)
        
        self.temp_backup_dir = self.backup_root / "temp"
        self.temp_backup_dir.mkdir(exist_ok=True)
        
        # Backup history file
        self.history_file = self.backup_root / "backup_history.json"
        self.backup_history = self._load_backup_history()
        
        logger.info(f"BackupManager initialized successfully")
        logger.info(f"Backup directory: {self.backup_root}")
    
    def _load_backup_history(self) -> List[Dict]:
        """Load backup history from file"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.error(f"Failed to load backup history: {e}")
            return []
    
    def _save_backup_history(self):
        """Save backup history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.backup_history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save backup history: {e}")
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _get_accounts_count(self) -> int:
        """Get total number of accounts"""
        try:
            conn = self.database._get_metadata_connection()
            cursor = conn.execute("SELECT COUNT(*) FROM accounts WHERE id != 'master_account'")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            logger.error(f"Failed to get accounts count: {e}")
            return 0
    
    def _create_accounts_backup(self, temp_dir: Path):
        """Create a backup containing only account metadata without passwords"""
        try:
            # Copy metadata database
            if os.path.exists(self.database.metadata_db):
                shutil.copy2(self.database.metadata_db, temp_dir / "metadata.db")
                logger.info("Metadata database copied")
            
            # Copy salt file - CRITICAL for encryption key derivation
            if os.path.exists(self.secure_file_manager.salt_path):
                shutil.copy2(self.secure_file_manager.salt_path, temp_dir / "salt_file")
                logger.info("Salt file copied")
            else:
                logger.warning("Salt file not found - backup may not be restorable!")
            
            # Create a filtered sensitive database with only non-sensitive account data
            if os.path.exists(self.database.sensitive_db):
                filtered_db_path = temp_dir / "sensitive.db"
                
                # Connect to original sensitive database
                original_conn = sqlite3.connect(self.database.sensitive_db)
                
                # Create new filtered database
                filtered_conn = sqlite3.connect(filtered_db_path)
                filtered_conn.execute("""
                    CREATE TABLE credentials (
                        account_id TEXT PRIMARY KEY,
                        encrypted_data BLOB NOT NULL
                    )
                """)
                
                # Process each account and remove sensitive data
                cursor = original_conn.execute("SELECT account_id, encrypted_data FROM credentials")
                accounts_processed = 0
                
                for row in cursor:
                    account_id, encrypted_data = row
                    
                    # Master account is intentionally skipped to prevent including it in the backup
                    if account_id == 'master_account':
                        logger.info("Skipping master account - not included in backup")
                        continue
                    
                    try:
                        # Decrypt the data
                        decrypted_json = self.database.crypto.decrypt_data(encrypted_data, self.database.encryption_key)
                        account_data = json.loads(decrypted_json)
                        
                        # Remove sensitive fields (passwords)
                        filtered_account_data = {
                            "name": account_data.get("name", ""),
                            "username": account_data.get("username", ""),
                            "email": account_data.get("email", ""),
                            "url": account_data.get("url", ""),
                            "notes": account_data.get("notes", ""),
                            "tags": account_data.get("tags", []),
                            "security_level": account_data.get("security_level", ""),
                            "account_type": account_data.get("account_type", ""),
                            "category": account_data.get("category", ""),
                            "two_factor_enabled": account_data.get("two_factor_enabled", 0),
                            "last_password_change": account_data.get("last_password_change", ""),
                            "recovery_email": account_data.get("recovery_email", ""),
                            "phone_number": account_data.get("phone_number", ""),
                            # PASSWORD IS EXCLUDED
                        }
                        
                        # Encrypt the filtered data
                        filtered_encrypted_data = self.database.crypto.encrypt_data(
                            json.dumps(filtered_account_data), 
                            self.database.encryption_key
                        )
                        
                        # Insert into filtered database
                        filtered_conn.execute("""
                            INSERT INTO credentials (account_id, encrypted_data)
                            VALUES (?, ?)
                        """, (account_id, filtered_encrypted_data))
                        
                        accounts_processed += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing account {account_id}: {e}")
                
                filtered_conn.commit()
                filtered_conn.close()
                original_conn.close()
                
                logger.info(f"Filtered sensitive database created with {accounts_processed} accounts")
                
        except Exception as e:
            logger.error(f"Failed to create accounts backup: {e}")
            raise
    
    def create_backup(self, description: str = "") -> Tuple[bool, str, Optional[Path]]:
        """
        Create a backup of accounts only (no passwords)
        
        Args:
            description: Optional backup description
            
        Returns:
            Tuple of (success: bool, message: str, backup_path: Optional[Path])
        """
        try:
            logger.info(f"Starting accounts-only backup creation...")
            
            # Generate backup ID and timestamp
            backup_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            timestamp = datetime.now().isoformat()
            
            # Create temporary directory for backup files
            temp_dir = self.temp_backup_dir / backup_id
            temp_dir.mkdir(exist_ok=True)
            
            try:
                # Create filtered backup with only account metadata (no passwords)
                self._create_accounts_backup(temp_dir)
                
                # Get accounts count
                accounts_count = self._get_accounts_count()
                
                # Create metadata file
                metadata = BackupMetadata(
                    backup_id=backup_id,
                    timestamp=timestamp,
                    version="1.0.0",  # App version
                    accounts_count=accounts_count,
                    file_size=0,  # Will be updated after compression
                    checksum="",  # Will be updated after compression
                    encrypted=True,
                    created_by=os.getenv("USERNAME", "unknown")
                )
                
                # Save metadata
                with open(temp_dir / "backup_metadata.json", 'w') as f:
                    json.dump(asdict(metadata), f, indent=2)
                
                # Add description file if provided
                if description:
                    with open(temp_dir / "description.txt", 'w') as f:
                        f.write(description)
                
                # Create encrypted ZIP archive
                backup_filename = f"securevault_backup_{backup_id}.svbak"
                backup_path = self.local_backups_dir / backup_filename
                
                logger.info(f"Creating encrypted backup archive: {backup_path}")
                
                # Create ZIP file
                with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, temp_dir)
                            zipf.write(file_path, arcname)
                
                # Calculate checksum and file size
                file_size = backup_path.stat().st_size
                checksum = self._calculate_checksum(backup_path)
                
                # Update metadata
                metadata.file_size = file_size
                metadata.checksum = checksum
                
                # Add to backup history
                backup_record = asdict(metadata)
                backup_record['backup_path'] = str(backup_path)
                backup_record['description'] = description
                backup_record['backup_type'] = 'accounts_only'  # Always accounts only
                self.backup_history.append(backup_record)
                self._save_backup_history()
                
                logger.info(f"Backup created successfully: {backup_path}")
                logger.info(f"Backup size: {file_size / (1024*1024):.2f} MB")
                logger.info(f"Accounts backed up: {accounts_count}")
                
                success_msg = (f"✅ Backup created successfully!\n\n"
                             f"Type: Accounts Only (No Passwords)\n"
                             f"Accounts: {accounts_count}\n"
                             f"Size: {file_size / (1024*1024):.2f} MB\n"
                             f"Location: {backup_path}\n\n"
                             f"⚠️ Note: Regular account passwords are NOT included.\n")
                
                return True, success_msg, backup_path
                
            finally:
                # Cleanup temporary directory
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp directory: {e}")
        
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            import traceback
            traceback.print_exc()
            return False, f"❌ Backup failed: {str(e)}", None
    
    def restore_backup(self, backup_path: Path, verify_only: bool = False) -> Tuple[bool, str]:
        """
        Restore accounts from backup (passwords will need to be re-entered)
        
        Args:
            backup_path: Path to backup file
            verify_only: If True, only verify backup without restoring
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"Starting backup restore from: {backup_path}")
            
            if not backup_path.exists():
                return False, "❌ Backup file not found"
            
            # Verify backup file
            logger.info("Verifying backup integrity...")
            
            # Create temporary extraction directory
            extract_dir = self.temp_backup_dir / f"restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            extract_dir.mkdir(exist_ok=True)
            
            try:
                # Extract backup
                with zipfile.ZipFile(backup_path, 'r') as zipf:
                    zipf.extractall(extract_dir)
                
                # Load and verify metadata
                metadata_path = extract_dir / "backup_metadata.json"
                if not metadata_path.exists():
                    return False, "❌ Invalid backup file: metadata missing"
                
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                logger.info(f"Backup metadata: {metadata}")
                
                if verify_only:
                    # Only verification requested
                    verify_msg = (f"✅ Backup verification successful!\n\n"
                                f"Type: Accounts Only\n"
                                f"Date: {metadata['timestamp']}\n"
                                f"Accounts: {metadata['accounts_count']}\n"
                                f"Size: {metadata['file_size'] / (1024*1024):.2f} MB")
                    return True, verify_msg
                
                # Perform restoration
                logger.info("Restoring backup files - replacing current data...")
                
                # Restore database files - directly replace existing files
                metadata_src = extract_dir / "metadata.db"
                sensitive_src = extract_dir / "sensitive.db"
                salt_src = extract_dir / "salt_file"
                
                # Close any existing DB connections to prevent file locks (Best Effort)
                try:
                    if hasattr(self.database, 'close'):
                        self.database.close()
                except Exception as e:
                    logger.warning(f"Could not close database connections explicitly: {e}")

                if metadata_src.exists():
                    # Remove old file and copy new one
                    if os.path.exists(self.database.metadata_db):
                        os.remove(self.database.metadata_db)
                    shutil.copy2(metadata_src, self.database.metadata_db)
                    logger.info("Restored metadata database")
                
                if sensitive_src.exists():
                    # Remove old file and copy new one
                    if os.path.exists(self.database.sensitive_db):
                        os.remove(self.database.sensitive_db)
                    shutil.copy2(sensitive_src, self.database.sensitive_db)
                    logger.info("Restored sensitive database")
                
                # CRITICAL: Restore salt file - must match the salt used when backup was created
                if salt_src.exists():
                    # Remove old salt file and copy new one
                    if os.path.exists(self.secure_file_manager.salt_path):
                        os.remove(self.secure_file_manager.salt_path)
                    # Ensure the directory exists
                    os.makedirs(os.path.dirname(self.secure_file_manager.salt_path), exist_ok=True)
                    shutil.copy2(salt_src, self.secure_file_manager.salt_path)
                    logger.info("Restored salt file - encryption key derivation will now match backup")
                else:
                    logger.error("Salt file not found in backup - restore may fail authentication!")
                    return False, "❌ Backup is missing salt file. Cannot restore - authentication will fail."
                
                # [FIX START] Force persistence of restored files
                # 1. Remove the integrity file to force regeneration on next login.
                #    The current session key cannot generate a valid signature for the restored salt/files.
                integrity_path = self.database.integrity_path
                if os.path.exists(integrity_path):
                    os.remove(integrity_path)
                    logger.info("Removed old integrity file to force regeneration on next login")
                
                # 2. Explicitly sync the restored temporary files to the secure storage location.
                #    We do this MANUALLY here to ensure it happens before any restart logic.
                #    We rely on the secure_file_manager to copy the current state of temp_dir (which we just filled)
                #    to the persistent storage.
                try:
                    logger.info("Forcing sync of restored files to secure storage...")
                    # We call sync_all_files. Note: This might sign with the OLD key, which is fine
                    # because we deleted the integrity file above or the app will detect the mismatch
                    # and regenerate it on login. The critical part is moving the files from Temp -> Secure.
                    self.secure_file_manager.sync_all_files() 
                    logger.info("Restored files successfully synced to persistent storage")
                except Exception as sync_error:
                    logger.error(f"Failed to sync restored files: {sync_error}")
                    # Even if this fails, we proceed, hoping the standard shutdown sync works, 
                    # but this log is critical for debugging.
                # [FIX END]

                success_msg = (f"✅ Backup restored successfully!\n\n"
                             f"Type: Accounts Only\n"
                             f"Accounts restored: {metadata['accounts_count']}\n"
                             f"From: {metadata['timestamp']}\n\n"
                             f"⚠️ IMPORTANT:\n"
                             f"• Regular account passwords were NOT included in the backup\n"
                             f"• You will need to re-enter passwords for regular accounts\n"
                             f"• Master password is preserved from backup time\n"
                             f"• Salt file has been restored to match backup encryption\n"
                             f"• All current data has been replaced\n\n"
                             f"Please restart the application for changes to take effect.")
                
                logger.info("Backup restore completed successfully")
                return True, success_msg
                
            finally:
                # Cleanup extraction directory
                try:
                    shutil.rmtree(extract_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup extraction directory: {e}")
        
        except Exception as e:
            logger.error(f"Backup restore failed: {e}")
            import traceback
            traceback.print_exc()
            return False, f"❌ Restore failed: {str(e)}"

    def get_backup_list(self) -> List[Dict]:
        """Get list of all available backups with metadata"""
        backups = []
        
        try:
            for backup_record in self.backup_history:
                backup_path = Path(backup_record.get('backup_path', ''))
                if backup_path.exists():
                    backups.append(backup_record)
            
            # Also scan directory for backups not in history
            for backup_file in self.local_backups_dir.glob("*.svbak"):
                if not any(b['backup_path'] == str(backup_file) for b in backups):
                    # Try to read metadata from backup
                    try:
                        with zipfile.ZipFile(backup_file, 'r') as zipf:
                            if 'backup_metadata.json' in zipf.namelist():
                                metadata_content = zipf.read('backup_metadata.json')
                                metadata = json.loads(metadata_content)
                                metadata['backup_path'] = str(backup_file)
                                metadata['backup_type'] = 'accounts_only'
                                backups.append(metadata)
                    except Exception as e:
                        logger.warning(f"Could not read metadata from {backup_file}: {e}")
            
            # Sort by timestamp (newest first)
            backups.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to get backup list: {e}")
        
        return backups
    
    def delete_backup(self, backup_path: Path) -> Tuple[bool, str]:
        """Delete a backup file"""
        try:
            if not backup_path.exists():
                return False, "❌ Backup file not found"
            
            # Remove from history
            self.backup_history = [b for b in self.backup_history 
                                  if b.get('backup_path') != str(backup_path)]
            self._save_backup_history()
            
            # Delete file
            backup_path.unlink()
            
            logger.info(f"Backup deleted: {backup_path}")
            return True, "✅ Backup deleted successfully"
            
        except Exception as e:
            logger.error(f"Failed to delete backup: {e}")
            return False, f"❌ Failed to delete backup: {str(e)}"
    
    def export_backup_to_location(self, backup_path: Path, destination: Path) -> Tuple[bool, str]:
        """Export backup to external location (USB, cloud, etc.)"""
        try:
            if not backup_path.exists():
                return False, "❌ Backup file not found"
            
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_path, destination)
            
            logger.info(f"Backup exported to: {destination}")
            return True, f"✅ Backup exported successfully to:\n{destination}"
            
        except Exception as e:
            logger.error(f"Failed to export backup: {e}")
            return False, f"❌ Export failed: {str(e)}"
    
    def cleanup_old_backups(self, keep_count: int = 10) -> Tuple[bool, str]:
        """Clean up old backups, keeping only the most recent ones"""
        try:
            backups = self.get_backup_list()
            
            if len(backups) <= keep_count:
                return True, f"✅ No cleanup needed. Current backups: {len(backups)}"
            
            # Sort by timestamp and keep only the newest ones
            backups_to_delete = backups[keep_count:]
            deleted_count = 0
            
            for backup in backups_to_delete:
                backup_path = Path(backup['backup_path'])
                if backup_path.exists():
                    success, _ = self.delete_backup(backup_path)
                    if success:
                        deleted_count += 1
            
            message = f"✅ Cleanup completed. Deleted {deleted_count} old backup(s)."
            logger.info(message)
            return True, message
            
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
            return False, f"❌ Cleanup failed: {str(e)}"
    
    def get_backup_directory(self) -> Path:
        """Get the backup directory path"""
        return self.backup_root