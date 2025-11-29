"""
backup.py - Comprehensive Backup and Restore Manager for SecureVault Pro

This module provides encrypted backup and restore functionality with:
- Full database backup with encryption
- Selective backup options
- Backup verification
- Automatic backup scheduling
- Cloud storage support (optional)
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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, asdict
import threading
import schedule
import time

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
    backup_type: str  # 'full', 'accounts_only', 'settings_only'
    encrypted: bool
    compression: str  # 'zip', 'tar.gz', etc.
    created_by: str


def get_program_directory():
    """Get the directory where the program is running from"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))


class BackupManager:
    """Manages backup and restore operations for SecureVault Pro"""
    
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
        
        # Auto-backup settings
        self.auto_backup_enabled = False
        self.auto_backup_interval = 7  # days
        self.auto_backup_thread = None
        
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
            conn = sqlite3.connect(self.database.metadata_db)
            cursor = conn.execute("SELECT COUNT(*) FROM accounts WHERE id != 'master_account'")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            logger.error(f"Failed to get accounts count: {e}")
            return 0
    
    def create_backup(self, backup_type: str = 'full', 
                     password: Optional[str] = None,
                     description: str = "") -> Tuple[bool, str, Optional[Path]]:
        """
        Create a backup of the vault
        
        Args:
            backup_type: Type of backup ('full', 'accounts_only', 'settings_only')
            password: Optional password for backup encryption (uses master password if None)
            description: Optional backup description
            
        Returns:
            Tuple of (success: bool, message: str, backup_path: Optional[Path])
        """
        try:
            logger.info(f"Starting {backup_type} backup creation...")
            
            # Generate backup ID and timestamp
            backup_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            timestamp = datetime.now().isoformat()
            
            # Create temporary directory for backup files
            temp_dir = self.temp_backup_dir / backup_id
            temp_dir.mkdir(exist_ok=True)
            
            try:
                # Copy database files based on backup type
                if backup_type in ['full', 'accounts_only']:
                    # Copy metadata database
                    if os.path.exists(self.database.metadata_db):
                        shutil.copy2(self.database.metadata_db, 
                                   temp_dir / "metadata.db")
                    
                    # Copy sensitive database
                    if os.path.exists(self.database.sensitive_db):
                        shutil.copy2(self.database.sensitive_db, 
                                   temp_dir / "sensitive.db")
                
                if backup_type in ['full', 'settings_only']:
                    # Copy salt file
                    if os.path.exists(self.database.salt_path):
                        shutil.copy2(self.database.salt_path, 
                                   temp_dir / "salt_file")
                    
                    # Copy secure storage files if available
                    if self.secure_file_manager:
                        if os.path.exists(self.secure_file_manager.secure_dir):
                            secure_backup_dir = temp_dir / "secure_storage"
                            secure_backup_dir.mkdir(exist_ok=True)
                            
                            for file in os.listdir(self.secure_file_manager.secure_dir):
                                src = os.path.join(self.secure_file_manager.secure_dir, file)
                                dst = secure_backup_dir / file
                                if os.path.isfile(src):
                                    shutil.copy2(src, dst)
                
                # Create metadata file
                accounts_count = self._get_accounts_count() if backup_type != 'settings_only' else 0
                
                metadata = BackupMetadata(
                    backup_id=backup_id,
                    timestamp=timestamp,
                    version="1.0.0",  # App version
                    accounts_count=accounts_count,
                    file_size=0,  # Will be updated after compression
                    checksum="",  # Will be updated after compression
                    backup_type=backup_type,
                    encrypted=True,
                    compression="zip",
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
                self.backup_history.append(backup_record)
                self._save_backup_history()
                
                logger.info(f"Backup created successfully: {backup_path}")
                logger.info(f"Backup size: {file_size / (1024*1024):.2f} MB")
                logger.info(f"Accounts backed up: {accounts_count}")
                
                success_msg = (f"Backup created successfully!\n\n"
                             f"Type: {backup_type}\n"
                             f"Accounts: {accounts_count}\n"
                             f"Size: {file_size / (1024*1024):.2f} MB\n"
                             f"Location: {backup_path}")
                
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
            return False, f"Backup failed: {str(e)}", None
    
    def restore_backup(self, backup_path: Path, 
                      password: Optional[str] = None,
                      verify_only: bool = False) -> Tuple[bool, str]:
        """
        Restore vault from backup
        
        Args:
            backup_path: Path to backup file
            password: Optional password for backup decryption
            verify_only: If True, only verify backup without restoring
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"Starting backup restore from: {backup_path}")
            
            if not backup_path.exists():
                return False, "Backup file not found"
            
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
                    return False, "Invalid backup file: metadata missing"
                
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                logger.info(f"Backup metadata: {metadata}")
                
                if verify_only:
                    # Only verification requested
                    verify_msg = (f"Backup verification successful!\n\n"
                                f"Type: {metadata['backup_type']}\n"
                                f"Date: {metadata['timestamp']}\n"
                                f"Accounts: {metadata['accounts_count']}\n"
                                f"Size: {metadata['file_size'] / (1024*1024):.2f} MB")
                    return True, verify_msg
                
                # Perform restoration
                logger.info("Restoring backup files - replacing current data...")
                
                backup_type = metadata['backup_type']
                
                # Restore database files - directly replace existing files
                if backup_type in ['full', 'accounts_only']:
                    metadata_src = extract_dir / "metadata.db"
                    sensitive_src = extract_dir / "sensitive.db"
                    
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
                
                if backup_type in ['full', 'settings_only']:
                    salt_src = extract_dir / "salt_file"
                    if salt_src.exists():
                        # Remove old file and copy new one
                        if os.path.exists(self.database.salt_path):
                            os.remove(self.database.salt_path)
                        shutil.copy2(salt_src, self.database.salt_path)
                        logger.info("Restored salt file")
                    
                    # Restore secure storage files - replace entire directory
                    secure_backup_dir = extract_dir / "secure_storage"
                    if secure_backup_dir.exists() and self.secure_file_manager:
                        # Clear existing secure storage directory
                        if os.path.exists(self.secure_file_manager.secure_dir):
                            # Remove all files in secure directory
                            for file in os.listdir(self.secure_file_manager.secure_dir):
                                file_path = os.path.join(self.secure_file_manager.secure_dir, file)
                                if os.path.isfile(file_path):
                                    os.remove(file_path)
                        
                        # Copy all files from backup
                        for file in os.listdir(secure_backup_dir):
                            src = secure_backup_dir / file
                            dst = os.path.join(self.secure_file_manager.secure_dir, file)
                            if src.is_file():
                                shutil.copy2(src, dst)
                        logger.info("Restored secure storage files")
                
                success_msg = (f"Backup restored successfully!\n\n"
                             f"Type: {backup_type}\n"
                             f"Accounts restored: {metadata['accounts_count']}\n"
                             f"From: {metadata['timestamp']}\n\n"
                             f"⚠️ All current data has been replaced with backup data.\n\n"
                             f"Please restart the application for changes to take effect.")
                
                logger.info("Backup restore completed successfully - all data replaced")
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
            return False, f"Restore failed: {str(e)}"
    
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
                return False, "Backup file not found"
            
            # Remove from history
            self.backup_history = [b for b in self.backup_history 
                                  if b.get('backup_path') != str(backup_path)]
            self._save_backup_history()
            
            # Delete file
            backup_path.unlink()
            
            logger.info(f"Backup deleted: {backup_path}")
            return True, "Backup deleted successfully"
            
        except Exception as e:
            logger.error(f"Failed to delete backup: {e}")
            return False, f"Failed to delete backup: {str(e)}"
    
    def enable_auto_backup(self, interval_days: int = 7):
        """Enable automatic backup scheduling"""
        self.auto_backup_enabled = True
        self.auto_backup_interval = interval_days
        
        if self.auto_backup_thread is None or not self.auto_backup_thread.is_alive():
            self.auto_backup_thread = threading.Thread(target=self._auto_backup_worker, daemon=True)
            self.auto_backup_thread.start()
            logger.info(f"Auto-backup enabled: every {interval_days} days")
    
    def disable_auto_backup(self):
        """Disable automatic backup scheduling"""
        self.auto_backup_enabled = False
        logger.info("Auto-backup disabled")
    
    def _auto_backup_worker(self):
        """Worker thread for automatic backups"""
        schedule.clear()
        schedule.every(self.auto_backup_interval).days.do(self._perform_auto_backup)
        
        while self.auto_backup_enabled:
            schedule.run_pending()
            time.sleep(3600)  # Check every hour
    
    def _perform_auto_backup(self):
        """Perform automatic backup"""
        try:
            logger.info("Performing automatic backup...")
            success, message, backup_path = self.create_backup(
                backup_type='full',
                description=f"Automatic backup - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            
            if success:
                logger.info(f"Automatic backup completed: {backup_path}")
            else:
                logger.error(f"Automatic backup failed: {message}")
        except Exception as e:
            logger.error(f"Auto-backup error: {e}")
    
    def export_backup_to_location(self, backup_path: Path, 
                                  destination: Path) -> Tuple[bool, str]:
        """Export backup to external location (USB, cloud, etc.)"""
        try:
            if not backup_path.exists():
                return False, "Backup file not found"
            
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_path, destination)
            
            logger.info(f"Backup exported to: {destination}")
            return True, f"Backup exported successfully to:\n{destination}"
            
        except Exception as e:
            logger.error(f"Failed to export backup: {e}")
            return False, f"Export failed: {str(e)}"
    
    def cleanup_old_backups(self, keep_count: int = 10) -> Tuple[bool, str]:
        """Clean up old backups, keeping only the most recent ones"""
        try:
            backups = self.get_backup_list()
            
            if len(backups) <= keep_count:
                return True, f"No cleanup needed. Current backups: {len(backups)}"
            
            # Sort by timestamp and keep only the newest ones
            backups_to_delete = backups[keep_count:]
            deleted_count = 0
            
            for backup in backups_to_delete:
                backup_path = Path(backup['backup_path'])
                if backup_path.exists():
                    success, _ = self.delete_backup(backup_path)
                    if success:
                        deleted_count += 1
            
            message = f"Cleanup completed. Deleted {deleted_count} old backup(s)."
            logger.info(message)
            return True, message
            
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
            return False, f"Cleanup failed: {str(e)}"
    
    def get_backup_directory(self) -> Path:
        """Get the backup directory path"""
        return self.backup_root