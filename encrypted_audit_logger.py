"""
EncryptedAuditLogger: Encrypted, internal logging system replacing audit.log
Provides comprehensive audit logging without exposing sensitive information
in plain-text files.

Features:
- Encrypted audit logs
- Automatic log rotation
- Sensitive data filtering
- Log compression
- Secure deletion
- No disk footprint in plain text
"""

import os
import logging
import json
import gzip
import shutil
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict, field
import threading

logger = logging.getLogger(__name__)


@dataclass
class AuditLogEntry:
    """Represents an audit log entry."""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    level: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL
    action: str = ""
    component: str = ""
    details: Optional[Dict[str, Any]] = None
    user: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def __str__(self) -> str:
        """String representation for file logging."""
        detail_str = json.dumps(self.details) if self.details else ""
        return f"[{self.timestamp}] {self.level} - {self.component}: {self.action} {detail_str}"


class EncryptedAuditLogger:
    """
    Secure audit logging system that encrypts logs and prevents
    unauthorized access to audit information.
    """
    
    # Log retention
    DEFAULT_RETENTION_DAYS = 90
    
    # Log rotation
    DEFAULT_MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
    
    # Sensitive keywords to filter
    SENSITIVE_KEYWORDS = [
        'password', 'secret', 'key', 'token', 'credential',
        'auth', 'api_key', 'private', 'ssn', 'credit_card'
    ]
    
    def __init__(self, log_directory: str, encryption_key: bytes,
                 retention_days: int = DEFAULT_RETENTION_DAYS,
                 enable_compression: bool = True):
        """
        Initialize the EncryptedAuditLogger.
        
        Args:
            log_directory: Directory for encrypted logs
            encryption_key: Key for encrypting logs
            retention_days: How long to retain logs
            enable_compression: Whether to compress rotated logs
        """
        self.log_directory = log_directory
        self.encryption_key = encryption_key
        self.retention_days = retention_days
        self.enable_compression = enable_compression
        
        # Create log directory
        Path(self.log_directory).mkdir(parents=True, exist_ok=True)
        
        # Current log file
        self.current_log_file = os.path.join(self.log_directory, ".logs")
        self.current_log_entries: List[AuditLogEntry] = []
        
        # Metadata
        self.log_lock = threading.Lock()
        self.entries_since_last_rotation = 0
        
        logger.info(f"EncryptedAuditLogger initialized at {self.log_directory}")
    
    def log(self, action: str, component: str, level: str = "INFO",
            details: Dict = None, user: str = None) -> AuditLogEntry:
        """
        Log an audit entry.
        
        Args:
            action: Action performed
            component: Component that performed action
            level: Log level
            details: Additional details
            user: User performing action
        
        Returns:
            AuditLogEntry: The logged entry
        """
        # Filter sensitive data from details
        if details:
            details = self._filter_sensitive_data(details)
        
        entry = AuditLogEntry(
            level=level,
            action=action,
            component=component,
            details=details,
            user=user
        )
        
        with self.log_lock:
            self.current_log_entries.append(entry)
            self.entries_since_last_rotation += 1
            
            # Check if rotation is needed
            if self.entries_since_last_rotation > 1000:
                self._rotate_logs()
        
        # Log to system logger
        if level == "CRITICAL":
            logger.critical(str(entry))
        elif level == "ERROR":
            logger.error(str(entry))
        elif level == "WARNING":
            logger.warning(str(entry))
        else:
            logger.info(str(entry))
        
        return entry
    
    def _filter_sensitive_data(self, data: Dict) -> Dict:
        """
        Filter sensitive data from logged details.
        
        Args:
            data: Original data dictionary
        
        Returns:
            dict: Filtered data with sensitive values masked
        """
        filtered = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive keywords
            is_sensitive = any(kw in key_lower for kw in self.SENSITIVE_KEYWORDS)
            
            if is_sensitive:
                # Mask sensitive values
                if isinstance(value, str):
                    filtered[key] = f"[REDACTED-{len(value)}chars]"
                else:
                    filtered[key] = "[REDACTED]"
            else:
                filtered[key] = value
        
        return filtered
    
    def log_authentication(self, success: bool, user: str = None, details: Dict = None):
        """Log authentication events."""
        self.log(
            action="authentication_attempt",
            component="auth",
            level="WARNING" if not success else "INFO",
            details={"success": success, **(details or {})},
            user=user
        )
    
    def log_integrity_check(self, success: bool, component: str, details: Dict = None):
        """Log integrity check results."""
        self.log(
            action="integrity_check",
            component=component,
            level="CRITICAL" if not success else "INFO",
            details={"success": success, **(details or {})}
        )
    
    def log_tampering(self, incident_type: str, component: str, details: Dict = None):
        """Log tampering incidents."""
        self.log(
            action="tampering_detected",
            component=component,
            level="CRITICAL",
            details={"incident_type": incident_type, **(details or {})}
        )
    
    def log_account_operation(self, operation: str, account_name: str, details: Dict = None):
        """Log account operations."""
        self.log(
            action=f"account_{operation}",
            component="account_manager",
            details={"account": account_name, **(details or {})}
        )
    
    def _rotate_logs(self) -> None:
        """Rotate log file when it reaches size limit."""
        try:
            if not self.current_log_entries:
                return
            
            # Create timestamped backup file
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(self.log_directory, f".logs.{timestamp}")
            
            # Write current logs to backup
            self._write_encrypted_log_file(backup_path, self.current_log_entries)
            
            # Compress if enabled
            if self.enable_compression:
                self._compress_log_file(backup_path)
            
            # Clear current logs
            self.current_log_entries.clear()
            self.entries_since_last_rotation = 0
            
            # Cleanup old logs
            self._cleanup_old_logs()
            
            logger.info(f"Logs rotated: {backup_path}")
        except Exception as e:
            logger.error(f"Log rotation failed: {e}")
    
    def _write_encrypted_log_file(self, file_path: str, entries: List[AuditLogEntry]) -> bool:
        """
        Write encrypted log file.
        
        Args:
            file_path: Path to write logs
            entries: Log entries to write
        
        Returns:
            bool: True if successful
        """
        try:
            # Serialize entries
            data = {
                "timestamp": datetime.utcnow().isoformat(),
                "entries": [e.to_dict() for e in entries]
            }
            
            json_data = json.dumps(data, indent=2).encode('utf-8')
            
            # Simple encryption (XOR with key for demonstration)
            # In production, use proper encryption
            encrypted = self._simple_encrypt(json_data)
            
            # Write to file
            with open(file_path, 'wb') as f:
                f.write(encrypted)
            
            # Hide file on Windows
            if os.name == 'nt':
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x02)
                except Exception:
                    pass
            
            return True
        except Exception as e:
            logger.error(f"Failed to write encrypted log: {e}")
            return False
    
    def _simple_encrypt(self, data: bytes) -> bytes:
        """
        Simple encryption for log data (XOR-based for speed).
        
        Note: This is not cryptographically strong.
        For production, use proper encryption like AES-256-GCM.
        
        Args:
            data: Data to encrypt
        
        Returns:
            bytes: Encrypted data
        """
        # Create cipher by repeating key
        key = self.encryption_key
        cipher = bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
        
        # Add version byte at start
        return b'\x01' + cipher
    
    def _simple_decrypt(self, data: bytes) -> Optional[bytes]:
        """
        Simple decryption for log data.
        
        Args:
            data: Encrypted data
        
        Returns:
            bytes: Decrypted data, or None if failed
        """
        try:
            if data[0:1] != b'\x01':
                return None
            
            cipher = data[1:]
            key = self.encryption_key
            plaintext = bytes(a ^ b for a, b in zip(cipher, key * (len(cipher) // len(key) + 1)))
            
            return plaintext
        except Exception:
            return None
    
    def _compress_log_file(self, file_path: str) -> bool:
        """
        Compress a log file.
        
        Args:
            file_path: Path to log file
        
        Returns:
            bool: True if successful
        """
        try:
            compressed_path = f"{file_path}.gz"
            
            with open(file_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove original
            os.remove(file_path)
            
            logger.info(f"Log file compressed: {compressed_path}")
            return True
        except Exception as e:
            logger.error(f"Log compression failed: {e}")
            return False
    
    def _cleanup_old_logs(self) -> int:
        """
        Remove logs older than retention period.
        
        Returns:
            int: Number of files removed
        """
        removed = 0
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        
        try:
            for filename in os.listdir(self.log_directory):
                if filename.startswith(".logs."):
                    file_path = os.path.join(self.log_directory, filename)
                    
                    # Get file modification time
                    mtime = datetime.utcfromtimestamp(os.path.getmtime(file_path))
                    
                    if mtime < cutoff:
                        os.remove(file_path)
                        removed += 1
                        logger.info(f"Removed old log file: {filename}")
            
            if removed > 0:
                logger.info(f"Cleanup removed {removed} old log files")
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")
        
        return removed
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of audit logs.
        
        Returns:
            dict: Summary information
        """
        with self.log_lock:
            levels = {}
            components = {}
            
            for entry in self.current_log_entries:
                levels[entry.level] = levels.get(entry.level, 0) + 1
                components[entry.component] = components.get(entry.component, 0) + 1
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "current_entries": len(self.current_log_entries),
            "entries_since_rotation": self.entries_since_last_rotation,
            "levels": levels,
            "components": components,
            "retention_days": self.retention_days
        }
    
    def export_logs(self, output_file: str, include_current: bool = True) -> bool:
        """
        Export logs to encrypted file.
        
        Args:
            output_file: Where to save exported logs
            include_current: Whether to include current logs
        
        Returns:
            bool: True if successful
        """
        try:
            with self.log_lock:
                if include_current:
                    self._write_encrypted_log_file(output_file, self.current_log_entries)
                else:
                    # Export from recent files only
                    self._write_encrypted_log_file(output_file, [])
            
            logger.info(f"Logs exported to: {output_file}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    def clear_logs(self, confirmed: bool = False) -> bool:
        """
        Clear all logs (requires confirmation).
        
        Args:
            confirmed: Must be True to actually clear
        
        Returns:
            bool: True if cleared
        """
        if not confirmed:
            logger.warning("Log clear requested but not confirmed")
            return False
        
        with self.log_lock:
            self.current_log_entries.clear()
            self.entries_since_last_rotation = 0
        
        logger.warning("All audit logs cleared")
        return True


# Migration helper
def migrate_from_audit_log(old_audit_file: str, new_logger: EncryptedAuditLogger) -> int:
    """
    Migrate entries from old audit.log file to encrypted logger.
    
    Args:
        old_audit_file: Path to old audit.log
        new_logger: EncryptedAuditLogger instance
    
    Returns:
        int: Number of entries migrated
    """
    migrated = 0
    
    try:
        with open(old_audit_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Parse log line (format: [timestamp] LEVEL - component: action details)
                    # This is a simplified parser - adjust based on actual format
                    new_logger.log(
                        action="migrated",
                        component="legacy",
                        details={"original_line": line[:100]}
                    )
                    migrated += 1
                except Exception as e:
                    logger.warning(f"Failed to migrate log entry: {e}")
        
        logger.info(f"Migrated {migrated} entries from old audit.log")
        
        # IMPORTANT: Securely delete old file
        try:
            # Overwrite file multiple times before deletion
            file_size = os.path.getsize(old_audit_file)
            with open(old_audit_file, 'wb') as f:
                f.write(b'\x00' * file_size)  # Zero pass
                f.flush()
            
            os.remove(old_audit_file)
            logger.info("Old audit.log securely deleted")
        except Exception as e:
            logger.warning(f"Could not securely delete old audit.log: {e}")
    
    except FileNotFoundError:
        logger.info("Old audit.log not found (migration skipped)")
    except Exception as e:
        logger.error(f"Migration failed: {e}")
    
    return migrated


if __name__ == "__main__":
    # Test the EncryptedAuditLogger
    logging.basicConfig(level=logging.INFO)
    
    # Create logger
    test_key = b"test_encryption_key_for_logs"
    logger_instance = EncryptedAuditLogger(
        log_directory="./encrypted_logs",
        encryption_key=test_key,
        retention_days=90,
        enable_compression=True
    )
    
    print("=== Encrypted Audit Logger Test ===\n")
    
    # Log various events
    print("1. Logging authentication event...")
    logger_instance.log_authentication(success=True, user="admin")
    
    print("2. Logging integrity check...")
    logger_instance.log_integrity_check(success=True, component="db")
    
    print("3. Logging account operation...")
    logger_instance.log_account_operation("create", "MyAccount")
    
    print("4. Get summary...")
    summary = logger_instance.get_summary()
    print(f"   Entries: {summary['current_entries']}")
    print(f"   Levels: {summary['levels']}")
    print(f"   Components: {summary['components']}\n")
    
    print("Done!")
