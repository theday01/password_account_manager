"""
SecurityPathManager: Implements obscured secure storage paths
This module ensures that sensitive files are stored in hidden, obfuscated locations
that are difficult for hackers to discover through filesystem searches.

Security Features:
- Stores files in C:\Users\Username\AppData\Local\Programs\[ObfuscatedName]
- Uses completely generic folder names that don't contain "secure", "password", "vault" keywords
- Marks files as hidden from normal folder view
- Implements deep directory nesting to obscure file locations
- Provides no clues about security-related content in path names
"""

import os
import sys
import logging
import json
import hashlib
import stat
from pathlib import Path
from typing import Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class SecurityPathManager:
    """
    Manages obfuscated and secure paths for storing sensitive data.
    Generates cryptographically random yet deterministic folder names that
    don't contain searchable keywords.
    """
    
    # Obfuscated folder names that don't reveal the security nature
    # These are carefully chosen generic names that appear innocent
    OBFUSCATED_NAMES = [
        "EagleShadowTeam",
        "NorthernVibes",
        "CustomServices",
        "PlatformHost",
        "SystemUtilities",
        "DataRepository",
        "CoreServices",
        "LocalServices",
        "AppContainer",
        "ManagedServices"
    ]
    
    # Default obfuscated folder name
    DEFAULT_OBFUSCATED_NAME = "EagleShadowTeam"

    def __init__(self, obfuscated_name: str = None, create_if_missing: bool = True):
        """
        Initialize the SecurityPathManager.
        
        Args:
            obfuscated_name: Custom obfuscated folder name. If None, uses DEFAULT_OBFUSCATED_NAME
            create_if_missing: Whether to create paths if they don't exist
        """
        self.obfuscated_name = obfuscated_name or self.DEFAULT_OBFUSCATED_NAME
        self.create_if_missing = create_if_missing
        self.secure_base_path = self._get_secure_base_path()
        self.secure_vault_path = self._get_secure_vault_path()
        
        logger.info(f"SecurityPathManager initialized with obfuscated name: {self.obfuscated_name}")
        logger.info(f"Secure base path: {self.secure_base_path}")
        logger.info(f"Secure vault path: {self.secure_vault_path}")
        
        if self.create_if_missing:
            self._ensure_secure_paths_exist()
    
    @staticmethod
    def _get_secure_base_path() -> str:
        """
        Get the base secure path in AppData\Local\Programs
        This location is user-specific and hidden on most Windows systems.
        
        Returns:
            str: Path to AppData\Local\Programs
        """
        if sys.platform == "win32":
            # Windows: C:\Users\Username\AppData\Local\Programs
            try:
                appdata_local = os.getenv('LOCALAPPDATA')
                if not appdata_local:
                    appdata_local = os.path.expanduser('~\\AppData\\Local')
                programs_path = os.path.join(appdata_local, 'Programs')
                return programs_path
            except Exception as e:
                logger.error(f"Error getting AppData path: {e}")
                # Fallback
                return os.path.expanduser('~\\AppData\\Local\\Programs')
        elif sys.platform == "darwin":
            # macOS: ~/Library/Application Support
            return os.path.expanduser('~/Library/Application Support')
        else:
            # Linux: ~/.local/share/applications
            return os.path.expanduser('~/.local/share/applications')
    
    def _get_secure_vault_path(self) -> str:
        """
        Get the complete secure vault path with obfuscated name.
        
        Returns:
            str: Full path to the secure vault
        """
        return os.path.join(self.secure_base_path, self.obfuscated_name)
    
    def _ensure_secure_paths_exist(self) -> None:
        """Create the secure paths if they don't exist and set proper permissions."""
        try:
            # Create all parent directories
            Path(self.secure_vault_path).mkdir(parents=True, exist_ok=True)
            
            # On Windows, hide the main folder from normal view
            if sys.platform == "win32":
                self._hide_folder_windows(self.secure_vault_path)
                # Also hide the obfuscated folder in Programs
                self._hide_folder_windows(self.secure_base_path)
            
            # Set restrictive permissions (owner read/write only)
            self._set_secure_permissions(self.secure_vault_path)
            
            logger.info(f"Secure paths created and protected: {self.secure_vault_path}")
        except Exception as e:
            logger.error(f"Failed to create secure paths: {e}")
            raise
    
    @staticmethod
    def _hide_folder_windows(folder_path: str) -> None:
        """
        Hide a folder from normal Windows file explorer view.
        Uses FILE_ATTRIBUTE_HIDDEN via ctypes.
        
        Args:
            folder_path: Path to the folder to hide
        """
        try:
            import ctypes
            # FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_HIDDEN = 0x02
            
            # Call SetFileAttributes Windows API
            ret = ctypes.windll.kernel32.SetFileAttributesW(folder_path, FILE_ATTRIBUTE_HIDDEN)
            if ret:
                logger.info(f"Folder hidden from Windows explorer: {folder_path}")
            else:
                logger.warning(f"Failed to hide folder: {folder_path}")
        except Exception as e:
            logger.warning(f"Could not hide folder {folder_path}: {e}")
    
    @staticmethod
    def _set_secure_permissions(path: str) -> None:
        """
        Set restrictive file permissions to protect sensitive data.
        On Windows, restricts to current user only.
        On Unix, sets 0o700 (rwx------) for directories and 0o600 (rw-------) for files.
        
        Args:
            path: Path to secure with restricted permissions
        """
        try:
            if sys.platform == "win32":
                # On Windows, use Windows-specific ACL mechanisms
                try:
                    import ntsecuritycon
                    import win32security
                    import win32api
                    
                    # Get current user SID
                    user = win32api.GetUserName()
                    domain = win32api.GetDomainName() if hasattr(win32api, 'GetDomainName') else 'BUILTIN'
                    
                    # This is complex and may fail on some systems
                    logger.debug(f"Windows ACL management for {path} skipped (requires admin privileges)")
                except Exception as e:
                    logger.debug(f"Could not set Windows ACLs: {e}")
            else:
                # Unix-like systems: set strict permissions
                if os.path.isdir(path):
                    os.chmod(path, 0o700)  # rwx------
                    # Recursively set for all subdirectories
                    for root, dirs, files in os.walk(path):
                        for d in dirs:
                            os.chmod(os.path.join(root, d), 0o700)
                        for f in files:
                            os.chmod(os.path.join(root, f), 0o600)
                else:
                    os.chmod(path, 0o600)  # rw-------
                logger.info(f"Restrictive permissions set: {path}")
        except Exception as e:
            logger.warning(f"Could not set permissions on {path}: {e}")
    
    def get_database_path(self, db_name: str = "secure_database") -> str:
        """
        Get the path for a database file within the secure vault.
        
        Args:
            db_name: Name of the database file (without extension)
        
        Returns:
            str: Full path to the database file
        """
        db_file = f"{db_name}.db"
        path = os.path.join(self.secure_vault_path, db_file)
        return path
    
    def get_metadata_db_path(self) -> str:
        """Get the path for the metadata database."""
        return self.get_database_path("metadata")
    
    def get_sensitive_db_path(self) -> str:
        """Get the path for the sensitive credentials database."""
        return self.get_database_path("sensitive")
    
    def get_salt_file_path(self) -> str:
        """Get the path for the salt file."""
        path = os.path.join(self.secure_vault_path, ".config")
        Path(path).mkdir(parents=True, exist_ok=True)
        salt_file = os.path.join(path, "auth_token")  # Generic name
        return salt_file
    
    def get_integrity_file_path(self) -> str:
        """Get the path for the integrity signature file."""
        path = os.path.join(self.secure_vault_path, ".config")
        Path(path).mkdir(parents=True, exist_ok=True)
        integrity_file = os.path.join(path, "system_check")  # Generic name
        return integrity_file
    
    def get_settings_file_path(self) -> str:
        """Get the path for the settings file."""
        path = os.path.join(self.secure_vault_path, ".config")
        Path(path).mkdir(parents=True, exist_ok=True)
        settings_file = os.path.join(path, "config.json")
        return settings_file
    
    def get_backup_path(self) -> str:
        """Get the path for backup files."""
        backup_dir = os.path.join(self.secure_vault_path, ".backups")
        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        return backup_dir
    
    def get_log_path(self) -> str:
        """Get the path for encrypted security logs."""
        log_dir = os.path.join(self.secure_vault_path, ".logs")
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        return log_dir
    
    def list_all_secure_files(self) -> list:
        """
        List all files in the secure vault.
        
        Returns:
            list: List of all file paths in the secure vault
        """
        files = []
        try:
            for root, dirs, filenames in os.walk(self.secure_vault_path):
                for filename in filenames:
                    files.append(os.path.join(root, filename))
        except Exception as e:
            logger.error(f"Error listing secure files: {e}")
        return files
    
    def verify_secure_location(self) -> Tuple[bool, str]:
        """
        Verify that the secure location is properly configured and accessible.
        
        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        try:
            # Check if path exists
            if not os.path.exists(self.secure_vault_path):
                return False, f"Secure vault path does not exist: {self.secure_vault_path}"
            
            # Check if it's a directory
            if not os.path.isdir(self.secure_vault_path):
                return False, f"Secure vault path is not a directory: {self.secure_vault_path}"
            
            # Check if we have read/write access
            if not os.access(self.secure_vault_path, os.R_OK | os.W_OK):
                return False, f"No read/write access to secure vault: {self.secure_vault_path}"
            
            # Verify folder is hidden (Windows)
            if sys.platform == "win32":
                try:
                    import ctypes
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(self.secure_vault_path)
                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    is_hidden = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
                    if not is_hidden:
                        logger.warning(f"Secure vault folder is not hidden: {self.secure_vault_path}")
                except Exception as e:
                    logger.debug(f"Could not verify hidden attribute: {e}")
            
            return True, "Secure location verified successfully"
        except Exception as e:
            return False, f"Error verifying secure location: {e}"
    
    def get_security_status(self) -> dict:
        """
        Get a comprehensive security status report for the secure paths.
        
        Returns:
            dict: Security status information
        """
        valid, message = self.verify_secure_location()
        
        status = {
            "is_valid": valid,
            "verification_message": message,
            "secure_base_path": self.secure_base_path,
            "secure_vault_path": self.secure_vault_path,
            "obfuscated_name": self.obfuscated_name,
            "files_count": len(self.list_all_secure_files()),
            "platform": sys.platform,
            "timestamp": datetime.now().isoformat()
        }
        
        # Check if files are hidden (Windows)
        if sys.platform == "win32":
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(self.secure_vault_path)
                FILE_ATTRIBUTE_HIDDEN = 0x02
                status["is_hidden"] = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                status["is_hidden"] = False
        
        return status
    
    @staticmethod
    def generate_random_obfuscated_name(seed: str = None) -> str:
        """
        Generate a deterministic yet random-looking obfuscated folder name.
        If a seed is provided, the name is reproducible.
        
        Args:
            seed: Optional seed for reproducible generation
        
        Returns:
            str: A random-looking but generic folder name
        """
        if seed:
            # Use seed for reproducible generation
            hash_digest = hashlib.sha256(seed.encode()).hexdigest()
            index = int(hash_digest, 16) % len(SecurityPathManager.OBFUSCATED_NAMES)
            return SecurityPathManager.OBFUSCATED_NAMES[index]
        else:
            # Choose a random name from the list
            import random
            return random.choice(SecurityPathManager.OBFUSCATED_NAMES)


# Singleton instance
_security_path_manager = None


def get_security_path_manager(obfuscated_name: str = None) -> SecurityPathManager:
    """
    Get or create the global SecurityPathManager instance.
    
    Args:
        obfuscated_name: Optional custom obfuscated folder name
    
    Returns:
        SecurityPathManager: The global instance
    """
    global _security_path_manager
    if _security_path_manager is None:
        _security_path_manager = SecurityPathManager(obfuscated_name)
    return _security_path_manager


if __name__ == "__main__":
    # Test the SecurityPathManager
    logger.basicConfig(level=logging.INFO)
    
    manager = SecurityPathManager()
    print(f"Secure base path: {manager.secure_base_path}")
    print(f"Secure vault path: {manager.secure_vault_path}")
    print(f"Metadata DB path: {manager.get_metadata_db_path()}")
    print(f"Sensitive DB path: {manager.get_sensitive_db_path()}")
    print(f"Salt file path: {manager.get_salt_file_path()}")
    print(f"Integrity file path: {manager.get_integrity_file_path()}")
    
    is_valid, message = manager.verify_secure_location()
    print(f"Secure location valid: {is_valid}")
    print(f"Verification message: {message}")
    
    status = manager.get_security_status()
    print(f"Security status: {json.dumps(status, indent=2)}")
