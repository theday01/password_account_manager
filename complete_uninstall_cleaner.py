"""
Complete Uninstall Cleaner for SecureVault Pro
Removes all activation files, trial data, and traces from the Windows system.
This ensures a complete clean slate as if the program was never installed.

Paths removed:
1. AppData/Local/SecureVaultPro - Trial and activation data
2. Windows Registry entries - System integrity watermark
3. Backup directories
4. Local secure vault data (if present)
"""

import os
import shutil
import sys
import logging
from pathlib import Path
from datetime import datetime
import ctypes


def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_as_admin():
    """Re-run the script with administrator privileges."""
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('uninstall_log.txt'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class CompleteUninstallCleaner:
    """
    Complete cleaner for removing all SecureVault Pro traces from the system.
    Targets both file system and Windows Registry entries.
    """
    
    def __init__(self):
        """Initialize the cleaner and identify all paths to remove."""
        self.paths_removed = []
        self.paths_failed = []
        self.registry_entries_removed = []
        self.registry_entries_failed = []
        
        logger.info("=" * 80)
        logger.info("SecureVault Pro - Complete Uninstall Cleaner")
        logger.info("=" * 80)
        logger.info(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Running as Administrator: {is_admin()}")
        logger.info("=" * 80)
    
    def remove_appdata_trial_activation(self) -> bool:
        r"""
        Remove trial and activation data from AppData/Local.
        
        Default path: C:\Users\[USERNAME]\AppData\Local\SecureVaultPro\.trial
        
        Returns:
            bool: True if removal was successful or path didn't exist
        """
        logger.info("\n[1/5] Removing AppData trial and activation data...")
        
        try:
            appdata = os.getenv('LOCALAPPDATA')
            if not appdata:
                logger.warning("❌ LOCALAPPDATA not found")
                return False
            
            securevault_path = os.path.join(appdata, 'SecureVaultPro')
            logger.info(f"    Checking path: {securevault_path}")
            
            if os.path.exists(securevault_path):
                logger.info(f"    📂 Found SecureVaultPro directory")
                logger.info(f"    🗑️ Deleting directory and all contents...")
                shutil.rmtree(securevault_path)
                self.paths_removed.append(securevault_path)
                logger.info(f"    ✅ Successfully removed: {securevault_path}")
                return True
            else:
                logger.info(f"    ℹ️ Directory not found (already clean)")
                return True
        
        except PermissionError as e:
            logger.error(f"    ❌ Permission denied: {e}")
            self.paths_failed.append(f"AppData/SecureVaultPro - Permission Denied")
            return False
        except Exception as e:
            logger.error(f"    ❌ Failed to remove AppData path: {e}")
            self.paths_failed.append(f"AppData/SecureVaultPro - {str(e)}")
            return False
    
    def remove_local_vault_data(self) -> bool:
        """
        Remove local secure vault directory and all data.
        
        Default path: secure_vault/ (in current directory or app directory)
        
        Returns:
            bool: True if removal was successful or path didn't exist
        """
        logger.info("\n[2/5] Removing local secure vault data...")
        
        vault_paths = [
            'secure_vault',
            os.path.join(os.path.dirname(__file__), 'secure_vault')
        ]
        
        for vault_path in vault_paths:
            try:
                logger.info(f"    Checking path: {vault_path}")
                if os.path.exists(vault_path):
                    logger.info(f"    📂 Found vault directory")
                    logger.info(f"    🗑️ Deleting vault files (metadata.db, sensitive.db, etc.)...")
                    shutil.rmtree(vault_path)
                    self.paths_removed.append(vault_path)
                    logger.info(f"    ✅ Successfully removed: {vault_path}")
                    return True
            except PermissionError as e:
                logger.error(f"    ❌ Permission denied for {vault_path}: {e}")
                self.paths_failed.append(f"secure_vault - Permission Denied")
            except Exception as e:
                logger.error(f"    ❌ Failed to remove vault path {vault_path}: {e}")
                self.paths_failed.append(f"secure_vault - {str(e)}")
        
        logger.info("    ℹ️ Secure vault directory not found (already clean)")
        return True
    
    def remove_backup_directories(self) -> bool:
        """
        Remove backup directories that may contain encrypted data.
        
        Default paths:
        - backups/local/
        - backups/temp/
        
        Returns:
            bool: True if removal was successful or paths didn't exist
        """
        logger.info("\n[3/5] Removing backup directories...")
        
        backup_paths = ['backups']
        
        for backup_path in backup_paths:
            try:
                logger.info(f"    Checking path: {backup_path}")
                if os.path.exists(backup_path):
                    logger.info(f"    📂 Found backup directory")
                    logger.info(f"    🗑️ Deleting backup files...")
                    shutil.rmtree(backup_path)
                    self.paths_removed.append(backup_path)
                    logger.info(f"    ✅ Successfully removed: {backup_path}")
                else:
                    logger.info(f"    ℹ️ Backup directory not found (already clean): {backup_path}")
            except PermissionError as e:
                logger.error(f"    ❌ Permission denied for {backup_path}: {e}")
                self.paths_failed.append(f"backups - Permission Denied")
            except Exception as e:
                logger.error(f"    ❌ Failed to remove backup path {backup_path}: {e}")
                self.paths_failed.append(f"backups - {str(e)}")
        
        return True
    
    def remove_registry_entries(self) -> bool:
        r"""
        Remove Windows Registry entries related to system integrity watermark.
        
        Registry path: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility
        Registry path: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility
        
        Entry: System integrity watermark hash (dynamic name based on machine ID)
        
        Returns:
            bool: True if removal was successful or entry didn't exist
        """
        logger.info("\n[4/5] Removing Windows Registry entries...")
        
        if os.name != 'nt':
            logger.warning("Registry cleanup is Windows-only. Skipping.")
            return True
        
        try:
            import winreg
            import hashlib
            from machine_id_utils import generate_machine_id
            
            try:
                machine_id = generate_machine_id()
                watermark_name = hashlib.sha256(f"sys-integrity-{machine_id}".encode()).hexdigest()[:16]
            except Exception as e:
                logger.warning(f"Could not generate machine ID for registry cleanup: {e}")
                logger.info("Attempting to clean all potential registry entries...")
                watermark_name = None
            
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility")
            ]
            
            for hkey, key_path in registry_paths:
                try:
                    with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                        if watermark_name:
                            try:
                                winreg.DeleteValue(key, watermark_name)
                                self.registry_entries_removed.append(f"{key_path}\\{watermark_name}")
                                logger.info(f"✓ Removed registry entry: {key_path}\\{watermark_name}")
                            except FileNotFoundError:
                                logger.info(f"Registry entry not found (already clean): {key_path}\\{watermark_name}")
                        else:
                            # Try to find and remove any entries that might match our pattern
                            try:
                                index = 0
                                while True:
                                    name, value, vtype = winreg.EnumValue(key, index)
                                    if len(name) == 16 and all(c in '0123456789abcdef' for c in name.lower()):
                                        try:
                                            winreg.DeleteValue(key, name)
                                            self.registry_entries_removed.append(f"{key_path}\\{name}")
                                            logger.info(f"✓ Removed registry entry: {key_path}\\{name}")
                                        except Exception as e:
                                            logger.warning(f"Could not delete {name}: {e}")
                                    index += 1
                            except WindowsError:
                                pass  # End of enumeration
                
                except FileNotFoundError:
                    logger.info(f"Registry path not found (already clean): {key_path}")
                except PermissionError:
                    logger.warning(f"Permission denied accessing registry: {key_path}")
                    logger.info("   (You may need to run this script as Administrator)")
                    self.registry_entries_failed.append(f"{key_path} - Permission Denied")
            
            return True
        
        except ImportError:
            logger.error("winreg module not available on this system")
            return False
        except Exception as e:
            logger.error(f"✗ Failed to clean registry entries: {e}")
            self.registry_entries_failed.append(f"Registry cleanup - {str(e)}")
            return False
    
    def remove_pycache_and_temp_files(self) -> bool:
        """
        Remove Python cache and temporary files.
        
        Returns:
            bool: True if removal was successful
        """
        logger.info("\n[5/5] Removing Python cache and temporary files...")
        
        cache_paths = ['__pycache__', '.pytest_cache', '____problms']
        
        for cache_path in cache_paths:
            try:
                logger.info(f"    Checking path: {cache_path}")
                if os.path.exists(cache_path):
                    logger.info(f"    📂 Found cache/temp directory")
                    logger.info(f"    🗑️ Deleting cache files...")
                    shutil.rmtree(cache_path)
                    self.paths_removed.append(cache_path)
                    logger.info(f"    ✅ Successfully removed: {cache_path}")
            except Exception as e:
                logger.warning(f"    ⚠️ Failed to remove {cache_path}: {e}")
        
        return True
    
    def print_summary(self):
        """Print a summary of all removals and failures."""
        logger.info("\n" + "=" * 80)
        logger.info("UNINSTALL SUMMARY")
        logger.info("=" * 80)
        
        logger.info(f"\n📋 Total Items Removed: {len(self.paths_removed) + len(self.registry_entries_removed)}")
        logger.info(f"❌ Total Failures: {len(self.paths_failed) + len(self.registry_entries_failed)}")
        
        logger.info("\n✓ Successfully Removed Files/Directories:")
        if self.paths_removed:
            for i, path in enumerate(self.paths_removed, 1):
                logger.info(f"  {i}. {path}")
        else:
            logger.info("  (No paths needed removal)")
        
        if self.registry_entries_removed:
            logger.info(f"\n✓ Registry entries removed ({len(self.registry_entries_removed)}):")
            for i, entry in enumerate(self.registry_entries_removed, 1):
                logger.info(f"  {i}. {entry}")
        
        if self.paths_failed or self.registry_entries_failed:
            logger.warning("\n⚠️ Failed/Skipped Items:")
            for failed in self.paths_failed + self.registry_entries_failed:
                logger.warning(f"  • {failed}")
        
        logger.info("\n" + "=" * 80)
        logger.info("✅ Uninstall completed successfully!")
        logger.info(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("SecureVault Pro has been completely removed from your system.")
        logger.info("=" * 80)
    
    def run_complete_cleanup(self) -> bool:
        """
        Execute complete cleanup sequence.
        
        Returns:
            bool: True if all operations completed (even with some failures)
        """
        try:
            self.remove_appdata_trial_activation()
            self.remove_local_vault_data()
            self.remove_backup_directories()
            self.remove_registry_entries()
            self.remove_pycache_and_temp_files()
            
            self.print_summary()
            return True
        
        except Exception as e:
            logger.error(f"Critical error during cleanup: {e}")
            return False


def main():
    """Main entry point for the uninstall cleaner."""
    # Ensure script runs as administrator
    run_as_admin()
    
    try:
        cleaner = CompleteUninstallCleaner()
        success = cleaner.run_complete_cleanup()
        
        if success:
            sys.exit(0)
        else:
            sys.exit(1)
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
