"""
Enhanced Developer Complete Reset Tool
========================================
Removes ALL trial, activation, and security data for developer testing.
"""

import os
import sys
import shutil
import logging
from pathlib import Path
from datetime import datetime
import ctypes
import platform

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

# Configure logging with UTF-8 encoding
log_file = f'developer_reset_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),  # FIX: UTF-8 encoding
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class EnhancedResetTool:
    def __init__(self):
        self.paths_removed = []
        self.paths_failed = []
        
        print("\n" + "="*70)
        print("DEVELOPER COMPLETE RESET TOOL")
        print("="*70)
        logger.info("Reset tool initialized")
    
    def get_all_trial_locations(self):
        """Get all possible trial storage locations"""
        locations = []
        
        if os.name == 'nt':  # Windows
            base_paths = [
                (os.getenv('LOCALAPPDATA'), 'SecureVaultPro'),
                (os.getenv('APPDATA'), 'SecureVaultPro'),
                (os.getenv('PROGRAMDATA'), 'SecureVaultPro'),
                (os.getenv('TEMP'), '.SecureVaultPro'),
            ]
        else:  # Unix-like
            base_paths = [
                (os.path.expanduser('~/.local/share'), 'securevaultpro'),
                (os.path.expanduser('~/.config'), 'securevaultpro'),
                ('/var/lib', 'securevaultpro'),
                ('/tmp', '.securevaultpro'),
            ]
        
        for base_dir, app_dir in base_paths:
            if base_dir:
                full_path = os.path.join(base_dir, app_dir)
                if os.path.exists(full_path):
                    locations.append(full_path)
        
        return locations
    
    def remove_directory_safe(self, path: str, description: str):
        """Safely remove a directory with logging"""
        try:
            if os.path.exists(path):
                logger.info(f"Removing {description}: {path}")
                shutil.rmtree(path)
                self.paths_removed.append(path)
                logger.info(f"SUCCESS: Removed {description}")
                return True
            else:
                logger.info(f"SKIP: {description} not found")
                return True
        except PermissionError:
            logger.error(f"PERMISSION DENIED: {path}")
            self.paths_failed.append(f"{path} - Permission Denied")
            return False
        except Exception as e:
            logger.error(f"FAILED: {path} - {e}")
            self.paths_failed.append(f"{path} - {str(e)}")
            return False
    
    def remove_file_safe(self, path: str, description: str):
        """Safely remove a file with logging"""
        try:
            if os.path.exists(path):
                logger.info(f"Removing {description}: {path}")
                os.remove(path)
                self.paths_removed.append(path)
                logger.info(f"SUCCESS: Removed {description}")
                return True
            else:
                logger.info(f"SKIP: {description} not found")
                return True
        except Exception as e:
            logger.error(f"FAILED: {path} - {e}")
            self.paths_failed.append(f"{path} - {str(e)}")
            return False
    
    def reset_trial_state(self):
        """Remove all trial state files"""
        print("\n[1/7] Removing trial state files...")
        logger.info("="*60)
        
        locations = self.get_all_trial_locations()
        
        if not locations:
            logger.info("No trial state directories found")
            return True
        
        for location in locations:
            self.remove_directory_safe(location, "Trial state directory")
        
        return True
    
    def remove_registry_entries(self):
        """Remove Windows Registry entries"""
        print("\n[2/7] Removing Registry entries...")
        logger.info("="*60)
        
        if os.name != 'nt':
            logger.info("Not Windows - skipping registry cleanup")
            return True
        
        try:
            import winreg
            
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility"),
            ]
            
            for hkey, key_path in registry_paths:
                try:
                    hkey_name = "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                    logger.info(f"Checking: {hkey_name}\\{key_path}")
                    
                    with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                        # Scan for suspicious hex entries (16 chars)
                        index = 0
                        removed_count = 0
                        while True:
                            try:
                                name, value, vtype = winreg.EnumValue(key, index)
                                
                                if (len(name) == 16 and 
                                    all(c in '0123456789abcdef' for c in name.lower())):
                                    try:
                                        winreg.DeleteValue(key, name)
                                        logger.info(f"SUCCESS: Removed registry entry {name}")
                                        removed_count += 1
                                    except Exception as e:
                                        logger.warning(f"Could not delete {name}: {e}")
                                
                                index += 1
                            except WindowsError:
                                break
                        
                        if removed_count > 0:
                            logger.info(f"Removed {removed_count} registry entries")
                        else:
                            logger.info("No suspicious entries found")
                
                except FileNotFoundError:
                    logger.info(f"Registry key not found: {key_path}")
                except PermissionError:
                    logger.warning(f"Permission denied: {key_path}")
        
        except ImportError:
            logger.error("winreg module not available")
            return False
        
        return True
    
    def remove_developer_files(self):
        """Remove developer override files"""
        print("\n[3/7] Removing developer mode files...")
        logger.info("="*60)
        
        dev_files = [
            '.dev_override',
            'developer_mode.txt',
            '.developer_key',
        ]
        
        for filename in dev_files:
            self.remove_file_safe(filename, f"Developer file: {filename}")
        
        return True
    
    def remove_database_files(self):
        """Remove all database files"""
        print("\n[4/7] Removing database files...")
        logger.info("="*60)
        
        import glob
        
        db_patterns = [
            'manageyouraccount*',
            '*.db',
            '*.db-wal',
            '*.db-shm',
            '*_salt',
            '*_integrity',
        ]
        
        removed = 0
        for pattern in db_patterns:
            for file in glob.glob(pattern):
                # Don't remove the log file
                if file == log_file:
                    continue
                
                if self.remove_file_safe(file, f"Database file: {file}"):
                    removed += 1
        
        if removed > 0:
            logger.info(f"Removed {removed} database files")
        else:
            logger.info("No database files found")
        
        return True
    
    def remove_temp_files(self):
        """Remove temporary files"""
        print("\n[5/7] Removing temporary files...")
        logger.info("="*60)
        
        temp_paths = [
            '__pycache__',
            '.pytest_cache',
            'htmlcov',
        ]
        
        removed = 0
        for path in temp_paths:
            if os.path.exists(path):
                if self.remove_directory_safe(path, f"Temp directory: {path}"):
                    removed += 1
        
        # Remove .pyc files
        import glob
        for file in glob.glob('**/*.pyc', recursive=True):
            if self.remove_file_safe(file, f"Compiled Python: {file}"):
                removed += 1
        
        # Remove old log files (except current)
        for file in glob.glob('developer_reset_*.log'):
            if file != log_file:
                if self.remove_file_safe(file, f"Old log: {file}"):
                    removed += 1
        
        logger.info(f"Removed {removed} temporary items")
        return True

    def remove_lockout_state(self):
        """Removes all redundant lockout state files and registry keys."""
        print("\n[6/7] Removing lockout state artifacts...")
        logger.info("="*60)

        paths = []
        home = Path.home()
        
        paths.append('auth_state.json')

        if platform.system() == "Windows":
            app_data = os.environ.get('APPDATA')
            if app_data:
                paths.append(os.path.join(app_data, 'SecVault', 'status.dat'))
            temp_dir = os.environ.get('TEMP', 'C:\\Temp')
            paths.append(os.path.join(temp_dir, 'sec_auth_cache.dat'))
        else:
            paths.append(os.path.join(home, '.config', 'secvault_status.conf'))
            paths.append('/var/tmp/sec_auth_cache.dat')
            paths.append(os.path.join(home, '.auth_status.local'))
        
        paths.append(os.path.join(home, '.auth_status.dat')) # Obsolete path

        for path in paths:
            self.remove_file_safe(path, f"Lockout state file: {path}")

        if platform.system() == "Windows":
            try:
                import winreg
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\SecVault")
                logger.info("SUCCESS: Removed registry key Software\\SecVault")
                self.paths_removed.append("Registry Key: Software\\SecVault")
            except FileNotFoundError:
                logger.info("SKIP: Registry key Software\\SecVault not found")
            except Exception as e:
                logger.error(f"FAILED: Could not remove registry key Software\\SecVault - {e}")
                self.paths_failed.append(f"Registry Key: Software\\SecVault - {e}")
        
        return True
    
    def verify_cleanup(self):
        """Verify cleanup was successful"""
        print("\n[7/7] Verifying cleanup...")
        logger.info("="*60)
        
        locations = self.get_all_trial_locations()
        
        if not locations:
            logger.info("SUCCESS: All trial locations cleaned")
            return True
        else:
            logger.warning(f"WARNING: {len(locations)} location(s) still exist")
            for loc in locations:
                logger.warning(f"  - {loc}")
            return False
    
    def print_summary(self):
        """Print summary of operations"""
        print("\n" + "="*70)
        print("CLEANUP SUMMARY")
        print("="*70)
        
        logger.info(f"\nStatistics:")
        logger.info(f"  Removed: {len(self.paths_removed)} items")
        logger.info(f"  Failed: {len(self.paths_failed)} items")
        
        if self.paths_failed:
            logger.warning(f"\nFailed items:")
            for item in self.paths_failed:
                logger.warning(f"  - {item}")
        
        logger.info("\n" + "="*70)
        logger.info("RESET COMPLETED")
        logger.info("="*70)
        logger.info(f"\nLog saved to: {log_file}")
        logger.info(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def run_complete_reset(self):
        """Execute complete reset"""
        try:
            # Check for a --force or -y flag to run non-interactively
            if '--force' not in sys.argv and '-y' not in sys.argv:
                print("\nWARNING: This will DELETE all program data!")
                print("Press ENTER to continue or Ctrl+C to cancel...")
                try:
                    input()
                except KeyboardInterrupt:
                    print("\n\nReset cancelled")
                    return False
            else:
                print("\n--force flag detected. Running non-interactively.")

            print("\nStarting complete reset...\n")
            
            # Execute cleanup steps
            self.reset_trial_state()
            self.remove_registry_entries()
            self.remove_developer_files()
            self.remove_database_files()
            self.remove_temp_files()
            self.remove_lockout_state()
            self.verify_cleanup()
            
            # Print summary
            self.print_summary()
            
            return True
        
        except KeyboardInterrupt:
            print("\n\nReset cancelled")
            return False
        except Exception as e:
            logger.error(f"Critical error: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    if os.name == 'nt':
        run_as_admin()
    
    try:
        tool = EnhancedResetTool()
        success = tool.run_complete_reset()
        
        # In non-interactive mode, exit immediately.
        if '--force' in sys.argv or '-y' in sys.argv:
            sys.exit(0 if success else 1)

        if success:
            print("\nSUCCESS: Press ENTER to exit...")
            input()
            sys.exit(0)
        else:
            print("\nFAILED: Check log for details")
            print("Press ENTER to exit...")
            input()
            sys.exit(1)
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        if '--force' not in sys.argv and '-y' not in sys.argv:
            print("\nPress ENTER to exit...")
            input()
        sys.exit(1)


if __name__ == "__main__":
    main()