import os
import sys
import argparse
import platform
import hashlib
import ctypes

# It is safe to import these as this script is not part of the main application
# and is only intended for development/testing.
from guardian_anchor import GuardianAnchor
from guardian_observer import GuardianObserver
from trial_manager import TrialManager
from secure_file_manager import SecureFileManager
from tamper_manager import TamperManager

# THIS IS A SECRET PASSWORD. A real application might use a more secure method
# for developer authentication, but for this context, a hardcoded secret is sufficient.
DEV_PASSWORD = "a_very_secret_dev_password_for_testing_only"

def is_admin():
    """
    Checks if the script is running with administrative privileges on Windows.
    Returns True if it is, False otherwise. On non-Windows systems, it always
    returns True as this elevation concept is specific to Windows UAC.
    """
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return True

def run_as_admin():
    """
    Re-launches the script with administrative privileges on Windows if not
    already running as an admin. This will trigger a UAC prompt.
    """
    if platform.system() == "Windows":
        if not is_admin():
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{p}"' for p in sys.argv[1:]])
            try:
                result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
                if result <= 32:
                    print(f"[ERROR] Failed to elevate privileges. ShellExecuteW returned {result}")
                    sys.exit(1)
            except Exception as e:
                print(f"[ERROR] An error occurred while trying to elevate privileges: {e}")
                sys.exit(1)
            sys.exit(0) # Exit the non-elevated instance

def secure_delete(path):
    """
    Securely deletes a file by overwriting it with random data, renaming it,
    and then deleting it.
    """
    try:
        if not os.path.isfile(path):
            return False  # Nothing to delete

        file_size = os.path.getsize(path)
        with open(path, 'rb+') as f:
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())

        # Rename to obscure the original filename
        dir_name = os.path.dirname(path)
        random_name = hashlib.sha256(os.urandom(32)).hexdigest()
        new_path = os.path.join(dir_name, random_name)
        os.rename(path, new_path)

        os.remove(new_path)
        return True
    except (OSError, IOError) as e:
        print(f"[ERROR] Secure delete failed for {path}: {e}")
        return False

def find_and_delete_files(prefixes_and_dirs, secure_mode=False):
    """
    Scans directories for files with specific prefixes and deletes them.
    If secure_mode is True, it will perform a secure deletion.
    """
    deleted_count = 0
    failed_count = 0
    
    for name, data in prefixes_and_dirs.items():
        prefix = data["prefix"]
        directory = data["dir"]
        
        if not os.path.isdir(directory):
            print(f"[INFO] Directory for {name} not found: {directory}. Skipping.")
            continue

        found_files = False
        for filename in os.listdir(directory):
            if filename.startswith(prefix):
                found_files = True
                path_to_delete = os.path.join(directory, filename)
                
                if secure_mode:
                    if secure_delete(path_to_delete):
                        print(f"[SUCCESS] Securely deleted {name}: {path_to_delete}")
                        deleted_count += 1
                    else:
                        failed_count += 1
                else:
                    try:
                        os.remove(path_to_delete)
                        print(f"[SUCCESS] Deleted {name}: {path_to_delete}")
                        deleted_count += 1
                    except OSError as e:
                        print(f"[ERROR] FAILED to delete {name}: {path_to_delete}")
                        print(f"         Reason: {e}")
                        print(f"         RECOMMENDATION: Manually delete the file above and re-run this script with elevated (admin/sudo) privileges.")
                        failed_count += 1
        
        if not found_files:
            print(f"[INFO] No files with prefix '{prefix}' found in {directory}.")
            
    return deleted_count, failed_count


def clean_registry_artifacts():
    """
    Deletes trial-related artifacts from the Windows Registry.
    """
    if platform.system() != "Windows":
        return 0, 0

    print("Scanning for registry artifacts...")
    try:
        import winreg
        tm = TamperManager()
        key_path = tm.registry_key_path
        value_name = tm.registry_value_name
        
        deleted_count = 0
        failed_count = 0

        keys_to_try = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
        for hkey in keys_to_try:
            try:
                with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_WRITE) as key:
                    winreg.DeleteValue(key, value_name)
                    print(f"[SUCCESS] Deleted registry value: {value_name} from {hkey}\\{key_path}")
                    deleted_count += 1
            except FileNotFoundError:
                # This is okay, it means the key/value doesn't exist.
                pass
            except OSError as e:
                print(f"[ERROR] FAILED to delete registry value from {hkey}\\{key_path}: {e}")
                print("         RECOMMENDATION: Run this script with elevated (admin/sudo) privileges.")
                failed_count += 1
        return deleted_count, failed_count
    except ImportError:
        print("[INFO] winreg module not found. Skipping registry cleanup.")
        return 0, 0
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during registry cleanup: {e}")
        return 0, 1


def clean_all_artifacts(secure_mode=False):
    """
    Finds and deletes all known artifacts from the new guardian-based trial system
    by scanning for discoverable filename prefixes and registry keys.
    """
    print("--- Developer Cleanup Tool ---")
    if secure_mode:
        print("Secure mode enabled: files will be overwritten before deletion.")
    print("Scanning for all trial-related artifacts...")

    total_deleted = 0
    total_failed = 0

    try:
        # Clean file-based artifacts
        anchor = GuardianAnchor()
        observer = GuardianObserver(anchor)
        settings_manager = SecureFileManager()
        trial_manager = TrialManager(
            parent_window=None, 
            settings_manager=settings_manager,
            restart_callback=None
        )
        
        search_locations = {
            "Anchor File(s)": {"prefix": "sv-anchor-", "dir": os.path.dirname(anchor.anchor_path)},
            "Backup Anchor File(s)": {"prefix": "sv-ts-validation-", "dir": os.path.dirname(anchor.backup_anchor_path)},
            "Observer File(s)": {"prefix": "sv-observer-", "dir": os.path.dirname(observer.observer_path)},
            "License File(s)": {"prefix": "sv-license-" if platform.system() == "Windows" else ".sv-license-", "dir": os.path.dirname(trial_manager.LICENSE_FILE)}
        }
        deleted, failed = find_and_delete_files(search_locations, secure_mode=secure_mode)
        total_deleted += deleted
        total_failed += failed

        # Clean the secure vault directory
        secure_vault_dir = "secure_vault"
        if os.path.exists(secure_vault_dir):
            print(f"[INFO] Cleaning secure vault directory: {secure_vault_dir}")
            if secure_mode:
                # Securely delete all files in the directory
                for root, dirs, files in os.walk(secure_vault_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if secure_delete(file_path):
                            print(f"[SUCCESS] Securely deleted: {file_path}")
                            total_deleted += 1
                        else:
                            print(f"[ERROR] Failed to securely delete: {file_path}")
                            total_failed += 1
                
                # Remove empty directories
                try:
                    import shutil
                    shutil.rmtree(secure_vault_dir)
                    print(f"[SUCCESS] Removed secure vault directory: {secure_vault_dir}")
                    total_deleted += 1
                except Exception as e:
                    print(f"[ERROR] Failed to remove secure vault directory: {e}")
                    total_failed += 1
            else:
                # Regular delete
                try:
                    import shutil
                    shutil.rmtree(secure_vault_dir)
                    print(f"[SUCCESS] Deleted secure vault directory: {secure_vault_dir}")
                    total_deleted += 1
                except Exception as e:
                    print(f"[ERROR] Failed to delete secure vault directory: {e}")
                    total_failed += 1

        # Clean any legacy database files in current directory
        legacy_files = [
            "manageyouraccount_metadata.db",
            "manageyouraccount_sensitive.db", 
            "manageyouraccount_salt",
            "manageyouraccount_integrity",
            "metadata.db",
            "sensitive.db",
            "salt_file",
            "integrity_file",
            "settings.json"
        ]
        
        print("\n[INFO] Cleaning legacy database files...")
        for fname in legacy_files:
            if os.path.exists(fname):
                try:
                    if secure_mode:
                        if secure_delete(fname):
                            print(f"[SUCCESS] Securely deleted legacy file: {fname}")
                            total_deleted += 1
                        else:
                            print(f"[ERROR] Failed to securely delete legacy file: {fname}")
                            total_failed += 1
                    else:
                        os.remove(fname)
                        print(f"[SUCCESS] Deleted legacy file: {fname}")
                        total_deleted += 1
                except Exception as e:
                    print(f"[ERROR] Failed to delete legacy file {fname}: {e}")
                    total_failed += 1

        # Clean backup directory
        backups_dir = "backups"
        if os.path.exists(backups_dir):
            print(f"\n[INFO] Cleaning backups directory: {backups_dir}")
            try:
                if secure_mode:
                    for root, dirs, files in os.walk(backups_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if secure_delete(file_path):
                                print(f"[SUCCESS] Securely deleted backup: {file_path}")
                                total_deleted += 1
                            else:
                                print(f"[ERROR] Failed to securely delete backup: {file_path}")
                                total_failed += 1
                    
                    import shutil
                    shutil.rmtree(backups_dir)
                    print(f"[SUCCESS] Removed backups directory: {backups_dir}")
                    total_deleted += 1
                else:
                    import shutil
                    shutil.rmtree(backups_dir)
                    print(f"[SUCCESS] Deleted backups directory: {backups_dir}")
                    total_deleted += 1
            except Exception as e:
                print(f"[ERROR] Failed to clean backups directory: {e}")
                total_failed += 1

        # Clean registry-based artifacts on Windows
        if platform.system() == "Windows":
            print("\n[INFO] Cleaning Windows registry artifacts...")
            deleted, failed = clean_registry_artifacts()
            total_deleted += deleted
            total_failed += failed

        # Clean WAL and SHM files (SQLite temporary files)
        print("\n[INFO] Cleaning SQLite temporary files...")
        sqlite_temp_files = [
            "metadata.db-wal",
            "metadata.db-shm",
            "sensitive.db-wal",
            "sensitive.db-shm",
            "manageyouraccount_metadata.db-wal",
            "manageyouraccount_metadata.db-shm",
            "manageyouraccount_sensitive.db-wal",
            "manageyouraccount_sensitive.db-shm"
        ]
        
        for fname in sqlite_temp_files:
            if os.path.exists(fname):
                try:
                    if secure_mode:
                        if secure_delete(fname):
                            print(f"[SUCCESS] Securely deleted SQLite temp file: {fname}")
                            total_deleted += 1
                        else:
                            print(f"[ERROR] Failed to securely delete SQLite temp file: {fname}")
                            total_failed += 1
                    else:
                        os.remove(fname)
                        print(f"[SUCCESS] Deleted SQLite temp file: {fname}")
                        total_deleted += 1
                except Exception as e:
                    print(f"[ERROR] Failed to delete SQLite temp file {fname}: {e}")
                    total_failed += 1

        print("\n" + "="*60)
        print("--- Cleanup Summary ---")
        print("="*60)
        if total_failed > 0:
            print(f"🔴 FAILED to delete {total_failed} artifact(s). Please review the errors above and take manual action.")
            print(f"✅ Successfully deleted {total_deleted} artifact(s).")
        else:
            print(f"🟢 Successfully deleted {total_deleted} artifact(s).")
        print("="*60)
        print("The system should now be in a clean state.")
        print("You can now restart the program and set up a new vault.\n")

    except Exception as e:
        print(f"\n❌ An unexpected error occurred during cleanup: {e}")
        print("Please ensure all application modules are available and paths are correct.")
        import traceback
        traceback.print_exc()

def main():
    """
    Main function to run the cleanup script.
    Parses command-line arguments to verify the developer password.
    """
    if platform.system() == "Windows":
        run_as_admin()

    parser = argparse.ArgumentParser(
        description="""
        *** SecureVault Pro Developer Cleanup Tool ***
        This script completely removes all trial-related data, including hidden guardian files.
        It is for development and testing purposes ONLY.
        WARNING: This provides a clean slate and will reset the trial period entirely.
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '--password',
        required=True,
        help='The secret developer password required to run the cleanup.'
    )
    
    parser.add_argument(
        '--secure',
        action='store_true',
        help='Perform a secure deletion, overwriting files before deletion (slower but more secure).'
    )
    
    print("\n" + "="*60)
    print("*"*60)
    print("WARNING: This is a developer-only tool.")
    print("Running this will PERMANENTLY delete all trial data.")
    print("*"*60)
    print("="*60 + "\n")

    try:
        args = parser.parse_args()
        if args.password.strip() == DEV_PASSWORD:
            print("✅ Developer password accepted.\n")
            print("Starting cleanup process...")
            if args.secure:
                print("Using SECURE mode (files will be overwritten before deletion)\n")
            else:
                print("Using NORMAL mode (standard deletion)\n")
            
            clean_all_artifacts(secure_mode=args.secure)
            
            print("\n" + "="*60)
            print("Cleanup completed!")
            print("You can now restart the application.")
            print("="*60 + "\n")
        else:
            print("\n[ACCESS DENIED] ❌ Incorrect developer password.")
            print("Access denied. The password provided is incorrect.\n")
            sys.exit(1)
    except SystemExit as e:
        if e.code != 0:
            print("\nTo use this script, you must provide the correct password.")
            print(f"Example: python {sys.argv[0]} --password=YOUR_PASSWORD")
            print(f"Example with secure mode: python {sys.argv[0]} --password=YOUR_PASSWORD --secure\n")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        import traceback
        traceback.print_exc()
        
if __name__ == "__main__":
    main()
