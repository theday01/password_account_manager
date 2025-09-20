import os
import sys
import argparse
import platform
import hashlib

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
            "Observer File(s)": {"prefix": "sv-observer-", "dir": os.path.dirname(observer.observer_path)},
            "License File(s)": {"prefix": "sv-license-" if platform.system() == "Windows" else ".sv-license-", "dir": os.path.dirname(trial_manager.LICENSE_FILE)}
        }
        deleted, failed = find_and_delete_files(search_locations, secure_mode=secure_mode)
        total_deleted += deleted
        total_failed += failed

        # Clean registry-based artifacts on Windows
        if platform.system() == "Windows":
            deleted, failed = clean_registry_artifacts()
            total_deleted += deleted
            total_failed += failed

        print("\n--- Cleanup Summary ---")
        if total_failed > 0:
            print(f"🔴 FAILED to delete {total_failed} artifact(s). Please review the errors above and take manual action.")
        else:
            print(f"🟢 Successfully deleted {total_deleted} artifact(s).")
        print("The system should now be in a clean state.")

    except Exception as e:
        print(f"\nAn unexpected error occurred during cleanup: {e}")
        print("Please ensure all application modules are available and paths are correct.")

def main():
    """
    Main function to run the cleanup script.
    Parses command-line arguments to verify the developer password.
    """
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
        help='Perform a secure scan, overwriting files before deletion.'
    )
    
    print("*"*60)
    print("WARNING: This is a developer-only tool.")
    print("Running this will permanently delete all trial data.")
    print("*"*60)

    try:
        args = parser.parse_args()
        if args.password.strip() == DEV_PASSWORD:
            print("\nDeveloper password accepted.")
            clean_all_artifacts(secure_mode=args.secure)
        else:
            print("\n[ACCESS DENIED] Incorrect developer password.")
            sys.exit(1)
    except SystemExit as e:
        if e.code != 0:
             print("\nTo use this script, you must provide the correct password.")
             print(f"Example: python {sys.argv[0]} --password={DEV_PASSWORD}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
