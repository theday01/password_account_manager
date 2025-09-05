import os
import sys
import platform
import json

try:
    import winreg
except ImportError:
    winreg = None

# --- Configuration: Must match trial_manager.py ---
LICENSE_FILE = os.path.expanduser("~/.sv_license")
DOTFILE_PATH = os.path.expanduser("~/.sv_meta")
REGISTRY_PATH = r"Software\SecureVaultPro"
SETTINGS_FILE = "vault_settings.json"
# ---

def check_registry():
    """Checks for the existence of the registry key."""
    if platform.system() != 'Windows' or not winreg:
        return None # Not applicable
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False

def check_settings_file():
    """Checks if the 'trial_data' key exists in the settings JSON."""
    if not os.path.exists(SETTINGS_FILE):
        return False
    try:
        with open(SETTINGS_FILE, 'r') as f:
            data = json.load(f)
        return 'trial_data' in data
    except (json.JSONDecodeError, IOError):
        return False

def report_status():
    """Checks for all trial artifacts and prints a status report."""
    print("--- Trial System Status Report ---")
    
    # 1. Check OS-specific primary storage
    if platform.system() == 'Windows':
        if check_registry():
            print(f"[+] Found Registry Key: HKEY_CURRENT_USER\\{REGISTRY_PATH}")
        else:
            print(f"[-] Registry Key Not Found.")
    else: # Linux/macOS
        if os.path.exists(DOTFILE_PATH):
            print(f"[+] Found Dotfile: {DOTFILE_PATH}")
        else:
            print(f"[-] Dotfile Not Found: {DOTFILE_PATH}")

    # 2. Check license file
    if os.path.exists(LICENSE_FILE):
        print(f"[+] Found License File: {LICENSE_FILE}")
    else:
        print(f"[-] License File Not Found: {LICENSE_FILE}")
        
    # 3. Check for trial data in settings file
    if check_settings_file():
        print(f"[+] Found 'trial_data' key in: {SETTINGS_FILE}")
    else:
        print(f"[-] 'trial_data' key not found in: {SETTINGS_FILE}")

def clean_artifacts():
    """Deletes all trial-related artifacts after user confirmation."""
    report_status()
    print("\nThis script will attempt to delete the artifacts listed above.")
    
    try:
        confirm = input("Are you sure you want to proceed? (y/n): ").lower()
    except KeyboardInterrupt:
        print("\nCleanup cancelled.")
        return
        
    if confirm != 'y':
        print("Cleanup cancelled.")
        return

    print("\n--- Starting Cleanup ---")

    # 1. Delete OS-specific primary storage
    if platform.system() == 'Windows':
        if check_registry():
            try:
                # Note: This deletes the key and all its values.
                # For more complex scenarios, might need to recursively delete subkeys.
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH)
                print(f"[+] Deleted Registry Key: HKEY_CURRENT_USER\\{REGISTRY_PATH}")
            except OSError as e:
                print(f"[!] Error deleting registry key: {e}")
    else: # Linux/macOS
        if os.path.exists(DOTFILE_PATH):
            try:
                os.remove(DOTFILE_PATH)
                print(f"[+] Deleted Dotfile: {DOTFILE_PATH}")
            except OSError as e:
                print(f"[!] Error deleting dotfile: {e}")

    # 2. Delete license file
    if os.path.exists(LICENSE_FILE):
        try:
            os.remove(LICENSE_FILE)
            print(f"[+] Deleted License File: {LICENSE_FILE}")
        except OSError as e:
            print(f"[!] Error deleting license file: {e}")

    # 3. Clean settings file
    if check_settings_file():
        try:
            with open(SETTINGS_FILE, 'r') as f:
                data = json.load(f)
            if 'trial_data' in data:
                del data['trial_data']
                with open(SETTINGS_FILE, 'w') as f:
                    json.dump(data, f, indent=4)
                print(f"[+] Removed 'trial_data' key from: {SETTINGS_FILE}")
        except (IOError, json.JSONDecodeError) as e:
            print(f"[!] Error cleaning settings file: {e}")
            
    print("\n--- Cleanup Complete ---")


def main():
    """
    Main function to run the cleanup script.
    Parses command-line arguments to either report or clean.
    """
    if len(sys.argv) > 1 and sys.argv[1].lower() == '--clean':
        clean_artifacts()
    else:
        report_status()
        print("\nTo remove these artifacts, run with the --clean flag.")
        print("Example: python cleanup_trial.py --clean")

if __name__ == "__main__":
    main()
