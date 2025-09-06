import os
import sys
import platform
import json
import shutil

try:
    import winreg
except ImportError:
    winreg = None

# --- Configuration: Must match trial_manager.py and secure_file_manager.py ---
LICENSE_FILE = os.path.expanduser("~/.sv_license")
DOTFILE_PATH = os.path.expanduser("~/.sv_meta")
REGISTRY_PATH = r"Software\SecureVaultPro"
SECURE_VAULT_DIR = "secure_vault"
SETTINGS_FILE = os.path.join(SECURE_VAULT_DIR, "settings.json")
# ---

def _get_tertiary_path():
    system = platform.system()
    if system == 'Windows':
        path = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "SystemLogs")
        return os.path.join(path, "updater.log")
    elif system == 'Linux':
        path = os.path.expanduser("~/.config/systemd")
        return os.path.join(path, "user.log")
    elif system == 'Darwin':
        path = os.path.expanduser("~/Library/Application Support")
        return os.path.join(path, ".system_events.log")
    return None

TERTIARY_PATH = _get_tertiary_path()

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

    # 4. Check for tertiary file
    if TERTIARY_PATH and os.path.exists(TERTIARY_PATH):
        print(f"[+] Found Tertiary File: {TERTIARY_PATH}")
    else:
        print(f"[-] Tertiary File Not Found: {TERTIARY_PATH}")

def clean_artifacts(force=False):
    """Deletes all trial-related artifacts. Asks for confirmation unless force=True."""
    report_status()
    print("\nThis script will attempt to delete the artifacts listed above, including the entire secure_vault directory.")
    
    if not force:
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

    # 3. To be safe and clean everything, we just remove the entire secure_vault directory
    if os.path.isdir(SECURE_VAULT_DIR):
        try:
            shutil.rmtree(SECURE_VAULT_DIR)
            print(f"[+] Deleted Secure Vault Directory: {SECURE_VAULT_DIR}")
        except OSError as e:
            print(f"[!] Error deleting secure vault directory: {e}")
    
    # 4. Delete tertiary file
    if TERTIARY_PATH and os.path.exists(TERTIARY_PATH):
        try:
            os.remove(TERTIARY_PATH)
            print(f"[+] Deleted Tertiary File: {TERTIARY_PATH}")
        except OSError as e:
            print(f"[!] Error deleting tertiary file: {e}")
            
    print("\n--- Cleanup Complete ---")


def main():
    """
    Main function to run the cleanup script.
    Parses command-line arguments to either report or clean.
    """
    print("*"*60)
    print("WARNING: This script is for development and testing purposes only.")
    print("It is designed to completely remove all trial-related data.")
    print("DO NOT distribute this script with the final application.")
    print("*"*60)
    
    args = [arg.lower() for arg in sys.argv[1:]]
    
    if '--clean' in args:
        force_clean = '--force' in args
        clean_artifacts(force=force_clean)
    else:
        report_status()
        print("\nTo remove these artifacts, run with the --clean flag.")
        print(f"Example: python {sys.argv[0]} --clean")
        print("Add --force to bypass confirmation prompt.")

if __name__ == "__main__":
    main()
