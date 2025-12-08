import hashlib
import sys
import tkinter as tk
from tkinter import messagebox
from machine_id_utils import get_mac_address, get_system_uuid, generate_machine_id

# This is a secret salt that should be kept private by the developer.
# It should be a long, random string.
SECRET_SALT = "a-very-secret-and-long-salt-that-is-hard-to-guess"

def generate_license_key(machine_id: str) -> str:
    """
    Generates a license key by hashing the machine ID with a secret salt.
    """
    if not machine_id:
        raise ValueError("Machine ID cannot be empty.")
    
    salted_id = machine_id + SECRET_SALT
    license_key = hashlib.sha256(salted_id.encode()).hexdigest()
    return license_key

def run_gui():
    """
    Launches a simple GUI for the vendor to generate license keys.
    """
    def on_generate():
        m_id = entry_machine_id.get().strip()
        if not m_id:
            messagebox.showwarning("Input Error", "Please enter a Machine ID.")
            return
        
        try:
            key = generate_license_key(m_id)
            entry_license_key.config(state='normal') # Enable writing
            entry_license_key.delete(0, tk.END)
            entry_license_key.insert(0, key)
            entry_license_key.config(state='readonly') # Make read-only again
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def copy_to_clipboard():
        key = entry_license_key.get()
        if key:
            root.clipboard_clear()
            root.clipboard_append(key)
            messagebox.showinfo("Copied", "License key copied to clipboard!")

    # --- GUI Setup ---
    root = tk.Tk()
    root.title("License Generator")
    root.geometry("500x250")
    root.resizable(False, False)

    # Input Section
    lbl_instruction = tk.Label(root, text="Enter User's Machine ID:", font=("Arial", 10, "bold"))
    lbl_instruction.pack(pady=(20, 5))

    entry_machine_id = tk.Entry(root, width=50, font=("Courier", 10))
    entry_machine_id.pack(pady=5)

    # Action Button
    btn_generate = tk.Button(root, text="Generate Activation Code", command=on_generate, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
    btn_generate.pack(pady=15)

    # Output Section
    lbl_result = tk.Label(root, text="Generated Activation Code:", font=("Arial", 10, "bold"))
    lbl_result.pack(pady=(10, 5))

    entry_license_key = tk.Entry(root, width=50, font=("Courier", 10), state='readonly')
    entry_license_key.pack(pady=5)
    
    # Footer / Copy
    btn_copy = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
    btn_copy.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    # The script can be run in three ways:
    # 1. Argument 'gui': Launches the graphical interface for the vendor.
    # 2. Argument [machine_id]: Generates key for that specific ID (CLI mode).
    # 3. No arguments: Generates ID for the *current* system (Client mode).

    if len(sys.argv) > 1 and sys.argv[1].lower() == 'gui':
        run_gui()
    
    elif len(sys.argv) == 2:
        # Mode 2: Generate key from provided machine_id via CLI
        machine_id_input = sys.argv[1]
        print(f"Using provided Machine ID: {machine_id_input}")
        try:
            key = generate_license_key(machine_id_input)
            print("-" * 30)
            print(f"Generated License Key: {key}")
            print("-" * 30)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif len(sys.argv) == 1:
        # Mode 1: Generate machine_id from current system
        print("Generating Machine ID from current system...")
        machine_id_input = generate_machine_id()
        print(f"Detected System UUID: {get_system_uuid() or 'Not Found'}")
        print(f"Detected MAC Address: {get_mac_address() or 'Not Found'}")
        print(f"Generated Machine ID: {machine_id_input}")
        
        # Optionally generate the key for the local machine (for testing)
        try:
            key = generate_license_key(machine_id_input)
            print("-" * 30)
            print(f"Generated License Key: {key}")
            print("-" * 30)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
            
    else:
        print("Usage:")
        print("  1. python generate_license.py gui          -> Launch GUI")
        print("  2. python generate_license.py [machine_id] -> Generate Key for ID")
        print("  3. python generate_license.py              -> Generate ID for this PC")
        sys.exit(1)