import hashlib
import sys
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

if __name__ == "__main__":
    # The script can be run in two ways:
    # 1. Without arguments: It generates the machine ID from the current system
    #    and then generates the license key.
    # 2. With a machine_id argument: It generates the license key for the given ID.
    
    if len(sys.argv) == 2:
        # Mode 2: Generate key from provided machine_id
        machine_id_input = sys.argv[1]
        print(f"Using provided Machine ID: {machine_id_input}")
    elif len(sys.argv) == 1:
        # Mode 1: Generate machine_id from current system
        print("Generating Machine ID from current system...")
        machine_id_input = generate_machine_id()
        print(f"Detected System UUID: {get_system_uuid() or 'Not Found'}")
        print(f"Detected MAC Address: {get_mac_address() or 'Not Found'}")
        print(f"Generated Machine ID: {machine_id_input}")
    else:
        print("Usage: python generate_license.py [machine_id]")
        print("If [machine_id] is not provided, it will be generated for the current machine.")
        sys.exit(1)
        
    try:
        key = generate_license_key(machine_id_input)
        print("-" * 30)
        print(f"Generated License Key: {key}")
        print("-" * 30)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
