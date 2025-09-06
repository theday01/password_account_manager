import hashlib
import sys

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
    if len(sys.argv) != 2:
        print("Usage: python generate_license.py <machine_id>")
        sys.exit(1)
        
    machine_id_input = sys.argv[1]
    try:
        key = generate_license_key(machine_id_input)
        print(f"Machine ID: {machine_id_input}")
        print(f"Generated License Key: {key}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
