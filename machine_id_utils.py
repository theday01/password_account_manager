import platform
import subprocess
import hashlib
import re

def _get_windows_machine_id():
    """
    Retrieves a unique and stable machine ID on Windows.
    Uses the motherboard serial number, which is very unlikely to change.
    """
    try:
        result = subprocess.run(
            ["wmic", "baseboard", "get", "serialnumber"],
            capture_output=True,
            text=True,
            check=True
        )
        serial = result.stdout.strip().split("\n")[-1]
        return serial if serial and serial != "Default string" else None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def _get_linux_machine_id():
    """
    Retrieves a unique and stable machine ID on Linux.
    Tries to read the machine-id file, which is standard on modern Linux systems.
    """
    try:
        with open("/etc/machine-id", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

def _get_macos_machine_id():
    """
    Retrieves a unique and stable machine ID on macOS.
    Uses the IOPlatformUUID, which is a hardware-based identifier.
    """
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.split("\n"):
            if "IOPlatformUUID" in line:
                return line.split("=")[-1].strip().replace('"', '')
        return None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def generate_machine_id():
    """
    Generates a unique and stable machine identifier based on the OS.
    The ID is then hashed to create a consistent, anonymous identifier.
    """
    os_type = platform.system()
    machine_id = None

    if os_type == "Windows":
        machine_id = _get_windows_machine_id()
    elif os_type == "Linux":
        machine_id = _get_linux_machine_id()
    elif os_type == "Darwin":
        machine_id = _get_macos_machine_id()

    # Fallback if the primary method fails
    if not machine_id:
        # A less stable but universal fallback
        try:
            import uuid
            machine_id = str(uuid.getnode())
        except Exception:
            # Absolute fallback
            machine_id = "default_machine_id_fallback"
            
    # Hash the identifier to ensure it's a consistent format and anonymous
    return hashlib.sha256(machine_id.encode()).hexdigest()
