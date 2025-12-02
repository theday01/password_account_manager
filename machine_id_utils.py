import hashlib
import platform
import subprocess
import os
import uuid

def get_mac_address():
    """
    Retrieves the MAC address of the primary network interface.
    """
    try:
        system = platform.system()
        if system == 'Windows':
            command = "wmic path win32_networkadapter where \"PhysicalAdapter=True and NetConnectionStatus is not null\" get MACAddress"
            output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
            mac_addresses = [line.strip() for line in output.split('\n') if ':' in line]
            if mac_addresses:
                return mac_addresses[0]
        elif system == 'Linux':
            try:
                for iface in ['eth0', 'enp0s3', 'enp3s0', 'wlan0']:
                    with open(f'/sys/class/net/{iface}/address', 'r') as f:
                        mac = f.read().strip()
                        if mac: return mac
            except FileNotFoundError:
                command = "ip link"
                output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
                lines = output.split('\n')
                for i, line in enumerate(lines):
                    if "state UP" in line and i + 1 < len(lines):
                        next_line = lines[i+1]
                        if "link/ether" in next_line:
                            return next_line.split()[1]
        elif system == 'Darwin': # macOS
            command = "ifconfig en0 | awk '/ether/{print $2}'"
            output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
            if output.strip():
                return output.strip()
    except Exception:
        return None
    return None

def get_system_uuid():
    """
    Retrieves the system's UUID.
    """
    try:
        system = platform.system()
        if system == 'Windows':
            command = "wmic csproduct get uuid"
            output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
            return output.split('\n')[1].strip()
        elif system == 'Linux':
            try:
                with open('/sys/class/dmi/id/product_uuid', 'r') as f:
                    return f.read().strip()
            except FileNotFoundError:
                with open('/var/lib/dbus/machine-id', 'r') as f:
                    return f.read().strip()
        elif system == 'Darwin': # macOS
            command = "ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'"
            output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
            return output.strip()
    except Exception:
        return None
    return None

def get_ram_info():
    """
    Retrieves RAM serial numbers.
    """
    try:
        system = platform.system()
        if system == 'Windows':
            command = "wmic memorychip get SerialNumber"
            output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
            serial_numbers = [line.strip() for line in output.split('\n') if line.strip() and "SerialNumber" not in line]
            return "".join(sorted(serial_numbers))
        elif system == 'Linux':
            try:
                command = "dmidecode -t memory | grep 'Serial Number:'"
                output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
                serial_numbers = [line.split(':')[1].strip() for line in output.split('\n') if "Serial Number:" in line]
                # Filter out "Not Specified" or similar placeholders
                serial_numbers = [sn for sn in serial_numbers if sn and "Not Specified" not in sn and "Unknown" not in sn]
                return "".join(sorted(serial_numbers))
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback if dmidecode is not available or fails
                return None
        elif system == 'Darwin': # macOS
            command = "system_profiler SPMemoryDataType | grep 'Serial Number'"
            output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
            serial_numbers = [line.split(':')[1].strip() for line in output.split('\n') if "Serial Number:" in line]
            return "".join(sorted(serial_numbers))
    except Exception:
        return None
    return None

def generate_machine_id():
    """
    Generates a stable machine ID from a combination of hardware identifiers.
    This is more stable and secure than relying on a single identifier.
    """
    # Use placeholders for unavailable information to ensure a consistent format
    mac_address = get_mac_address() or "no_mac"
    ram_info = get_ram_info() or "no_ram"
    uuid = get_system_uuid() or "no_uuid"

    # Combine all the info, using a separator to prevent collisions
    machine_info = f"{mac_address}|{ram_info}|{uuid}"

    # Fallback for cases where no hardware identifiers can be retrieved
    if machine_info == "no_mac|no_ram|no_uuid":
        # Persist a generated stable id to the user's profile so it survives restarts
        home_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        store_path = os.path.join(home_dir, ".sv_machine_id")

        try:
            if os.path.exists(store_path):
                with open(store_path, 'r') as f:
                    stored = f.read().strip()
                    if stored:
                        return hashlib.sha256(stored.encode()).hexdigest()
            # Generate and persist a fallback id
            fallback = uuid.uuid4().hex
            with open(store_path, 'w') as f:
                f.write(fallback)
            return hashlib.sha256(fallback.encode()).hexdigest()
        except Exception:
            # As a last resort, fall back to hashing volatile system info
            system_info = f"{platform.system()}-{platform.node()}-{platform.architecture()}"
            return hashlib.sha256(system_info.encode()).hexdigest()

    return hashlib.sha256(machine_info.encode()).hexdigest()
