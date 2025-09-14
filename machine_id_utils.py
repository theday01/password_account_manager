import hashlib
import platform
import subprocess

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

def generate_machine_id():
    """
    Generates a stable machine ID primarily from the system's UUID.
    This is more stable than including the MAC address, which can change.
    """
    uuid = get_system_uuid()
    
    # If UUID is not available, fall back to a combination of system info.
    # This is less ideal but provides a fallback.
    if not uuid:
        system_info = f"{platform.system()}-{platform.node()}-{platform.architecture()}"
        return hashlib.sha256(system_info.encode()).hexdigest()
        
    return hashlib.sha256(uuid.encode()).hexdigest()
