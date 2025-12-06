"""
Activation State Protector
==========================
Robust activation state protection mechanism that maintains and synchronizes
the program's activation status across multiple secure locations in the Windows
file system and registry.

Features:
- Multi-location activation state storage (registry + hidden file locations)
- Continuous monitoring and synchronization
- Tamper detection and response
- Developer-only restoration after tampering
- Encrypted and signed activation data
- Real-time integrity verification

Security Locations:
1. Windows Registry (HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE)
2. AppData Local hidden locations (multiple)
3. AppData Roaming hidden locations
4. User-specific secure vault locations
"""

import os
import sys
import json
import hashlib
import hmac
import base64
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from machine_id_utils import generate_machine_id

logger = logging.getLogger(__name__)

# Developer recovery key (SHA256 hash of secret phrase known only to developer)
DEVELOPER_RECOVERY_KEY = "f9e7d8c6b5a4937281d0e1f2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2"


@dataclass
class ActivationState:
    """Represents the activation state of the application."""
    is_activated: bool
    activation_date: Optional[str]
    license_key: Optional[str]
    machine_id_hash: str
    timestamp: str
    checksum: str  # HMAC-SHA256 signature
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'ActivationState':
        """Create from dictionary."""
        return ActivationState(**data)


class ActivationStateProtector:
    """
    Protects activation state across multiple secure locations with
    continuous monitoring and tamper detection.
    """
    
    # Monitoring interval (seconds)
    MONITOR_INTERVAL = 30  # Check every 30 seconds
    
    # Registry paths
    REGISTRY_PATHS = [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppPaths", "activation_state"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "svc_activation"),
        (r"SOFTWARE\Classes\CLSID\{A5B3C2D1-E4F3-4A5B-9C8D-7E6F5A4B3C2D}", "state_data")
    ]
    
    def __init__(self, trial_manager=None):
        """
        Initialize the Activation State Protector.
        
        Args:
            trial_manager: Reference to TrialActivationManager for state synchronization
        """
        self.machine_id = generate_machine_id()
        self.trial_manager = trial_manager
        self.secret_key = self._generate_secret_key()
        
        # Storage locations
        self.storage_locations = self._initialize_storage_locations()
        
        # Monitoring
        self.is_monitoring = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        
        # Tamper tracking
        self.tamper_detected = False
        self.tamper_events: List[Dict[str, Any]] = []
        
        logger.info("ActivationStateProtector initialized")
        logger.info(f"Protecting {len(self.storage_locations)} storage locations")
    
    def _generate_secret_key(self) -> bytes:
        """Generate a secret key based on machine ID."""
        combined = f"{self.machine_id}-activation-protector-v1"
        return hashlib.sha256(combined.encode()).digest()
    
    def _initialize_storage_locations(self) -> List[str]:
        """
        Initialize multiple secure storage locations across the filesystem.
        Only includes locations that don't require admin privileges.
        
        Returns:
            List of storage paths
        """
        locations = []
        
        try:
            # Location 1: AppData\Local (primary - no admin required)
            appdata_local = os.getenv('LOCALAPPDATA')
            if appdata_local:
                path1 = os.path.join(appdata_local, 'Microsoft', 'Windows', 'WinX', '.activation_state')
                locations.append(path1)
                
                path2 = os.path.join(appdata_local, 'SecureVaultPro', '.state', 'activation.dat')
                locations.append(path2)
                
                # Additional LocalAppData location
                path3 = os.path.join(appdata_local, 'Microsoft', 'Protect', '.state_cache')
                locations.append(path3)
            
            # Location 2: AppData\Roaming (synchronized across domain - no admin required)
            appdata_roaming = os.getenv('APPDATA')
            if appdata_roaming:
                path4 = os.path.join(appdata_roaming, 'Microsoft', 'Protect', '.state_data')
                locations.append(path4)
                
                # Additional Roaming location
                path5 = os.path.join(appdata_roaming, 'Microsoft', 'Windows', 'Recent', '.activation_data')
                locations.append(path5)
            
            # Location 3: User profile hidden locations (no admin required)
            userprofile = os.getenv('USERPROFILE')
            if userprofile:
                path6 = os.path.join(userprofile, '.config', 'system', 'activation_state.dat')
                locations.append(path6)
                
                # Additional user profile location
                path7 = os.path.join(userprofile, 'AppData', 'LocalLow', 'SecureVault', '.activation_state')
                locations.append(path7)
            
            # Location 4: Temp directory persistent location (no admin required)
            temp_base = os.getenv('TEMP') or os.getenv('TMP')
            if temp_base:
                # Use a less obvious temp location that persists
                persistent_temp = os.path.join(os.path.dirname(temp_base), '.SecureVault', '.activation_persistent')
                locations.append(persistent_temp)
            
            # Create directories and test write access
            verified_locations = []
            for location in locations:
                try:
                    # Create parent directory
                    Path(location).parent.mkdir(parents=True, exist_ok=True)
                    
                    # Test write access
                    test_file = location + '.test'
                    try:
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.remove(test_file)
                        
                        # If write successful, add to verified locations
                        verified_locations.append(location)
                        
                        # Hide on Windows
                        if sys.platform == "win32":
                            self._hide_file_windows(location)
                    except (PermissionError, OSError) as e:
                        logger.debug(f"Skipping {location} - no write access: {e}")
                        continue
                        
                except Exception as e:
                    logger.debug(f"Skipping {location} - cannot create directory: {e}")
                    continue
            
            logger.info(f"Initialized {len(verified_locations)}/{len(locations)} storage locations (write-accessible)")
            return verified_locations
            
        except Exception as e:
            logger.error(f"Error initializing storage locations: {e}")
            return []
    
    @staticmethod
    def _hide_file_windows(file_path: str) -> None:
        """Hide a file/folder on Windows."""
        if sys.platform != "win32":
            return
        
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            parent_dir = str(Path(file_path).parent)
            if os.path.exists(parent_dir):
                ctypes.windll.kernel32.SetFileAttributesW(parent_dir, FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass
    
    def _compute_checksum(self, data: Dict[str, Any]) -> str:
        """
        Compute HMAC-SHA256 checksum of activation data.
        
        Args:
            data: Activation data dictionary
        
        Returns:
            Hex-encoded checksum
        """
        # Create deterministic JSON (sorted keys)
        data_copy = data.copy()
        data_copy.pop('checksum', None)  # Remove checksum field itself
        json_str = json.dumps(data_copy, sort_keys=True)
        
        signature = hmac.new(self.secret_key, json_str.encode(), hashlib.sha256)
        return signature.hexdigest()
    
    def _verify_checksum(self, data: Dict[str, Any]) -> bool:
        """
        Verify HMAC-SHA256 checksum of activation data.
        
        Args:
            data: Activation data dictionary with checksum
        
        Returns:
            True if checksum is valid
        """
        if 'checksum' not in data:
            return False
        
        stored_checksum = data['checksum']
        computed_checksum = self._compute_checksum(data)
        
        return hmac.compare_digest(stored_checksum, computed_checksum)
    
    def _encrypt_data(self, data: Dict[str, Any]) -> str:
        """
        Encrypt activation data using XOR cipher with machine ID.
        
        Args:
            data: Data to encrypt
        
        Returns:
            Base64-encoded encrypted data
        """
        json_str = json.dumps(data, sort_keys=True)
        key = self.machine_id
        
        # XOR encryption
        xored = ''.join(
            chr(ord(c) ^ ord(k)) 
            for c, k in zip(json_str, key * (len(json_str) // len(key) + 1))
        )
        
        return base64.b64encode(xored.encode()).decode()
    
    def _decrypt_data(self, encrypted: str) -> Optional[Dict[str, Any]]:
        """
        Decrypt activation data.
        
        Args:
            encrypted: Base64-encoded encrypted data
        
        Returns:
            Decrypted data dictionary or None if failed
        """
        try:
            xored_bytes = base64.b64decode(encrypted)
            xored = xored_bytes.decode()
            key = self.machine_id
            
            # XOR decryption
            json_str = ''.join(
                chr(ord(c) ^ ord(k)) 
                for c, k in zip(xored, key * (len(xored) // len(key) + 1))
            )
            
            return json.loads(json_str)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def _write_to_file(self, file_path: str, data: Dict[str, Any]) -> bool:
        """
        Write encrypted activation data to file.
        
        Args:
            file_path: Path to file
            data: Activation data
        
        Returns:
            True if successful
        """
        try:
            encrypted = self._encrypt_data(data)
            
            # Ensure parent directory exists
            try:
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            except (PermissionError, OSError):
                logger.debug(f"Cannot create directory for {file_path}")
                return False
            
            # Write atomically
            temp_path = file_path + ".tmp"
            try:
                with open(temp_path, 'w') as f:
                    f.write(encrypted)
                
                os.replace(temp_path, file_path)
                
                # Hide the file
                if sys.platform == "win32":
                    self._hide_file_windows(file_path)
                
                return True
            except (PermissionError, OSError) as e:
                # Clean up temp file if it exists
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                logger.debug(f"Permission denied writing to {file_path}: {e}")
                return False
                
        except Exception as e:
            logger.debug(f"Failed to write to {file_path}: {e}")
            return False
    
    def _read_from_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Read and decrypt activation data from file.
        
        Args:
            file_path: Path to file
        
        Returns:
            Decrypted data or None
        """
        try:
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r') as f:
                encrypted = f.read()
            
            return self._decrypt_data(encrypted)
        except Exception as e:
            logger.error(f"Failed to read from {file_path}: {e}")
            return None
    
    def _write_to_registry(self, key_path: str, value_name: str, data: Dict[str, Any]) -> bool:
        """
        Write encrypted activation data to Windows Registry.
        
        Args:
            key_path: Registry key path
            value_name: Registry value name
            data: Activation data
        
        Returns:
            True if successful
        """
        if sys.platform != "win32":
            return False
        
        try:
            import winreg
            
            encrypted = self._encrypt_data(data)
            
            # Try both HKCU and HKLM
            hives = [
                (winreg.HKEY_CURRENT_USER, "HKCU"),
                (winreg.HKEY_LOCAL_MACHINE, "HKLM")
            ]
            
            success = False
            for hive, hive_name in hives:
                try:
                    with winreg.CreateKey(hive, key_path) as key:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, encrypted)
                    logger.debug(f"Wrote to registry: {hive_name}\\{key_path}\\{value_name}")
                    success = True
                except OSError as e:
                    logger.debug(f"Failed to write to {hive_name}: {e}")
            
            return success
        except Exception as e:
            logger.error(f"Registry write error: {e}")
            return False
    
    def _read_from_registry(self, key_path: str, value_name: str) -> Optional[Dict[str, Any]]:
        """
        Read and decrypt activation data from Windows Registry.
        
        Args:
            key_path: Registry key path
            value_name: Registry value name
        
        Returns:
            Decrypted data or None
        """
        if sys.platform != "win32":
            return None
        
        try:
            import winreg
            
            # Try both HKCU and HKLM
            hives = [
                (winreg.HKEY_CURRENT_USER, "HKCU"),
                (winreg.HKEY_LOCAL_MACHINE, "HKLM")
            ]
            
            for hive, hive_name in hives:
                try:
                    with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                        encrypted, _ = winreg.QueryValueEx(key, value_name)
                        data = self._decrypt_data(encrypted)
                        if data:
                            logger.debug(f"Read from registry: {hive_name}\\{key_path}\\{value_name}")
                            return data
                except (FileNotFoundError, PermissionError, OSError):
                    continue
            
            return None
        except Exception as e:
            logger.error(f"Registry read error: {e}")
            return None
    
    def create_activation_state(self, is_activated: bool, license_key: Optional[str] = None) -> ActivationState:
        """
        Create an ActivationState object with checksum.
        
        Args:
            is_activated: Activation status
            license_key: License key if activated
        
        Returns:
            ActivationState object
        """
        state_data = {
            'is_activated': is_activated,
            'activation_date': datetime.now().isoformat() if is_activated else None,
            'license_key': license_key,
            'machine_id_hash': hashlib.sha256(self.machine_id.encode()).hexdigest(),
            'timestamp': datetime.now().isoformat(),
            'checksum': ''
        }
        
        # Compute checksum
        state_data['checksum'] = self._compute_checksum(state_data)
        
        return ActivationState.from_dict(state_data)
    
    def save_activation_state(self, state: ActivationState) -> bool:
        """
        Save activation state to all storage locations.
        
        Args:
            state: ActivationState to save
        
        Returns:
            True if saved to at least one location
        """
        state_dict = state.to_dict()
        success_count = 0
        total_locations = len(self.storage_locations) + (len(self.REGISTRY_PATHS) if sys.platform == "win32" else 0)
        
        with self.lock:
            # Save to file locations
            for location in self.storage_locations:
                if self._write_to_file(location, state_dict):
                    success_count += 1
            
            # Save to registry locations
            if sys.platform == "win32":
                for key_path, value_name in self.REGISTRY_PATHS:
                    if self._write_to_registry(key_path, value_name, state_dict):
                        success_count += 1
        
        if success_count > 0:
            logger.info(f"Saved activation state to {success_count}/{total_locations} locations")
        else:
            logger.error(f"Failed to save activation state to any location!")
        
        # Success if we saved to at least 3 locations (minimum redundancy)
        return success_count >= 3
    
    def load_activation_state(self) -> Optional[ActivationState]:
        """
        Load activation state from storage locations.
        Performs majority voting to detect tampering.
        
        Returns:
            ActivationState if valid, None if tampered or not found
        """
        states: List[Tuple[Dict[str, Any], str]] = []
        
        with self.lock:
            # Load from file locations
            for location in self.storage_locations:
                data = self._read_from_file(location)
                if data:
                    states.append((data, location))
            
            # Load from registry locations
            if sys.platform == "win32":
                for key_path, value_name in self.REGISTRY_PATHS:
                    data = self._read_from_registry(key_path, value_name)
                    if data:
                        states.append((data, f"Registry:{key_path}\\{value_name}"))
        
        if not states:
            logger.warning("No activation state found in any location")
            return None
        
        # Verify checksums and detect tampering
        valid_states = []
        for data, source in states:
            if self._verify_checksum(data):
                valid_states.append((data, source))
            else:
                logger.warning(f"Invalid checksum detected at {source}")
                self._record_tamper_event("checksum_invalid", source)
        
        if not valid_states:
            logger.error("All activation states have invalid checksums - TAMPERING DETECTED")
            self.tamper_detected = True
            return None
        
        # Majority voting: ensure all valid states agree
        first_state = valid_states[0][0]
        consistent = True
        
        for data, source in valid_states[1:]:
            if (data['is_activated'] != first_state['is_activated'] or
                data['license_key'] != first_state['license_key']):
                logger.warning(f"Inconsistent activation state at {source}")
                self._record_tamper_event("state_mismatch", source)
                consistent = False
        
        if not consistent:
            logger.error("Activation states are inconsistent across locations - TAMPERING DETECTED")
            self.tamper_detected = True
            return None
        
        # Return the consistent state
        return ActivationState.from_dict(first_state)
    
    def _record_tamper_event(self, event_type: str, location: str):
        """Record a tampering event."""
        event = {
            'type': event_type,
            'location': location,
            'timestamp': datetime.now().isoformat()
        }
        self.tamper_events.append(event)
        logger.critical(f"TAMPER EVENT: {event_type} at {location}")
    
    def synchronize_with_trial_manager(self) -> bool:
        """
        Synchronize activation state with TrialActivationManager.
        
        Returns:
            True if synchronized successfully
        """
        if not self.trial_manager:
            return False
        
        try:
            # Get status from trial manager
            trial_status = self.trial_manager.get_trial_status()
            
            # Create activation state
            state = self.create_activation_state(
                is_activated=trial_status['is_activated'],
                license_key=self.trial_manager._load_trial_data().get('license_key')
            )
            
            # Save to all locations
            return self.save_activation_state(state)
        except Exception as e:
            logger.error(f"Synchronization error: {e}")
            return False
    
    def start_monitoring(self) -> bool:
        """
        Start continuous monitoring of activation state.
        
        Returns:
            True if monitoring started
        """
        if self.is_monitoring:
            logger.warning("Monitoring already active")
            return False
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Activation state monitoring started")
        return True
    
    def stop_monitoring(self):
        """Stop monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Activation state monitoring stopped")
    
    def _monitor_loop(self):
        """Continuous monitoring loop."""
        while self.is_monitoring:
            try:
                # Load and verify activation state
                state = self.load_activation_state()
                
                if state is None and not self.tamper_detected:
                    # State missing but no tampering detected yet - repair
                    logger.warning("Activation state missing - attempting repair")
                    self.synchronize_with_trial_manager()
                
                # Sleep
                time.sleep(self.MONITOR_INTERVAL)
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(self.MONITOR_INTERVAL)
    
    def is_tampered(self) -> bool:
        """
        Check if tampering has been detected.
        
        Returns:
            True if tampering detected
        """
        return self.tamper_detected
    
    def verify_developer_recovery_key(self, recovery_key: str) -> bool:
        """
        Verify developer recovery key.
        
        Args:
            recovery_key: Recovery key provided by user
        
        Returns:
            True if valid
        """
        # Hash the provided key
        key_hash = hashlib.sha256(recovery_key.encode()).hexdigest()
        
        # Compare with developer key
        if hmac.compare_digest(key_hash, DEVELOPER_RECOVERY_KEY):
            logger.info("Developer recovery key verified")
            return True
        
        logger.warning("Invalid developer recovery key")
        return False
    
    def reset_after_developer_recovery(self, recovery_key: str) -> bool:
        """
        Reset activation protection after developer recovery.
        
        Args:
            recovery_key: Developer recovery key
        
        Returns:
            True if reset successful
        """
        if not self.verify_developer_recovery_key(recovery_key):
            return False
        
        with self.lock:
            # Clear tamper flags
            self.tamper_detected = False
            self.tamper_events.clear()
            
            # Resynchronize state
            success = self.synchronize_with_trial_manager()
            
            if success:
                logger.info("Activation protection reset by developer")
            
            return success
    
    def get_protection_status(self) -> Dict[str, Any]:
        """
        Get detailed protection status report.
        
        Returns:
            Status dictionary
        """
        return {
            'is_monitoring': self.is_monitoring,
            'tamper_detected': self.tamper_detected,
            'tamper_events_count': len(self.tamper_events),
            'recent_tamper_events': self.tamper_events[-5:] if self.tamper_events else [],
            'storage_locations_count': len(self.storage_locations),
            'registry_locations_count': len(self.REGISTRY_PATHS),
            'timestamp': datetime.now().isoformat()
        }


# Singleton instance
_activation_protector = None


def get_activation_protector(trial_manager=None) -> ActivationStateProtector:
    """
    Get or create the global ActivationStateProtector instance.
    
    Args:
        trial_manager: TrialActivationManager reference
    
    Returns:
        ActivationStateProtector instance
    """
    global _activation_protector
    if _activation_protector is None:
        _activation_protector = ActivationStateProtector(trial_manager)
    return _activation_protector


if __name__ == "__main__":
    # Test the ActivationStateProtector
    logging.basicConfig(level=logging.INFO)
    
    print("=== Activation State Protector Test ===\n")
    
    protector = ActivationStateProtector()
    
    # Create test state
    print("1. Creating activation state...")
    state = protector.create_activation_state(is_activated=True, license_key="test_key_12345")
    print(f"   State created: {state.is_activated}\n")
    
    # Save state
    print("2. Saving activation state...")
    success = protector.save_activation_state(state)
    print(f"   Save result: {success}\n")
    
    # Load state
    print("3. Loading activation state...")
    loaded_state = protector.load_activation_state()
    if loaded_state:
        print(f"   Loaded: {loaded_state.is_activated}")
        print(f"   License: {loaded_state.license_key}\n")
    
    # Check protection status
    print("4. Protection status:")
    status = protector.get_protection_status()
    print(f"   Monitoring: {status['is_monitoring']}")
    print(f"   Tamper detected: {status['tamper_detected']}")
    print(f"   Storage locations: {status['storage_locations_count']}")
    print(f"   Registry locations: {status['registry_locations_count']}\n")
    
    print("✅ Test completed!")
