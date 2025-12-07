"""
Enhanced Trial Period and Activation Manager with Advanced Anti-Tampering
===========================================================================
Multi-layered protection against trial manipulation and unauthorized access.

Security Features:
- Multiple redundant encrypted storage locations
- Cryptographic signing (HMAC-SHA256) of all trial data
- Real-time file monitoring and integrity verification
- Anti-rollback protection using system time tracking
- Permanent lockout on tampering detection
- Tripwire files for unauthorized access detection
- Machine-specific encryption keys
- Cross-verification between multiple data sources
"""

import os
import json
import hashlib
import hmac
import base64
import logging
import threading
import time
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple, Optional, Dict, List
from machine_id_utils import generate_machine_id

logger = logging.getLogger(__name__)

# Try to import watchdog for real-time monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileDeletedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("Watchdog not available - real-time monitoring disabled")


class TrialStateCorruptionError(Exception):
    """Raised when trial state is corrupted or tampered with."""
    pass


class TrialTamperingDetectedError(Exception):
    """Raised when tampering is detected - permanent lockout."""
    pass


class TrialMonitorEventHandler(FileSystemEventHandler):
    """Monitors trial state files for unauthorized modifications."""
    
    def __init__(self, trial_manager):
        self.trial_manager = trial_manager
        self.last_alert = 0
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        # Check if this is a trial state file
        if any(str(loc) in event.src_path for loc in self.trial_manager.storage_locations):
            current_time = time.time()
            # Rate limit alerts (max once per 5 seconds)
            if current_time - self.last_alert > 5:
                logger.critical(f"TAMPERING DETECTED: Trial state file modified: {event.src_path}")
                self.trial_manager._handle_tampering_detected("file_modification", event.src_path)
                self.last_alert = current_time
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        
        if any(str(loc) in event.src_path for loc in self.trial_manager.storage_locations):
            logger.critical(f"TAMPERING DETECTED: Trial state file deleted: {event.src_path}")
            self.trial_manager._handle_tampering_detected("file_deletion", event.src_path)


class EnhancedTrialActivationManager:
    """
    Enhanced trial and activation manager with multi-layered anti-tampering.
    
    Protection Layers:
    1. Multiple encrypted storage locations
    2. Cryptographic signing with HMAC-SHA256
    3. Real-time file monitoring
    4. Anti-rollback protection
    5. Tripwire files
    6. Cross-verification
    7. Permanent lockout on tampering
    """
    
    # Trial configuration
    TRIAL_DAYS = 7
    SECRET_SALT = "a-very-secret-and-long-salt-that-is-hard-to-guess"
    
    # Security configuration
    VERIFICATION_INTERVAL = 30  # Check integrity every 30 seconds
    MAX_TIME_DRIFT = 300  # Allow 5 minutes of system time drift
    
    def __init__(self):
        """Initialize the Enhanced Trial Activation Manager."""
        self.machine_id = generate_machine_id()
        self.secret_key = self._generate_secret_key()
        
        # Initialize multiple storage locations
        self.storage_locations = self._initialize_storage_locations()
        
        # Tripwire files (detect unauthorized access attempts)
        self.tripwire_locations = self._initialize_tripwire_files()
        
        # Monitoring
        self.is_monitoring = False
        self.monitor_thread = None
        self.file_observer = None
        self.lock = threading.Lock()
        
        # Tampering tracking
        self.tampering_detected = False
        self.tampering_events = []
        self.permanent_lockout = False
        
        # Last known good timestamp (for anti-rollback)
        self.last_known_timestamp = None
        
        logger.info("EnhancedTrialActivationManager initialized")
        logger.info(f"Storage locations: {len(self.storage_locations)}")
        logger.info(f"Tripwire locations: {len(self.tripwire_locations)}")
    
    def _generate_secret_key(self) -> bytes:
        """Generate machine-specific secret key for encryption."""
        combined = f"{self.machine_id}-trial-protection-v2-{self.SECRET_SALT}"
        return hashlib.sha256(combined.encode()).digest()
    
    def _initialize_storage_locations(self) -> List[Path]:
        """
        Initialize multiple redundant storage locations for trial state.
        
        Returns:
            List of storage paths
        """
        locations = []
        
        try:
            if os.name == 'nt':  # Windows
                base_paths = [
                    os.path.join(os.getenv('LOCALAPPDATA'), 'SecureVaultPro'),
                    os.path.join(os.getenv('APPDATA'), 'SecureVaultPro'),
                    os.path.join(os.getenv('PROGRAMDATA'), 'SecureVaultPro'),
                    os.path.join(os.getenv('TEMP'), '.SecureVaultPro'),
                ]
            else:  # Unix-like
                base_paths = [
                    os.path.expanduser('~/.local/share/securevaultpro'),
                    os.path.expanduser('~/.config/securevaultpro'),
                    '/var/lib/securevaultpro',
                    '/tmp/.securevaultpro',
                ]
            
            # Create multiple hidden trial state files in each location
            for base_path in base_paths:
                try:
                    base = Path(base_path)
                    base.mkdir(parents=True, exist_ok=True)
                    
                    # Test write access
                    test_file = base / '.test'
                    try:
                        test_file.write_text('test')
                        test_file.unlink()
                        
                        # Add multiple files in this location
                        locations.append(base / '.trial_state')
                        locations.append(base / '.trial_backup')
                        locations.append(base / hashlib.md5(self.machine_id.encode()).hexdigest()[:16])
                    except (PermissionError, OSError):
                        continue
                except Exception as e:
                    logger.debug(f"Skipping {base_path}: {e}")
                    continue
            
            logger.info(f"Initialized {len(locations)} storage locations")
            return locations
        
        except Exception as e:
            logger.error(f"Error initializing storage locations: {e}")
            return []
    
    
    def _initialize_tripwire_files(self) -> List[Path]:
        """
        Initialize tripwire files that detect unauthorized access.
        These files should never be modified by legitimate code.
        
        Returns:
            List of tripwire file paths
        """
        tripwires = []
        
        try:
            if os.name == 'nt':
                base_path = Path(os.getenv('LOCALAPPDATA')) / 'SecureVaultPro'
            else:
                base_path = Path.home() / '.local' / 'share' / 'securevaultpro'
            
            base_path.mkdir(parents=True, exist_ok=True)
            
            # Create tripwire files
            tripwire_names = ['.integrity_check', '.system_state', '.verification']
            
            for name in tripwire_names:
                tripwire = base_path / name
                tripwires.append(tripwire)
                
                # Initialize tripwire with marker (not 'signature' to avoid collision!)
                if not tripwire.exists():
                    tripwire_data = {
                        'created': datetime.now().isoformat(),
                        'machine_id_hash': hashlib.sha256(self.machine_id.encode()).hexdigest(),
                        'tripwire_marker': 'TRIPWIRE_SENTINEL'  
                    }
                    self._write_encrypted_file(tripwire, tripwire_data)
            
            logger.info(f"Initialized {len(tripwires)} tripwire files")
            return tripwires
        
        except Exception as e:
            logger.error(f"Error initializing tripwires: {e}")
            return []
    
    def _compute_signature(self, data: Dict) -> str:
        """Compute HMAC-SHA256 signature of data."""
        data_copy = data.copy()
        data_copy.pop('signature', None)  # Remove signature itself
        json_str = json.dumps(data_copy, sort_keys=True)
        signature = hmac.new(self.secret_key, json_str.encode(), hashlib.sha256)
        return signature.hexdigest()
    
    def _verify_signature(self, data: Dict) -> bool:
        """Verify HMAC-SHA256 signature of data."""
        if 'signature' not in data:
            return False
        stored_signature = data['signature']
        computed_signature = self._compute_signature(data)
        return hmac.compare_digest(stored_signature, computed_signature)
    
    def _encrypt_data(self, data: Dict) -> str:
        """Encrypt data using XOR cipher with machine-specific key."""
        json_str = json.dumps(data, sort_keys=True)
        key = self.machine_id
        xored = ''.join(
            chr(ord(c) ^ ord(k))
            for c, k in zip(json_str, key * (len(json_str) // len(key) + 1))
        )
        return base64.b64encode(xored.encode()).decode()
    
    def _decrypt_data(self, encrypted: str) -> Optional[Dict]:
        """Decrypt data."""
        try:
            xored_bytes = base64.b64decode(encrypted)
            xored = xored_bytes.decode()
            key = self.machine_id
            json_str = ''.join(
                chr(ord(c) ^ ord(k))
                for c, k in zip(xored, key * (len(xored) // len(key) + 1))
            )
            return json.loads(json_str)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def _write_encrypted_file(self, file_path: Path, data: Dict) -> bool:
        """Write encrypted and signed data to file."""
        try:
            # Add signature
            data['signature'] = self._compute_signature(data)
            
            # Encrypt
            encrypted = self._encrypt_data(data)
            
            # Write atomically
            temp_path = file_path.with_suffix('.tmp')
            temp_path.write_text(encrypted)
            temp_path.replace(file_path)
            
            return True
        except Exception as e:
            logger.error(f"Failed to write {file_path}: {e}")
            return False
    
    def _read_encrypted_file(self, file_path: Path) -> Optional[Dict]:
        """Read and verify encrypted file."""
        try:
            if not file_path.exists():
                return None
            
            encrypted = file_path.read_text()
            data = self._decrypt_data(encrypted)
            
            if data is None:
                return None
            
            # Verify signature
            if not self._verify_signature(data):
                logger.warning(f"Invalid signature in {file_path}")
                return None
            
            return data
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return None

    def _check_tripwires(self) -> bool:
        """
        Check if tripwire files have been tampered with.
        
        Returns:
            bool: True if tripwires are intact, False if tampered
        """
        for tripwire in self.tripwire_locations:
            if not tripwire.exists():
                logger.critical(f"TRIPWIRE MISSING: {tripwire}")
                return False
            
            data = self._read_encrypted_file(tripwire)
            if data is None:
                logger.critical(f"TRIPWIRE CORRUPTED: {tripwire}")
                return False
            
            # Verify tripwire marker (changed from 'signature' to avoid collision)
            if data.get('tripwire_marker') != 'TRIPWIRE_SENTINEL':
                logger.critical(f"TRIPWIRE MODIFIED: {tripwire}")
                return False
            
            # Verify machine ID
            expected_hash = hashlib.sha256(self.machine_id.encode()).hexdigest()
            if data.get('machine_id_hash') != expected_hash:
                logger.critical(f"TRIPWIRE MACHINE ID MISMATCH: {tripwire}")
                return False
        
        return True  

    def _handle_tampering_detected(self, event_type: str, details: str):
        """Handle tampering detection - permanent lockout."""
        with self.lock:
            self.tampering_detected = True
            self.permanent_lockout = True
            
            # Record event
            event = {
                'type': event_type,
                'details': details,
                'timestamp': datetime.now().isoformat()
            }
            self.tampering_events.append(event)
            
            # Write permanent lockout flag to all locations
            lockout_data = {
                'lockout': True,
                'reason': event_type,
                'details': details,
                'timestamp': datetime.now().isoformat(),
                'machine_id_hash': hashlib.sha256(self.machine_id.encode()).hexdigest()
            }
            
            for location in self.storage_locations:
                try:
                    self._write_encrypted_file(location, lockout_data)
                except:
                    pass
            
            logger.critical(f"PERMANENT LOCKOUT ACTIVATED: {event_type} - {details}")
    
    def _save_trial_state(self, data: Dict) -> bool:
        """
        Save trial state to all storage locations with signatures.
        
        Returns:
            bool: True if saved to at least 3 locations (minimum redundancy)
        """
        success_count = 0
        
        # Add timestamp and machine ID hash
        data['last_update'] = datetime.now().isoformat()
        data['machine_id_hash'] = hashlib.sha256(self.machine_id.encode()).hexdigest()
        
        # Update last known timestamp
        self.last_known_timestamp = datetime.now()
        data['last_known_timestamp'] = self.last_known_timestamp.isoformat()
        
        with self.lock:
            for location in self.storage_locations:
                if self._write_encrypted_file(location, data):
                    success_count += 1
        
        logger.info(f"Trial state saved to {success_count}/{len(self.storage_locations)} locations")
        
        # Require saving to at least 3 locations for redundancy
        return success_count >= 3
    
    def _load_trial_state(self) -> Optional[Dict]:
        """
        Load trial state with integrity verification and majority voting.
        
        Returns:
            Dict: Trial state if valid, None if corrupted/tampered
        """
        states = []
        
        with self.lock:
            for location in self.storage_locations:
                data = self._read_encrypted_file(location)
                if data:
                    states.append((location, data))
        
        if not states:
            logger.info("No trial state found - first launch")
            return None
        
        # Majority voting - ensure consistency
        if len(states) < 2:
            logger.warning("Insufficient redundancy - potential tampering")
            # Allow if this is the only copy
            return states[0][1] if states else None
        
        # Check for consistency across states
        first_state = states[0][1]
        consistent = True
        
        for location, state in states[1:]:
            # Compare critical fields
            if (state.get('trial_start_date') != first_state.get('trial_start_date') or
                state.get('activated') != first_state.get('activated') or
                state.get('machine_id_hash') != first_state.get('machine_id_hash')):
                logger.critical(f"INCONSISTENT STATE DETECTED at {location}")
                consistent = False
        
        if not consistent:
            logger.critical("Trial state inconsistency detected - TAMPERING")
            self._handle_tampering_detected("state_inconsistency", "Multiple trial states don't match")
            return None
        
        # Verify machine ID
        expected_hash = hashlib.sha256(self.machine_id.encode()).hexdigest()
        if first_state.get('machine_id_hash') != expected_hash:
            logger.critical("MACHINE ID MISMATCH - Trial data from different machine")
            self._handle_tampering_detected("machine_id_mismatch", "Trial data doesn't match this machine")
            return None
        
        # Anti-rollback protection
        if 'last_known_timestamp' in first_state:
            try:
                last_known = datetime.fromisoformat(first_state['last_known_timestamp'])
                current_time = datetime.now()
                
                # Check if system time has been rolled back
                if current_time < last_known - timedelta(seconds=self.MAX_TIME_DRIFT):
                    logger.critical("TIME ROLLBACK DETECTED - System clock manipulated")
                    self._handle_tampering_detected("time_rollback", 
                        f"System time: {current_time}, Last known: {last_known}")
                    return None
            except Exception as e:
                logger.error(f"Error checking time rollback: {e}")
        
        return first_state
    
    def _check_permanent_lockout(self) -> Tuple[bool, str]:
        """
        Check if permanent lockout is active.
        
        Returns:
            Tuple[bool, str]: (is_locked, reason)
        """
        # Check memory flag
        if self.permanent_lockout:
            return True, "Tampering detected - permanent lockout active"
        
        # Check stored states
        with self.lock:
            for location in self.storage_locations:
                data = self._read_encrypted_file(location)
                if data and data.get('lockout'):
                    self.permanent_lockout = True
                    return True, f"Permanent lockout: {data.get('reason', 'unknown')}"
        
        return False, ""
    
    def initialize_trial(self) -> bool:
        """Initialize trial period if not already started."""
        # Check for permanent lockout first
        is_locked, reason = self._check_permanent_lockout()
        if is_locked:
            logger.critical(f"Cannot initialize trial: {reason}")
            return False
        
        # Check tripwires
        if not self._check_tripwires():
            self._handle_tampering_detected("tripwire_failure", "Tripwire files tampered")
            return False
        
        # Load existing state
        existing_state = self._load_trial_state()
        if existing_state:
            logger.info("Trial already initialized")
            return False
        
        # Initialize new trial
        now = datetime.now()
        trial_data = {
            'trial_start_date': now.isoformat(),
            'trial_end_date': (now + timedelta(days=self.TRIAL_DAYS)).isoformat(),
            'activated': False,
            'activation_date': None,
            'license_key': None,
            'initialization_timestamp': now.isoformat(),
            'version': '2.0'
        }
        
        success = self._save_trial_state(trial_data)
        if success:
            logger.info(f"âœ… Trial initialized: {self.TRIAL_DAYS} days")
            # Start monitoring
            self.start_monitoring()
        
        return success
    
    def get_trial_status(self) -> Dict:
        """Get comprehensive trial status with integrity verification."""
        # Check permanent lockout
        is_locked, reason = self._check_permanent_lockout()
        if is_locked:
            return {
                'is_activated': False,
                'is_trial_active': False,
                'is_expired': False,
                'is_locked': True,
                'lockout_reason': reason,
                'days_remaining': 0,
                'machine_id': self.machine_id
            }
        
        # Check tripwires
        if not self._check_tripwires():
            self._handle_tampering_detected("tripwire_check_failed", "Tripwires compromised")
            return {
                'is_activated': False,
                'is_trial_active': False,
                'is_expired': False,
                'is_locked': True,
                'lockout_reason': 'Tampering detected',
                'days_remaining': 0,
                'machine_id': self.machine_id
            }
        
        # Load trial state
        data = self._load_trial_state()
        
        # Check if activated
        if data and data.get('activated'):
            return {
                'is_activated': True,
                'is_trial_active': False,
                'is_expired': False,
                'is_locked': False,
                'days_remaining': None,
                'activation_date': data.get('activation_date'),
                'machine_id': self.machine_id
            }
        
        # Trial not started
        if not data or 'trial_start_date' not in data:
            return {
                'is_activated': False,
                'is_trial_active': False,
                'is_expired': False,
                'is_locked': False,
                'days_remaining': self.TRIAL_DAYS,
                'machine_id': self.machine_id
            }
        
        # Calculate trial status
        try:
            trial_end = datetime.fromisoformat(data['trial_end_date'])
            now = datetime.now()
            
            if now > trial_end:
                return {
                    'is_activated': False,
                    'is_trial_active': False,
                    'is_expired': True,
                    'is_locked': False,
                    'days_remaining': 0,
                    'trial_start_date': data['trial_start_date'],
                    'trial_end_date': data['trial_end_date'],
                    'machine_id': self.machine_id
                }
            else:
                days_remaining = (trial_end - now).days + 1
                return {
                    'is_activated': False,
                    'is_trial_active': True,
                    'is_expired': False,
                    'is_locked': False,
                    'days_remaining': days_remaining,
                    'trial_start_date': data['trial_start_date'],
                    'trial_end_date': data['trial_end_date'],
                    'machine_id': self.machine_id
                }
        except Exception as e:
            logger.error(f"Error calculating trial status: {e}")
            # Safe fallback
            return {
                'is_activated': False,
                'is_trial_active': False,
                'is_expired': True,
                'is_locked': False,
                'days_remaining': 0,
                'machine_id': self.machine_id
            }
    
    def is_access_allowed(self) -> Tuple[bool, str]:
        """Check if user can access the application."""
        status = self.get_trial_status()
        
        # Check lockout
        if status.get('is_locked'):
            return False, f"locked: {status.get('lockout_reason', 'unknown')}"
        
        # Check activation
        if status['is_activated']:
            return True, "activated"
        
        # Check trial
        if status['is_trial_active']:
            return True, f"trial_{status['days_remaining']}_days"
        
        # Check expiration
        if status['is_expired']:
            return False, "trial_expired"
        
        # First launch - initialize
        self.initialize_trial()
        return True, f"trial_{self.TRIAL_DAYS}_days"
    
    def verify_license_key(self, license_key: str) -> bool:
        """Verify license key against this machine."""
        try:
            salted_id = self.machine_id + self.SECRET_SALT
            expected = hashlib.sha256(salted_id.encode()).hexdigest()
            return license_key.strip().lower() == expected.lower()
        except Exception as e:
            logger.error(f"Error verifying license: {e}")
            return False
    
    def activate(self, license_key: str) -> Tuple[bool, str]:
        """Activate the application with license key."""
        # Check permanent lockout
        is_locked, reason = self._check_permanent_lockout()
        if is_locked:
            return False, f"Cannot activate: {reason}"
        
        # Verify license
        if not self.verify_license_key(license_key):
            return False, "Invalid license key for this machine"
        
        # Load current state
        data = self._load_trial_state() or {}
        
        # Update activation
        data['activated'] = True
        data['activation_date'] = datetime.now().isoformat()
        data['license_key'] = license_key
        
        # Save
        if self._save_trial_state(data):
            logger.info("âœ… Application activated successfully")
            return True, "Activation successful"
        else:
            return False, "Failed to save activation"
    
    def start_monitoring(self) -> bool:
        """Start real-time monitoring of trial state files."""
        if self.is_monitoring:
            return False
        
        self.is_monitoring = True
        
        # Start background monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        # Start file system monitoring if available
        if WATCHDOG_AVAILABLE:
            try:
                self.file_observer = Observer()
                handler = TrialMonitorEventHandler(self)
                
                # Monitor all storage location directories
                monitored_dirs = set()
                for location in self.storage_locations:
                    parent_dir = str(location.parent)
                    if parent_dir not in monitored_dirs:
                        self.file_observer.schedule(handler, parent_dir, recursive=False)
                        monitored_dirs.add(parent_dir)
                
                self.file_observer.start()
                logger.info("File system monitoring started")
            except Exception as e:
                logger.error(f"Failed to start file monitoring: {e}")
        
        logger.info("Trial monitoring started")
        return True
    
    def stop_monitoring(self):
        """Stop monitoring."""
        self.is_monitoring = False
        
        if self.file_observer:
            try:
                self.file_observer.stop()
                self.file_observer.join(timeout=5)
            except:
                pass
        
        logger.info("Trial monitoring stopped")
    
    def _monitoring_loop(self):
        """Continuous monitoring loop."""
        while self.is_monitoring:
            try:
                # Periodic integrity check
                self._verify_integrity()
                
                # Sleep
                time.sleep(self.VERIFICATION_INTERVAL)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(self.VERIFICATION_INTERVAL)
    
    def _verify_integrity(self):
        """Periodic integrity verification."""
        # Check tripwires
        if not self._check_tripwires():
            self._handle_tampering_detected("periodic_tripwire_check", "Tripwire compromised")
            return
        
        # Load and verify state
        data = self._load_trial_state()
        if data is None and not self.permanent_lockout:
            # State missing - potential tampering
            logger.warning("Trial state missing during monitoring")
            # Don't immediately lock out - might be first run
    
    def get_machine_id(self) -> str:
        """Get machine ID for this system."""
        return self.machine_id

    def get_activation_info(self) -> Dict:
        """
        Get comprehensive activation information.
        
        Returns:
            Dict containing:
            - machine_id: Unique machine identifier
            - is_activated: Whether the application is activated
            - activation_date: When activation occurred (if activated)
            - days_remaining: Days remaining in trial (if not activated)
            - trial_expired: Whether trial has expired
            - license_key: License key (if activated, masked)
        """
        try:
            # Get trial status first
            status = self.get_trial_status()
            
            # Load state for additional details
            state = self._load_trial_state() or {}
            
            # Build comprehensive info
            info = {
                'machine_id': self.machine_id,
                'is_activated': status.get('is_activated', False),
                'activation_date': status.get('activation_date'),
                'days_remaining': status.get('days_remaining'),
                'trial_expired': status.get('is_expired', False),
                'is_locked': status.get('is_locked', False),
                'lockout_reason': status.get('lockout_reason'),
                'trial_start_date': status.get('trial_start_date'),
                'trial_end_date': status.get('trial_end_date'),
            }
            
            # Add license key (masked) if activated
            if info['is_activated'] and 'license_key' in state:
                # Mask the license key (show first 8 and last 4 characters)
                key = state['license_key']
                if len(key) > 12:
                    info['license_key'] = f"{key[:8]}...{key[-4:]}"
                else:
                    info['license_key'] = "***"
            else:
                info['license_key'] = None
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting activation info: {e}")
            # Return safe defaults
            return {
                'machine_id': self.machine_id,
                'is_activated': False,
                'activation_date': None,
                'days_remaining': 0,
                'trial_expired': True,
                'is_locked': False,
                'lockout_reason': None,
                'license_key': None,
                'trial_start_date': None,
                'trial_end_date': None,
            }

# Singleton instance
_enhanced_trial_manager = None

def get_trial_manager() -> EnhancedTrialActivationManager:
    """Get or create the global trial manager instance."""
    global _enhanced_trial_manager
    if _enhanced_trial_manager is None:
        _enhanced_trial_manager = EnhancedTrialActivationManager()
    return _enhanced_trial_manager


if __name__ == "__main__":
    # Test the enhanced trial manager
    logging.basicConfig(level=logging.INFO)
    
    print("=== Enhanced Trial Manager Test ===\n")
    
    manager = EnhancedTrialActivationManager()
    
    # Initialize trial
    print("1. Initializing trial...")
    manager.initialize_trial()
    
    # Get status
    print("\n2. Trial status:")
    status = manager.get_trial_status()
    for key, value in status.items():
        print(f"   {key}: {value}")
    
    # Check access
    print("\n3. Access check:")
    can_access, reason = manager.is_access_allowed()
    print(f"   Can access: {can_access}")
    print(f"   Reason: {reason}")
    
    # Check tripwires
    print("\n4. Tripwire check:")
    tripwires_ok = manager._check_tripwires()
    print(f"   Tripwires intact: {tripwires_ok}")
    
    print("\nâœ… Test completed!")