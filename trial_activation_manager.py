"""
Trial Period and Activation Manager
Manages 7-day trial period and license activation for SecureVault Pro

Features:
- 7-day trial period tracking
- Machine ID based activation
- Trial expiration enforcement
- Persistent activation status
- Professional activation UI
"""

import os
import json
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple, Optional, Dict
from machine_id_utils import generate_machine_id

logger = logging.getLogger(__name__)


class TrialActivationManager:
    """
    Manages trial period and activation for SecureVault Pro.
    
    Trial Period: 7 days from first launch
    Activation: Machine ID based license verification
    """
    
    # Trial configuration
    TRIAL_DAYS = 7
    
    # Secret salt for license verification (same as generate_license.py)
    SECRET_SALT = "a-very-secret-and-long-salt-that-is-hard-to-guess"
    
    def __init__(self, storage_path: str = None):
        """
        Initialize the Trial and Activation Manager.
        
        Args:
            storage_path: Path to store trial/activation data. If None, uses AppData
        """
        if storage_path is None:
            # Store in AppData/Local for persistence
            if os.name == 'nt':  # Windows
                appdata = os.getenv('LOCALAPPDATA')
                storage_path = os.path.join(appdata, 'SecureVaultPro', '.trial')
            else:  # Unix-like
                storage_path = os.path.expanduser('~/.local/share/securevaultpro/.trial')
        
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate machine ID for this system
        self.machine_id = generate_machine_id()
        
        logger.info(f"TrialActivationManager initialized")
        logger.info(f"Storage path: {self.storage_path}")
        logger.info(f"Machine ID: {self.machine_id[:16]}...")  # Log partial ID only
    
    def _load_trial_data(self) -> Dict:
        """Load trial and activation data from storage."""
        if not self.storage_path.exists():
            return {}
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            logger.debug(f"Trial data loaded: {list(data.keys())}")
            return data
        except Exception as e:
            logger.error(f"Failed to load trial data: {e}")
            return {}
    
    def _save_trial_data(self, data: Dict) -> bool:
        """Save trial and activation data to storage."""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug("Trial data saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save trial data: {e}")
            return False
    
    def initialize_trial(self) -> bool:
        """
        Initialize trial period if not already started.
        Called on first launch.
        
        Returns:
            bool: True if trial initialized, False if already exists
        """
        data = self._load_trial_data()
        
        if 'trial_start_date' in data:
            logger.info("Trial already initialized")
            return False
        
        # Initialize trial
        now = datetime.now()
        data['trial_start_date'] = now.isoformat()
        data['trial_end_date'] = (now + timedelta(days=self.TRIAL_DAYS)).isoformat()
        data['machine_id_hash'] = hashlib.sha256(self.machine_id.encode()).hexdigest()
        data['activated'] = False
        data['activation_date'] = None
        data['license_key'] = None
        
        success = self._save_trial_data(data)
        if success:
            logger.info(f"Trial initialized: {self.TRIAL_DAYS} days")
            logger.info(f"Trial end date: {data['trial_end_date']}")
        
        return success
    
    def get_trial_status(self) -> Dict:
        """
        Get comprehensive trial status information.
        
        Returns:
            dict: Trial status with keys:
                - is_activated: bool
                - is_trial_active: bool
                - is_expired: bool
                - days_remaining: int
                - trial_start_date: str
                - trial_end_date: str
                - machine_id: str
        """
        data = self._load_trial_data()
        
        # Check if activated
        if data.get('activated', False):
            return {
                'is_activated': True,
                'is_trial_active': False,
                'is_expired': False,
                'days_remaining': None,
                'trial_start_date': data.get('trial_start_date'),
                'trial_end_date': data.get('trial_end_date'),
                'activation_date': data.get('activation_date'),
                'machine_id': self.machine_id
            }
        
        # Check if trial initialized
        if 'trial_start_date' not in data:
            # Trial not started yet
            return {
                'is_activated': False,
                'is_trial_active': False,
                'is_expired': False,
                'days_remaining': self.TRIAL_DAYS,
                'trial_start_date': None,
                'trial_end_date': None,
                'machine_id': self.machine_id
            }
        
        # Calculate trial status
        try:
            trial_end = datetime.fromisoformat(data['trial_end_date'])
            now = datetime.now()
            
            if now > trial_end:
                # Trial expired
                return {
                    'is_activated': False,
                    'is_trial_active': False,
                    'is_expired': True,
                    'days_remaining': 0,
                    'trial_start_date': data['trial_start_date'],
                    'trial_end_date': data['trial_end_date'],
                    'machine_id': self.machine_id
                }
            else:
                # Trial active
                days_remaining = (trial_end - now).days + 1  # +1 to include current day
                return {
                    'is_activated': False,
                    'is_trial_active': True,
                    'is_expired': False,
                    'days_remaining': days_remaining,
                    'trial_start_date': data['trial_start_date'],
                    'trial_end_date': data['trial_end_date'],
                    'machine_id': self.machine_id
                }
        
        except Exception as e:
            logger.error(f"Error calculating trial status: {e}")
            # Safe fallback - treat as expired
            return {
                'is_activated': False,
                'is_trial_active': False,
                'is_expired': True,
                'days_remaining': 0,
                'trial_start_date': data.get('trial_start_date'),
                'trial_end_date': data.get('trial_end_date'),
                'machine_id': self.machine_id
            }
    
    def is_access_allowed(self) -> Tuple[bool, str]:
        """
        Check if user can access the application.
        
        Returns:
            Tuple[bool, str]: (can_access, reason)
        """
        status = self.get_trial_status()
        
        if status['is_activated']:
            return True, "activated"
        
        if status['is_trial_active']:
            return True, f"trial_{status['days_remaining']}_days"
        
        if status['is_expired']:
            return False, "trial_expired"
        
        # First launch - initialize trial
        self.initialize_trial()
        return True, f"trial_{self.TRIAL_DAYS}_days"
    
    def generate_expected_license_key(self) -> str:
        """
        Generate the expected license key for this machine.
        Uses the same algorithm as generate_license.py
        
        Returns:
            str: Expected license key (SHA256 hash)
        """
        salted_id = self.machine_id + self.SECRET_SALT
        license_key = hashlib.sha256(salted_id.encode()).hexdigest()
        return license_key
    
    def verify_license_key(self, license_key: str) -> bool:
        """
        Verify a license key against this machine.
        
        Args:
            license_key: License key to verify
        
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            expected = self.generate_expected_license_key()
            is_valid = license_key.strip().lower() == expected.lower()
            
            if is_valid:
                logger.info("License key verification: SUCCESS")
            else:
                logger.warning("License key verification: FAILED")
            
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying license key: {e}")
            return False
    
    def activate(self, license_key: str) -> Tuple[bool, str]:
        """
        Activate the application with a license key.
        
        Args:
            license_key: License key to activate with
        
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            # Verify license key
            if not self.verify_license_key(license_key):
                logger.warning("Activation failed: Invalid license key")
                return False, "Invalid license key for this machine"
            
            # Load and update trial data
            data = self._load_trial_data()
            data['activated'] = True
            data['activation_date'] = datetime.now().isoformat()
            data['license_key'] = license_key
            
            # Save activation
            if self._save_trial_data(data):
                logger.info("✅ Application activated successfully")
                return True, "Activation successful"
            else:
                logger.error("Failed to save activation data")
                return False, "Failed to save activation"
        
        except Exception as e:
            logger.error(f"Activation error: {e}")
            return False, f"Activation error: {str(e)}"
    
    def deactivate(self) -> bool:
        """
        Deactivate the application (for testing/development).
        
        Returns:
            bool: True if deactivated successfully
        """
        try:
            data = self._load_trial_data()
            data['activated'] = False
            data['activation_date'] = None
            data['license_key'] = None
            
            success = self._save_trial_data(data)
            if success:
                logger.info("Application deactivated")
            
            return success
        except Exception as e:
            logger.error(f"Deactivation error: {e}")
            return False
    
    def get_machine_id(self) -> str:
        """Get the machine ID for this system."""
        return self.machine_id
    
    def get_activation_info(self) -> Dict:
        """
        Get detailed activation information for display.
        
        Returns:
            dict: Activation information
        """
        data = self._load_trial_data()
        status = self.get_trial_status()
        
        return {
            'machine_id': self.machine_id,
            'is_activated': status['is_activated'],
            'activation_date': data.get('activation_date'),
            'trial_start_date': status.get('trial_start_date'),
            'trial_end_date': status.get('trial_end_date'),
            'days_remaining': status.get('days_remaining'),
            'expected_license_key': self.generate_expected_license_key()
        }


# Singleton instance
_trial_manager = None


def get_trial_manager() -> TrialActivationManager:
    """
    Get or create the global TrialActivationManager instance.
    
    Returns:
        TrialActivationManager: The global instance
    """
    global _trial_manager
    if _trial_manager is None:
        _trial_manager = TrialActivationManager()
    return _trial_manager


if __name__ == "__main__":
    # Test the TrialActivationManager
    logging.basicConfig(level=logging.INFO)
    
    manager = TrialActivationManager()
    
    print("=== Trial & Activation Manager Test ===\n")
    
    # Initialize trial
    print("1. Initializing trial...")
    manager.initialize_trial()
    
    # Get status
    print("\n2. Trial status:")
    status = manager.get_trial_status()
    print(f"   - Activated: {status['is_activated']}")
    print(f"   - Trial Active: {status['is_trial_active']}")
    print(f"   - Expired: {status['is_expired']}")
    print(f"   - Days Remaining: {status['days_remaining']}")
    print(f"   - Machine ID: {status['machine_id'][:32]}...")
    
    # Check access
    print("\n3. Access check:")
    can_access, reason = manager.is_access_allowed()
    print(f"   - Can Access: {can_access}")
    print(f"   - Reason: {reason}")
    
    # Get activation info
    print("\n4. Activation info:")
    info = manager.get_activation_info()
    print(f"   - Machine ID: {info['machine_id'][:32]}...")
    print(f"   - Expected License Key: {info['expected_license_key'][:32]}...")
    
    print("\n✅ Test completed!")
