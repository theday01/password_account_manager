import time
import logging
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidTag
import secrets
import base64

logger = logging.getLogger(__name__)

# Try to import pyotp for TOTP functionality
try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False
    logger.warning("pyotp not available. 2FA functionality will be disabled. Install with: pip install pyotp qrcode[pil]")

class AuthGuardian:
    """
    Manages authentication security, including brute-force protection and lockouts.
    """
    # Constants for master password protection
    MAX_ATTEMPTS_BEFORE_LOCKOUT = 3
    INITIAL_LOCKOUT_MINUTES = 60
    SUBSEQUENT_LOCKOUT_INCREMENT_MINUTES = 30
    
    # Constants for 2FA protection
    MAX_TFA_ATTEMPTS_BEFORE_LOCKOUT = 5
    TFA_LOCKOUT_MINUTES = 15

    def __init__(self, settings_manager):
        """
        Initializes the AuthGuardian.

        Args:
            settings_manager: An object (like SecureFileManager) that can read/write settings.
        """
        self._settings_manager = settings_manager
        raw_settings = self._settings_manager.read_settings() or {}
        
        # Load settings (2FA secret is now allowed)
        self._settings = raw_settings.copy()
        
        # Load master password state from settings
        self.failed_attempts = self._settings.get('guardian_failed_attempts', 0)
        self.consecutive_lockouts = self._settings.get('guardian_consecutive_lockouts', 0)
        lockout_end_iso = self._settings.get('guardian_lockout_end_time')
        self.lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None
        
        # Load 2FA state from settings
        self.tfa_failed_attempts = self._settings.get('guardian_tfa_failed_attempts', 0)
        self.consecutive_tfa_lockouts = self._settings.get('guardian_consecutive_tfa_lockouts', 0)
        tfa_lockout_end_iso = self._settings.get('guardian_tfa_lockout_end_time')
        self.tfa_lockout_end_time = datetime.fromisoformat(tfa_lockout_end_iso) if tfa_lockout_end_iso else None

        # Don't save state during initialization - encryption key might not be available yet
        # This prevents overwriting settings with empty dict when encryption key isn't set
        self._validate_state(save_state=False)

    def get_settings(self):
        """Returns a copy of the current settings."""
        return self._settings.copy()

    def update_setting(self, key: str, value):
        """
        Updates a specific setting and immediately persists the change.

        Args:
            key (str): The key of the setting to update.
            value: The new value for the setting.
        
        Returns:
            bool: True if the setting was successfully saved, False otherwise.
        """
        logger.info(f"Updating setting '{key}' and persisting changes.")
        self._settings[key] = value
        return self._save_state()

    def _validate_state(self, save_state=True):
        """Sanity check and cleanup of the loaded state.
        
        Args:
            save_state: If True, save state after validation. If False, only validate without saving.
                       This is useful during initialization when encryption key might not be available.
        """
        if self.is_locked_out():
            if datetime.now() >= self.lockout_end_time:
                logger.info("Master password lockout period has expired. Resetting state.")
                self._reset_lockout()
        
        if self.is_tfa_locked_out():
            if datetime.now() >= self.tfa_lockout_end_time:
                logger.info("2FA lockout period has expired. Resetting state.")
                self._reset_tfa_lockout()

        # Sanity checks for all state variables
        self.failed_attempts = max(0, self.failed_attempts)
        self.consecutive_lockouts = max(0, self.consecutive_lockouts)
        self.tfa_failed_attempts = max(0, self.tfa_failed_attempts)
        self.consecutive_tfa_lockouts = max(0, self.consecutive_tfa_lockouts)
        
        # Only save state if encryption key is available and save_state is True
        if save_state and self._settings_manager.encryption_key:
            self._save_state()
        elif save_state and not self._settings_manager.encryption_key:
            logger.info("Skipping state save during validation - encryption key not available yet")

    def _save_state(self):
        """Saves the current state back to the settings file.
        This method preserves all existing settings and only updates guardian-specific state.
        
        Returns:
            bool: True if settings were successfully saved, False otherwise.
        """
        # CRITICAL: We MUST have an encryption key to save settings
        # If we don't have a key, we can't read existing settings, so we can't safely save
        if not self._settings_manager.encryption_key:
            logger.warning("Cannot save state - encryption key is not available. Settings will be saved after authentication.")
            return False
        
        # First, try to load existing settings from disk to preserve them
        existing_settings = {}
        try:
            existing_settings = self._settings_manager.read_settings()
            if existing_settings is None:
                existing_settings = {}
                logger.info("No existing settings file found, starting with empty dict")
            else:
                logger.info(f"Loaded existing settings before save. Keys: {list(existing_settings.keys())}")
        except InvalidTag as e:
            logger.error(f"Failed to decrypt existing settings (InvalidTag) - file may be encrypted with different key: {e}")
            # If decryption fails, we can't safely save - we might overwrite settings with wrong data
            logger.error("Cannot save state - failed to decrypt existing settings. This might indicate a key mismatch.")
            return False
        except Exception as e:
            logger.error(f"Could not load existing settings before save: {e}")
            # If we can't read existing settings, we can't safely save
            logger.error("Cannot save state - failed to read existing settings.")
            return False
        
        # Start with existing settings from disk to preserve them
        settings_to_save = {}
        for key, value in (existing_settings.items() if existing_settings else {}):
            settings_to_save[key] = value
        
        # Merge all other settings from self._settings
        # This preserves any other settings that were updated
        for key, value in self._settings.items():
            settings_to_save[key] = value
        
        # Update guardian-specific state (these always override any existing values)
        settings_to_save['guardian_failed_attempts'] = self.failed_attempts
        settings_to_save['guardian_consecutive_lockouts'] = self.consecutive_lockouts
        settings_to_save['guardian_lockout_end_time'] = self.lockout_end_time.isoformat() if self.lockout_end_time else None
        
        # 2FA state
        settings_to_save['guardian_tfa_failed_attempts'] = self.tfa_failed_attempts
        settings_to_save['guardian_consecutive_tfa_lockouts'] = self.consecutive_tfa_lockouts
        settings_to_save['guardian_tfa_lockout_end_time'] = self.tfa_lockout_end_time.isoformat() if self.tfa_lockout_end_time else None
        
        # Update all other settings from settings_to_save (except guardian state keys)
        for key, value in settings_to_save.items():
            if key not in ['guardian_failed_attempts', 'guardian_consecutive_lockouts', 'guardian_lockout_end_time',
                          'guardian_tfa_failed_attempts', 'guardian_consecutive_tfa_lockouts', 'guardian_tfa_lockout_end_time']:
                # Guardian state keys are managed separately
                self._settings[key] = value
        
        try:
            # Log what we're about to save
            logger.info(f"About to save settings. Keys to save: {list(settings_to_save.keys())}")
            
            success = self._settings_manager.write_settings(settings_to_save)
            if not success:
                logger.error("Failed to save guardian state, most likely because the vault is locked.")
                return False
            
            logger.info(f"Successfully saved settings. Keys: {list(settings_to_save.keys())}")
            return True
        except Exception as e:
            logger.error(f"An unexpected error occurred while saving guardian state: {e}")
            return False

    def record_login_attempt(self, success: bool):
        """
        Records the result of a master password login attempt and updates the security state.
        
        Args:
            success (bool): True if the login was successful, False otherwise.
        """
        if success:
            logger.info("Successful master password login recorded. Resetting guardian state.")
            self.failed_attempts = 0
            self.consecutive_lockouts = 0
            # Reset 2FA lockout on successful master password login
            self._reset_tfa_lockout()
        else:
            self.failed_attempts += 1
            logger.warning(f"Failed master password attempt #{self.failed_attempts} recorded.")
            
            if self.failed_attempts >= self.MAX_ATTEMPTS_BEFORE_LOCKOUT:
                self.consecutive_lockouts += 1
                
                if self.consecutive_lockouts == 1:
                    lockout_minutes = self.INITIAL_LOCKOUT_MINUTES
                else:
                    lockout_minutes = self.INITIAL_LOCKOUT_MINUTES + (self.consecutive_lockouts - 1) * self.SUBSEQUENT_LOCKOUT_INCREMENT_MINUTES
                
                self.lockout_end_time = datetime.now() + timedelta(minutes=lockout_minutes)
                logger.warning(f"Max master password attempts reached. Account locked for {lockout_minutes} minutes.")

        self._save_state()

    def is_locked_out(self) -> bool:
        """
        Checks if the account is currently in a hard lockout state.

        Returns:
            bool: True if locked out, False otherwise.
        """
        if not self.lockout_end_time:
            return False
        
        if datetime.now() < self.lockout_end_time:
            return True
        else:
            # Lockout has just expired, so reset and report not locked.
            self._reset_lockout()
            return False

    def get_remaining_lockout_time(self) -> int:
        """
        Gets the remaining lockout time in seconds.

        Returns:
            int: The number of seconds remaining, or 0 if not locked out.
        """
        if not self.is_locked_out():
            return 0
        
        remaining = self.lockout_end_time - datetime.now()
        return max(0, int(remaining.total_seconds()))

    def _reset_lockout(self):
        """Resets the state after a lockout expires."""
        self.lockout_end_time = None
        self.failed_attempts = 0 # Reset attempts after a lockout
        self._save_state()
    
    def is_tfa_enabled(self) -> bool:
        """Check if 2FA is enabled for this account."""
        if not PYOTP_AVAILABLE:
            return False
        return 'tfa_secret' in self._settings and self._settings.get('tfa_secret') is not None
    
    def generate_tfa_secret(self) -> str:
        """Generate a new TOTP secret for 2FA setup."""
        if not PYOTP_AVAILABLE:
            raise ValueError("pyotp library is not available. Please install it: pip install pyotp")
        return pyotp.random_base32()
    
    def get_tfa_provisioning_uri(self, account_name: str = None, issuer_name: str = "SecureVault") -> str:
        """Get the provisioning URI for the TOTP secret (for QR code generation)."""
        if not PYOTP_AVAILABLE:
            raise ValueError("pyotp library is not available")
        if not self.is_tfa_enabled():
            raise ValueError("2FA is not enabled")
        totp = pyotp.TOTP(self._settings['tfa_secret'])
        
        # Use the provided account_name, but fall back to the default "SecureVault Pro" if it's None or empty.
        effective_account_name = account_name if account_name else "SecureVault Pro"
        
        return totp.provisioning_uri(name=effective_account_name, issuer_name=issuer_name)
    
    def enable_tfa(self, secret: str) -> bool:
        """Enable 2FA with the given secret."""
        if not PYOTP_AVAILABLE:
            raise ValueError("pyotp library is not available. Please install it: pip install pyotp")
        if not secret or len(secret) < 16:
            raise ValueError("Invalid TOTP secret")
        self._settings['tfa_secret'] = secret
        self._settings['tfa_enabled_at'] = datetime.now().isoformat()
        # Reset 2FA failure state when enabling
        self.tfa_failed_attempts = 0
        self.consecutive_tfa_lockouts = 0
        self.tfa_lockout_end_time = None
        return self._save_state()
    
    def disable_tfa(self) -> bool:
        """Disable 2FA for this account."""
        if 'tfa_secret' in self._settings:
            del self._settings['tfa_secret']
        if 'tfa_enabled_at' in self._settings:
            del self._settings['tfa_enabled_at']
        if 'tfa_backup_codes' in self._settings:
            del self._settings['tfa_backup_codes']
        # Reset 2FA failure state
        self.tfa_failed_attempts = 0
        self.consecutive_tfa_lockouts = 0
        self.tfa_lockout_end_time = None
        return self._save_state()
    
    def verify_tfa_code(self, code: str) -> bool:
        """Verify a TOTP code or backup code."""
        if not PYOTP_AVAILABLE:
            return False
        if not self.is_tfa_enabled():
            return False
        if self.is_tfa_locked_out():
            logger.warning("2FA verification attempted while locked out")
            return False
        
        # Check backup codes first
        backup_codes = self._settings.get('tfa_backup_codes', [])
        if code in backup_codes:
            # Remove used backup code
            backup_codes.remove(code)
            self._settings['tfa_backup_codes'] = backup_codes
            self._save_state()
            logger.info("2FA backup code used successfully")
            return True
        
        # Verify TOTP code
        try:
            totp = pyotp.TOTP(self._settings['tfa_secret'])
            # Allow a time window of ±1 time step (30 seconds) for clock skew
            is_valid = totp.verify(code, valid_window=1)
            if is_valid:
                self.tfa_failed_attempts = 0
                self.consecutive_tfa_lockouts = 0
                self._save_state()
                logger.info("2FA code verified successfully")
            else:
                self.record_tfa_attempt(success=False)
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying 2FA code: {e}")
            self.record_tfa_attempt(success=False)
            return False
    
    def record_tfa_attempt(self, success: bool):
        """Record a 2FA verification attempt."""
        if success:
            logger.info("Successful 2FA attempt recorded. Resetting 2FA failure count.")
            self.tfa_failed_attempts = 0
            self.consecutive_tfa_lockouts = 0
        else:
            self.tfa_failed_attempts += 1
            logger.warning(f"Failed 2FA attempt #{self.tfa_failed_attempts} recorded.")
            
            if self.tfa_failed_attempts >= self.MAX_TFA_ATTEMPTS_BEFORE_LOCKOUT:
                self.consecutive_tfa_lockouts += 1
                lockout_duration = timedelta(minutes=self.TFA_LOCKOUT_MINUTES * self.consecutive_tfa_lockouts)
                self.tfa_lockout_end_time = datetime.now() + lockout_duration
                logger.warning(f"Max 2FA attempts reached. Locked for {lockout_duration.total_seconds() / 60} minutes.")
                self.tfa_failed_attempts = 0  # Reset attempts after lockout
        
        self._save_state()
    
    def is_tfa_locked_out(self) -> bool:
        """Check if 2FA is currently locked out."""
        if not self.tfa_lockout_end_time:
            return False
        
        if datetime.now() < self.tfa_lockout_end_time:
            return True
        else:
            self._reset_tfa_lockout()
            return False
    
    def get_remaining_tfa_lockout_time(self) -> int:
        """Get remaining 2FA lockout time in seconds."""
        if not self.is_tfa_locked_out():
            return 0
        
        remaining = self.tfa_lockout_end_time - datetime.now()
        return max(0, int(remaining.total_seconds()))
    
    def _reset_tfa_lockout(self):
        """Reset 2FA lockout state."""
        self.tfa_lockout_end_time = None
        self.tfa_failed_attempts = 0
        self.consecutive_tfa_lockouts = 0
        self._save_state()
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes for 2FA recovery."""
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric codes
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
            codes.append(code)
        self._settings['tfa_backup_codes'] = codes
        self._save_state()
        return codes

    def reload_settings(self):
        """Reloads settings from the settings manager."""
        new_settings = self._settings_manager.read_settings() or {}
        logger.info(f"Reloading settings, read_settings returned: {list(new_settings.keys())}")
        
        # Clear settings and reload
        self._settings.clear()
        self._settings.update(new_settings)
        
        # Re-load master password state
        self.failed_attempts = self._settings.get('guardian_failed_attempts', 0)
        self.consecutive_lockouts = self._settings.get('guardian_consecutive_lockouts', 0)
        lockout_end_iso = self._settings.get('guardian_lockout_end_time')
        self.lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None
        
        # Re-load 2FA state
        self.tfa_failed_attempts = self._settings.get('guardian_tfa_failed_attempts', 0)
        self.consecutive_tfa_lockouts = self._settings.get('guardian_consecutive_tfa_lockouts', 0)
        tfa_lockout_end_iso = self._settings.get('guardian_tfa_lockout_end_time')
        self.tfa_lockout_end_time = datetime.fromisoformat(tfa_lockout_end_iso) if tfa_lockout_end_iso else None

        # After reloading settings, validate state but don't save (save only happens on explicit updates)
        # This prevents unnecessary saves that might cause issues
        self._validate_state(save_state=False)
        logger.info(f"After reload, _settings has: {list(self._settings.keys())}")
