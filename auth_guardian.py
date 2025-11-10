import time
import logging
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

class AuthGuardian:
    """
    Manages authentication security, including brute-force protection and lockouts.
    """
    # Constants for master password protection
    MAX_ATTEMPTS_BEFORE_LOCKOUT = 3
    INITIAL_LOCKOUT_MINUTES = 60
    SUBSEQUENT_LOCKOUT_INCREMENT_MINUTES = 30

    def __init__(self, settings_manager):
        """
        Initializes the AuthGuardian.

        Args:
            settings_manager: An object (like SecureFileManager) that can read/write settings.
        """
        self._settings_manager = settings_manager
        raw_settings = self._settings_manager.read_settings() or {}
        
        # Filter out legacy keys that are no longer used
        self._settings = {}
        legacy_keys_to_remove = ['tfa_secret', 'guardian_tfa_failed_attempts', 'guardian_consecutive_tfa_lockouts', 'guardian_tfa_lockout_end_time']
        for key, value in raw_settings.items():
            if key not in legacy_keys_to_remove:
                self._settings[key] = value
        
        # Load master password state from settings
        self.failed_attempts = self._settings.get('guardian_failed_attempts', 0)
        self.consecutive_lockouts = self._settings.get('guardian_consecutive_lockouts', 0)
        lockout_end_iso = self._settings.get('guardian_lockout_end_time')
        self.lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None

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

        # Sanity checks for all state variables
        self.failed_attempts = max(0, self.failed_attempts)
        self.consecutive_lockouts = max(0, self.consecutive_lockouts)
        
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
        
        # Start with existing settings from disk to preserve them (excluding legacy keys)
        settings_to_save = {}
        legacy_keys_to_remove = ['tfa_secret', 'guardian_tfa_failed_attempts', 'guardian_consecutive_tfa_lockouts', 'guardian_tfa_lockout_end_time']
        for key, value in (existing_settings.items() if existing_settings else {}):
            if key not in legacy_keys_to_remove:
                settings_to_save[key] = value
        
        # Merge all other settings from self._settings (excluding legacy keys)
        # This preserves any other settings that were updated
        for key, value in self._settings.items():
            if key not in legacy_keys_to_remove:
                settings_to_save[key] = value
        
        # Update guardian-specific state (these always override any existing values)
        settings_to_save['guardian_failed_attempts'] = self.failed_attempts
        settings_to_save['guardian_consecutive_lockouts'] = self.consecutive_lockouts
        settings_to_save['guardian_lockout_end_time'] = self.lockout_end_time.isoformat() if self.lockout_end_time else None
        
        # Update all other settings from settings_to_save (except guardian state keys)
        for key, value in settings_to_save.items():
            if key not in ['guardian_failed_attempts', 'guardian_consecutive_lockouts', 'guardian_lockout_end_time']:
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

    def reload_settings(self):
        """Reloads settings from the settings manager."""
        new_settings = self._settings_manager.read_settings() or {}
        logger.info(f"Reloading settings, read_settings returned: {list(new_settings.keys())}")
        
        # Clear settings and reload (excluding legacy keys)
        self._settings.clear()
        legacy_keys_to_remove = ['tfa_secret', 'guardian_tfa_failed_attempts', 'guardian_consecutive_tfa_lockouts', 'guardian_tfa_lockout_end_time']
        for key, value in new_settings.items():
            if key not in legacy_keys_to_remove:
                self._settings[key] = value
        
        # Re-load master password state
        self.failed_attempts = self._settings.get('guardian_failed_attempts', 0)
        self.consecutive_lockouts = self._settings.get('guardian_consecutive_lockouts', 0)
        lockout_end_iso = self._settings.get('guardian_lockout_end_time')
        self.lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None

        # After reloading settings, validate state but don't save (save only happens on explicit updates)
        # This prevents unnecessary saves that might cause issues
        self._validate_state(save_state=False)
        logger.info(f"After reload, _settings has: {list(self._settings.keys())}")
