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

    # Constants for 2FA protection
    MAX_TFA_ATTEMPTS_BEFORE_LOCKOUT = 4
    TFA_LOCKOUT_MINUTES = 15

    def __init__(self, settings_manager):
        """
        Initializes the AuthGuardian.

        Args:
            settings_manager: An object (like SecureFileManager) that can read/write settings.
        """
        self._settings_manager = settings_manager
        self._settings = self._settings_manager.read_settings() or {}
        
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

        self._validate_state()

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

    def _validate_state(self):
        """Sanity check and cleanup of the loaded state."""
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
        
        self._save_state()

    def _save_state(self):
        """Saves the current state back to the settings file.
        This method preserves all existing settings (like tfa_secret) and only updates guardian-specific state.
        
        Returns:
            bool: True if settings were successfully saved, False otherwise.
        """
        # First, try to load existing settings from disk to preserve them (like tfa_secret)
        # Only do this if encryption key is available (vault is unlocked)
        existing_settings = {}
        if self._settings_manager.encryption_key:
            try:
                existing_settings = self._settings_manager.read_settings()
                if existing_settings is None:
                    existing_settings = {}
                    logger.info("No existing settings file found, starting with empty dict")
                else:
                    logger.info(f"Loaded existing settings before save. Keys: {list(existing_settings.keys())}")
                    if 'tfa_secret' in existing_settings:
                        logger.info(f"Preserving tfa_secret in settings save: {existing_settings['tfa_secret'] is not None}")
            except InvalidTag as e:
                logger.error(f"Failed to decrypt existing settings (InvalidTag) - file may be encrypted with different key: {e}")
                # If decryption fails, we can't read existing settings, so preserve what's in self._settings
                # This shouldn't happen in normal operation, but we handle it gracefully
                existing_settings = self._settings.copy()
                logger.warning("Using current _settings as fallback due to decryption failure")
            except Exception as e:
                logger.warning(f"Could not load existing settings before save: {e}")
                # If we can't read existing settings, we'll try to use what's in self._settings
                existing_settings = self._settings.copy()
        else:
            # No encryption key, can't read existing settings, use current _settings
            logger.info("No encryption key available, cannot read existing settings")
            existing_settings = self._settings.copy()
        
        # Merge existing settings with current _settings (current takes precedence for guardian state)
        # This ensures we preserve all existing settings like tfa_secret
        settings_to_save = {**existing_settings, **self._settings}
        
        # Update guardian-specific state (these always override any existing values)
        settings_to_save['guardian_failed_attempts'] = self.failed_attempts
        settings_to_save['guardian_consecutive_lockouts'] = self.consecutive_lockouts
        settings_to_save['guardian_lockout_end_time'] = self.lockout_end_time.isoformat() if self.lockout_end_time else None
        
        # 2FA state
        settings_to_save['guardian_tfa_failed_attempts'] = self.tfa_failed_attempts
        settings_to_save['guardian_consecutive_tfa_lockouts'] = self.consecutive_tfa_lockouts
        settings_to_save['guardian_tfa_lockout_end_time'] = self.tfa_lockout_end_time.isoformat() if self.tfa_lockout_end_time else None
        
        # Update self._settings to match what we're saving (for consistency)
        self._settings.update(settings_to_save)
        
        try:
            success = self._settings_manager.write_settings(settings_to_save)
            if not success:
                logger.warning("Failed to save guardian state, most likely because the vault is locked.")
                return False
            logger.info(f"Successfully saved settings. Keys: {list(settings_to_save.keys())}")
            if 'tfa_secret' in settings_to_save:
                logger.info(f"tfa_secret preserved in saved settings: {settings_to_save['tfa_secret'] is not None}")
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
            # A successful master password login should also reset any 2FA lockout
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

    def record_tfa_attempt(self, success: bool):
        """
        Records the result of a 2FA attempt and updates the security state.
        
        Args:
            success (bool): True if the 2FA code was correct, False otherwise.
        """
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
                self.tfa_failed_attempts = 0 # Reset attempts after a lockout is triggered

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

    def is_tfa_locked_out(self) -> bool:
        """
        Checks if the account is currently in a 2FA lockout state.

        Returns:
            bool: True if locked out, False otherwise.
        """
        if not self.tfa_lockout_end_time:
            return False
        
        if datetime.now() < self.tfa_lockout_end_time:
            return True
        else:
            self._reset_tfa_lockout()
            return False

    def get_remaining_tfa_lockout_time(self) -> int:
        """
        Gets the remaining 2FA lockout time in seconds.

        Returns:
            int: The number of seconds remaining, or 0 if not locked out.
        """
        if not self.is_tfa_locked_out():
            return 0
        
        remaining = self.tfa_lockout_end_time - datetime.now()
        return max(0, int(remaining.total_seconds()))

    def _reset_tfa_lockout(self):
        """Resets the 2FA lockout state."""
        self.tfa_lockout_end_time = None
        self.tfa_failed_attempts = 0
        self.consecutive_tfa_lockouts = 0
        self._save_state()

    def reload_settings(self):
        """Reloads settings from the settings manager."""
        new_settings = self._settings_manager.read_settings() or {}
        logger.info(f"Reloading settings, read_settings returned: {list(new_settings.keys())}")
        if 'tfa_secret' in new_settings:
            logger.info(f"2FA secret found in reloaded settings: {new_settings['tfa_secret'] is not None}")
        else:
            logger.warning("2FA secret NOT found in reloaded settings")
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

        self._validate_state()
        logger.info(f"After reload, _settings has: {list(self._settings.keys())}")
        if 'tfa_secret' in self._settings:
            logger.info(f"2FA secret in _settings after reload: {self._settings['tfa_secret'] is not None}")
