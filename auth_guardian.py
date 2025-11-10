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
        
        # Track if tfa_secret was explicitly modified (to distinguish from "not loaded yet")
        self._tfa_secret_explicitly_set = False
        self._tfa_secret_explicitly_removed = False
        
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
            value: The new value for the setting. If value is None and key is 'tfa_secret',
                   the key will be removed from settings (2FA disabled).
        
        Returns:
            bool: True if the setting was successfully saved, False otherwise.
        """
        logger.info(f"Updating setting '{key}' and persisting changes.")
        # Special handling for disabling 2FA: remove the key entirely
        if key == 'tfa_secret' and value is None:
            logger.info("Disabling 2FA: removing tfa_secret key from settings")
            if key in self._settings:
                del self._settings[key]
            # Mark that we explicitly removed tfa_secret
            self._tfa_secret_explicitly_removed = True
            self._tfa_secret_explicitly_set = False
        elif key == 'tfa_secret':
            # Setting tfa_secret to a value (enabling 2FA)
            self._settings[key] = value
            # Mark that we explicitly set tfa_secret
            self._tfa_secret_explicitly_set = True
            self._tfa_secret_explicitly_removed = False
        else:
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
        This method preserves all existing settings (like tfa_secret) and only updates guardian-specific state.
        
        Returns:
            bool: True if settings were successfully saved, False otherwise.
        """
        # CRITICAL: We MUST have an encryption key to save settings
        # If we don't have a key, we can't read existing settings, so we can't safely save
        if not self._settings_manager.encryption_key:
            logger.warning("Cannot save state - encryption key is not available. Settings will be saved after authentication.")
            return False
        
        # First, try to load existing settings from disk to preserve them (like tfa_secret)
        existing_settings = {}
        try:
            existing_settings = self._settings_manager.read_settings()
            if existing_settings is None:
                existing_settings = {}
                logger.info("No existing settings file found, starting with empty dict")
            else:
                logger.info(f"Loaded existing settings before save. Keys: {list(existing_settings.keys())}")
                if 'tfa_secret' in existing_settings:
                    logger.info(f"Found tfa_secret in existing settings (2FA enabled): {existing_settings['tfa_secret'] is not None}")
                else:
                    logger.info("tfa_secret not found in existing settings (2FA disabled)")
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
        
        # Start with existing settings from disk to preserve all settings EXCEPT tfa_secret
        # tfa_secret will be handled explicitly below
        settings_to_save = {}
        for key, value in (existing_settings.items() if existing_settings else {}):
            if key != 'tfa_secret':  # Don't copy tfa_secret yet - handle it explicitly
                settings_to_save[key] = value
        
        # CRITICAL: Handle tfa_secret explicitly - this is the key to fixing enable/disable
        # Priority order:
        # 1. If explicitly set/removed via update_setting() - use that (flags set)
        # 2. Otherwise, use self._settings (which was loaded via reload_settings() from disk)
        # This ensures that after reload_settings(), we use the reloaded state, not stale existing_settings
        if self._tfa_secret_explicitly_set and 'tfa_secret' in self._settings:
            # 2FA is being explicitly enabled or updated - set the value from self._settings
            settings_to_save['tfa_secret'] = self._settings['tfa_secret']
            logger.info(f"2FA is being enabled/updated - setting tfa_secret in settings_to_save (length: {len(str(self._settings['tfa_secret']))})")
        elif self._tfa_secret_explicitly_removed:
            # 2FA is being explicitly disabled - remove the key from settings_to_save
            # Even if it exists in existing_settings, we're removing it
            if 'tfa_secret' in settings_to_save:
                logger.info(f"2FA is being disabled - removing tfa_secret key from settings_to_save (was: {len(str(settings_to_save['tfa_secret']))} chars)")
                del settings_to_save['tfa_secret']
            # Double-check it's actually removed
            if 'tfa_secret' in settings_to_save:
                logger.error("CRITICAL: Failed to remove tfa_secret from settings_to_save!")
                del settings_to_save['tfa_secret']  # Force remove
            else:
                logger.info("Confirmed: tfa_secret successfully removed from settings_to_save (2FA disabled)")
        elif 'tfa_secret' in self._settings:
            # tfa_secret is in self._settings (from reload_settings) - use it
            # This is the normal case after reload_settings() - self._settings reflects disk state
            settings_to_save['tfa_secret'] = self._settings['tfa_secret']
            logger.info(f"Using tfa_secret from self._settings (from reload) - 2FA enabled, length: {len(str(self._settings['tfa_secret']))}")
        else:
            # tfa_secret is NOT in self._settings - 2FA is disabled
            # Don't add it to settings_to_save, even if it exists in existing_settings
            # This ensures that if 2FA was disabled, it stays disabled
            logger.info("tfa_secret not in self._settings - 2FA is disabled, not adding to settings_to_save")
        
        # Merge all other settings from self._settings (except tfa_secret which we handled above)
        # This preserves any other settings that were updated
        # CRITICAL: Never add tfa_secret back here - it's already handled explicitly above
        for key, value in self._settings.items():
            if key != 'tfa_secret':  # tfa_secret already handled above - DO NOT add it here
                settings_to_save[key] = value
        
        # Final safety check: If we explicitly removed tfa_secret, ensure it's not in settings_to_save
        if self._tfa_secret_explicitly_removed and 'tfa_secret' in settings_to_save:
            logger.error("CRITICAL: tfa_secret is still in settings_to_save after explicit removal! Removing it now.")
            del settings_to_save['tfa_secret']
        
        # Final safety check: Log the final state before saving
        if 'tfa_secret' in settings_to_save:
            logger.info(f"FINAL CHECK: tfa_secret WILL be saved (2FA enabled): {len(str(settings_to_save['tfa_secret']))} chars")
        else:
            logger.info("FINAL CHECK: tfa_secret WILL NOT be saved (2FA disabled)")
        
        # Update guardian-specific state (these always override any existing values)
        settings_to_save['guardian_failed_attempts'] = self.failed_attempts
        settings_to_save['guardian_consecutive_lockouts'] = self.consecutive_lockouts
        settings_to_save['guardian_lockout_end_time'] = self.lockout_end_time.isoformat() if self.lockout_end_time else None
        
        # 2FA state
        settings_to_save['guardian_tfa_failed_attempts'] = self.tfa_failed_attempts
        settings_to_save['guardian_consecutive_tfa_lockouts'] = self.consecutive_tfa_lockouts
        settings_to_save['guardian_tfa_lockout_end_time'] = self.tfa_lockout_end_time.isoformat() if self.tfa_lockout_end_time else None
        
        # Update self._settings to match what we're saving (for consistency)
        # CRITICAL: Sync tfa_secret state - if it was removed from settings_to_save, remove it from self._settings
        if 'tfa_secret' in settings_to_save:
            # tfa_secret is in settings_to_save - add/update it in self._settings
            self._settings['tfa_secret'] = settings_to_save['tfa_secret']
        elif 'tfa_secret' not in settings_to_save:
            # tfa_secret is NOT in settings_to_save - ensure it's removed from self._settings
            if 'tfa_secret' in self._settings:
                logger.info("Removing tfa_secret from self._settings to match settings_to_save (2FA disabled)")
                del self._settings['tfa_secret']
        
        # Update all other settings from settings_to_save (except guardian state keys and tfa_secret)
        for key, value in settings_to_save.items():
            if key not in ['guardian_failed_attempts', 'guardian_consecutive_lockouts', 'guardian_lockout_end_time', 
                          'guardian_tfa_failed_attempts', 'guardian_consecutive_tfa_lockouts', 'guardian_tfa_lockout_end_time', 'tfa_secret']:
                # Guardian state keys and tfa_secret are managed separately
                self._settings[key] = value
        
        try:
            # Log what we're about to save
            logger.info(f"About to save settings. Keys to save: {list(settings_to_save.keys())}")
            if 'tfa_secret' in settings_to_save:
                logger.info(f"tfa_secret will be saved (2FA enabled): {len(str(settings_to_save['tfa_secret']))} chars")
            else:
                logger.info("tfa_secret will NOT be saved (2FA disabled)")
            
            success = self._settings_manager.write_settings(settings_to_save)
            if not success:
                logger.error("Failed to save guardian state, most likely because the vault is locked.")
                return False
            
            # Verify the settings were actually written by reading them back
            # This is CRITICAL for 2FA state persistence - we must verify the save was successful
            import time
            time.sleep(0.2)  # Small delay to ensure file system has flushed
            
            verify_settings = None
            try:
                verify_settings = self._settings_manager.read_settings()
            except Exception as e:
                logger.error(f"Failed to read settings for verification: {e}")
                # This is a critical error - we can't verify the save
                return False
            
            if verify_settings is None:
                logger.error("Failed to verify saved settings - read_settings returned None")
                return False
            
            verify_tfa_exists = 'tfa_secret' in verify_settings
            expected_tfa_exists = 'tfa_secret' in settings_to_save
            
            if verify_tfa_exists != expected_tfa_exists:
                logger.error(f"CRITICAL: Settings verification failed! Expected tfa_secret={'present' if expected_tfa_exists else 'absent'}, but found {'present' if verify_tfa_exists else 'absent'}")
                logger.error(f"Settings keys on disk: {list(verify_settings.keys())}")
                logger.error(f"Settings keys we tried to save: {list(settings_to_save.keys())}")
                # This is a critical error - the save didn't work as expected
                return False
            
            if verify_tfa_exists:
                if verify_settings['tfa_secret'] != settings_to_save['tfa_secret']:
                    logger.error("CRITICAL: Settings verification failed! tfa_secret value mismatch")
                    return False
                logger.info(f"Verified: tfa_secret was correctly saved (2FA enabled, {len(str(verify_settings['tfa_secret']))} chars)")
            else:
                logger.info("Verified: tfa_secret was correctly removed from disk (2FA disabled)")
            
            logger.info(f"Successfully saved settings. Keys: {list(settings_to_save.keys())}")
            if 'tfa_secret' in settings_to_save:
                logger.info(f"tfa_secret preserved in saved settings: {settings_to_save['tfa_secret'] is not None}")
            else:
                logger.info("tfa_secret is None or missing in the saved settings (2FA is disabled).")
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
            if new_settings['tfa_secret'] is not None:
                logger.info(f"2FA secret found in reloaded settings (2FA enabled): {len(str(new_settings['tfa_secret']))} chars")
            else:
                logger.warning("2FA secret found but is None - removing it (treating as disabled)")
                # Remove None values for tfa_secret - if it's None, treat it as disabled (key should not exist)
                del new_settings['tfa_secret']
        else:
            logger.info("2FA secret NOT found in reloaded settings (2FA disabled)")
        
        # Clear settings and reload
        self._settings.clear()
        self._settings.update(new_settings)
        
        # Reset the explicit modification flags after reload
        # This ensures that after reload, we preserve the loaded state unless explicitly changed
        self._tfa_secret_explicitly_set = False
        self._tfa_secret_explicitly_removed = False
        
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
        if 'tfa_secret' in self._settings:
            logger.info(f"2FA secret in _settings after reload: {self._settings['tfa_secret'] is not None}")
