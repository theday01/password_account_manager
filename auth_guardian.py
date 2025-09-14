import time
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AuthGuardian:
    """
    Manages authentication security, including brute-force protection and lockouts.
    """
    # Constants for the protection mechanism
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
        self._settings = self._settings_manager.read_settings() or {}
        
        # Load state from settings or initialize to defaults
        self.failed_attempts = self._settings.get('guardian_failed_attempts', 0)
        self.consecutive_lockouts = self._settings.get('guardian_consecutive_lockouts', 0)
        
        lockout_end_iso = self._settings.get('guardian_lockout_end_time')
        self.lockout_end_time = datetime.fromisoformat(lockout_end_iso) if lockout_end_iso else None

        self._validate_state()

    def _validate_state(self):
        """Sanity check and cleanup of the loaded state."""
        if self.is_locked_out():
            # If the lockout has expired, reset the state
            if datetime.now() >= self.lockout_end_time:
                logger.info("Lockout period has expired. Resetting state.")
                self._reset_lockout()
        
        if self.failed_attempts < 0:
            self.failed_attempts = 0
        if self.consecutive_lockouts < 0:
            self.consecutive_lockouts = 0
        
        self._save_state()

    def _save_state(self):
        """Saves the current state back to the settings file."""
        self._settings['guardian_failed_attempts'] = self.failed_attempts
        self._settings['guardian_consecutive_lockouts'] = self.consecutive_lockouts
        self._settings['guardian_lockout_end_time'] = self.lockout_end_time.isoformat() if self.lockout_end_time else None
        
        try:
            self._settings_manager.write_settings(self._settings)
        except Exception as e:
            logger.error(f"Failed to save guardian state: {e}")

    def record_login_attempt(self, success: bool):
        """
        Records the result of a login attempt and updates the security state.
        
        Args:
            success (bool): True if the login was successful, False otherwise.
        """
        if success:
            logger.info("Successful login attempt recorded. Resetting guardian state.")
            self.failed_attempts = 0
            # On successful login, we can reset consecutive_lockouts,
            # or keep it to penalize users who repeatedly fail and succeed.
            # For this implementation, we'll reset it to be more forgiving.
            self.consecutive_lockouts = 0
        else:
            self.failed_attempts += 1
            logger.warning(f"Failed login attempt #{self.failed_attempts} recorded.")
            
            if self.failed_attempts >= self.MAX_ATTEMPTS_BEFORE_LOCKOUT:
                self.consecutive_lockouts += 1
                
                if self.consecutive_lockouts == 1:
                    lockout_minutes = self.INITIAL_LOCKOUT_MINUTES
                else:
                    # Subsequent lockouts add 30 minutes to the initial 60-minute lockout
                    lockout_minutes = self.INITIAL_LOCKOUT_MINUTES + (self.consecutive_lockouts - 1) * self.SUBSEQUENT_LOCKOUT_INCREMENT_MINUTES
                
                self.lockout_end_time = datetime.now() + timedelta(minutes=lockout_minutes)
                logger.warning(f"Maximum login attempts reached. Account locked for {lockout_minutes} minutes.")

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
        # `consecutive_lockouts` is not reset, to penalize repeated lockouts.
        self._save_state()
