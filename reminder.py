import threading
from ui_utils import show_reminder_dialog

class ReminderManager:
    """
    Manages a recurring reminder to activate the software during the trial period.
    """
    def __init__(self, trial_manager, parent_window):
        self.trial_manager = trial_manager
        self.parent_window = parent_window
        #self.REMINDER_INTERVAL = 3 * 60 * 60  # 3 hours in seconds
        self.REMINDER_INTERVAL = 30  # 30 seconds
        self.timer = None
        self.start()

    def _show_reminder(self):
        """
        Shows the reminder dialog if the trial is active and then reschedules the timer.
        """
        if self.trial_manager.is_trial_active:
            remaining_seconds = self.trial_manager.get_remaining_seconds()
            if remaining_seconds > 0:
                # Ensure the dialog is created in the main UI thread
                self.parent_window.after(0, show_reminder_dialog, self.parent_window, remaining_seconds, self.activate_now)
        
        # Reschedule the next reminder
        self.start()

    def activate_now(self):
        """
        Placeholder for the activation logic.
        """
        if hasattr(self.parent_window, 'show_activation_dialog'):
            self.parent_window.show_activation_dialog()

    def start(self):
        """
        Starts the recurring timer if the trial is active.
        """
        if self.trial_manager.is_trial_active:
            self.timer = threading.Timer(self.REMINDER_INTERVAL, self._show_reminder)
            self.timer.daemon = True
            self.timer.start()

    def stop(self):
        """
        Stops the timer.
        """
        if self.timer:
            self.timer.cancel()
