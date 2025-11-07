import threading
import time
from datetime import datetime, timedelta

class PasswordReminder:
    def __init__(self, db_manager, parent_window):
        self.db_manager = db_manager
        self.parent_window = parent_window
        self.REMINDER_INTERVAL = 60  # Check every 60 seconds
        self.reminded_accounts = set()
        self.timer = None
        self.start()

    def _check_accounts(self):
        try:
            now = datetime.now()
            five_minutes_ago = now - timedelta(minutes=5)
            
            metadata_conn = self.db_manager.get_metadata_connection()
            cursor = metadata_conn.execute("SELECT id, name, updated_at FROM accounts WHERE updated_at <= ?", (five_minutes_ago.isoformat(),))
            accounts_to_remind = cursor.fetchall()
            metadata_conn.close()

            for account_id, name, updated_at in accounts_to_remind:
                if account_id not in self.reminded_accounts:
                    self.reminded_accounts.add(account_id)
                    self.parent_window.root.after(0, self.parent_window.load_password_cards) # Refresh UI
                    self.parent_window.root.after(0, self.parent_window.update_expired_passwords_count)
                    
        finally:
            # Reschedule the next check
            self.timer = threading.Timer(self.REMINDER_INTERVAL, self._check_accounts)
            self.timer.daemon = True
            self.timer.start()

    def start(self):
        self.timer = threading.Timer(self.REMINDER_INTERVAL, self._check_accounts)
        self.timer.daemon = True
        self.timer.start()

    def stop(self):
        if self.timer:
            self.timer.cancel()

    def get_reminded_accounts(self):
        return self.reminded_accounts

    def mark_as_changed(self, account_id):
        if account_id in self.reminded_accounts:
            self.reminded_accounts.remove(account_id)
