import threading
import time
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class PasswordReminder:
    def __init__(self, db_manager, parent_window):
        self.db_manager = db_manager
        self.parent_window = parent_window
        self.REMINDER_INTERVAL = 60  # Check every 60 seconds
        self.reminded_accounts = set()
        self.timer = None
        self.logger = logging.getLogger(__name__)
        
        self.logger.info("PasswordReminder initialized")
        self.start()

    def _check_accounts(self):
        try:
            self.logger.debug("Starting account check...")
            now = datetime.now()
            five_minutes_ago = now - timedelta(minutes=5)
            
            metadata_conn = self.db_manager.get_metadata_connection()
            cursor = metadata_conn.execute(
                "SELECT id, name, updated_at FROM accounts WHERE updated_at <= ? AND id != 'master_account'",
                (five_minutes_ago.isoformat(),)
            )
            accounts_to_remind = cursor.fetchall()
            metadata_conn.close()

            self.logger.info(f"Found {len(accounts_to_remind)} accounts older than 5 minutes")

            for account_id, name, updated_at in accounts_to_remind:
                if account_id not in self.reminded_accounts:
                    self.logger.info(f"Adding reminder for account: {name} (ID: {account_id}, Last updated: {updated_at})")
                    self.reminded_accounts.add(account_id)
                    self.parent_window.root.after(0, self.parent_window.load_password_cards)
                    self.parent_window.root.after(0, self.parent_window.update_expired_passwords_count)
                else:
                    self.logger.debug(f"Account {name} (ID: {account_id}) already reminded")
            
            self.logger.debug(f"Account check completed. Total reminded accounts: {len(self.reminded_accounts)}")
                    
        except Exception as e:
            self.logger.error(f"Error during account check: {str(e)}", exc_info=True)
        finally:
            # Reschedule the next check
            self.logger.debug(f"Scheduling next check in {self.REMINDER_INTERVAL} seconds")
            self.timer = threading.Timer(self.REMINDER_INTERVAL, self._check_accounts)
            self.timer.daemon = True
            self.timer.start()

    def start(self):
        self.logger.info("Starting PasswordReminder timer (first check in 30 seconds)")
        # Delay the first check to avoid slowing down the UI at startup
        self.timer = threading.Timer(15, self._check_accounts)
        self.timer.daemon = True
        self.timer.start()

    def stop(self):
        self.logger.info("Stopping PasswordReminder timer")
        if self.timer:
            self.timer.cancel()
            self.logger.info("Timer cancelled successfully")

    def get_reminded_accounts(self):
        self.logger.debug(f"Getting reminded accounts: {len(self.reminded_accounts)} accounts")
        return self.reminded_accounts

    def mark_as_changed(self, account_id):
        if account_id in self.reminded_accounts:
            self.logger.info(f"Removing account {account_id} from reminded list (marked as changed)")
            self.reminded_accounts.remove(account_id)
        else:
            self.logger.debug(f"Account {account_id} not in reminded list")