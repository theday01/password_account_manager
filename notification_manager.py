import asyncio
from desktop_notifier import DesktopNotifier, Icon
from pathlib import Path
import os

# Create notifier with custom app name
notifier = DesktopNotifier(app_name="SecureVault Pro")

async def _periodic_sender(is_trial_active: bool):
    """
    An async function that sends a notification every 4 minutes, unless in trial.
    """
    if is_trial_active:
        # Do not send backup reminders during the trial period
        return

    while True:
        try:
            # Get the icon path
            icon_path = Path(__file__).parent / "icons" / "main.ico"
            
            # Send notification with icon if available
            if icon_path.exists():
                await notifier.send(
                    title="Backup Reminder",
                    message="It's time to back up your data to keep everything safe and secure.",
                    icon=Icon(icon_path)
                )
            else:
                # Fallback without icon if file doesn't exist
                await notifier.send(
                    title="Backup Reminder",
                    message="It's time to back up your data to keep everything safe and secure.",
                )
        except Exception as e:
            print(f"Error sending notification: {e}")
        await asyncio.sleep(240)  # 4 minutes

def start_notification_loop(is_trial_active: bool):
    """
    Starts the notification loop. This function is meant to be run in a thread.
    """
    try:
        asyncio.run(_periodic_sender(is_trial_active=is_trial_active))
    except Exception as e:
        # It's good practice to log exceptions in a thread
        print(f"Error in notification loop: {e}")

if __name__ == "__main__":
    start_notification_loop()