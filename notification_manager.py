import asyncio
from desktop_notifier import DesktopNotifier

notifier = DesktopNotifier()

async def _periodic_sender():
    """
    An async function that sends a notification every 4 minutes.
    """
    while True:
        try:
            await notifier.send(
                title="Backup Reminder",
                message="It’s time to back up your data to keep everything safe and secure.",
            )
        except Exception as e:
            print(f"Error sending notification: {e}")
        await asyncio.sleep(240)  # 4 minutes

def start_notification_loop():
    """
    Starts the notification loop. This function is meant to be run in a thread.
    """
    try:
        asyncio.run(_periodic_sender())
    except Exception as e:
        # It's good practice to log exceptions in a thread
        print(f"Error in notification loop: {e}")

if __name__ == "__main__":
    start_notification_loop()
