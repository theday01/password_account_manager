import asyncio
import logging
from desktop_notifier import DesktopNotifier, Icon, Notification
from pathlib import Path
import os
import sys

logger = logging.getLogger(__name__)

# Create notifier with custom app name and error handling
notifier = DesktopNotifier(
    app_name="SecureVault Pro",
    notification_limit=10  # Limit concurrent notifications
)

async def send_safe_notification(title: str, message: str, icon_path: Path = None):
    """
    Send a notification with comprehensive error handling and fallbacks.
    """
    try:
        # Create notification object
        notification = Notification(
            title=title,
            message=message,
            app_name="SecureVault Pro"
        )
        
        # Add icon if available and valid
        if icon_path and icon_path.exists() and icon_path.suffix.lower() in ['.ico', '.png', '.jpg', '.jpeg']:
            try:
                notification.icon = Icon(icon_path)
            except Exception as icon_error:
                logger.warning(f"Failed to load icon {icon_path}: {icon_error}")
                # Continue without icon
        
        # Attempt to send notification with timeout
        try:
            await asyncio.wait_for(notifier.send(notification), timeout=10.0)
            logger.info(f"Notification sent successfully: {title}")
            return True
            
        except asyncio.TimeoutError:
            logger.error("Notification send timed out")
            return False
            
        except Exception as send_error:
            logger.error(f"Failed to send notification via primary method: {send_error}")
            
            # Fallback: Try without icon
            if notification.icon:
                logger.info("Attempting to send notification without icon...")
                notification.icon = None
                try:
                    await asyncio.wait_for(notifier.send(notification), timeout=5.0)
                    logger.info("Notification sent successfully (without icon)")
                    return True
                except Exception as fallback_error:
                    logger.error(f"Fallback notification also failed: {fallback_error}")
            
            # Final fallback: Try with basic notifier
            try:
                basic_notifier = DesktopNotifier(app_name="SecureVault")
                basic_notification = Notification(title=title, message=message)
                await asyncio.wait_for(basic_notifier.send(basic_notification), timeout=5.0)
                logger.info("Notification sent via basic notifier")
                return True
            except Exception as basic_error:
                logger.error(f"Basic notification fallback failed: {basic_error}")
            
            return False
            
    except Exception as outer_error:
        logger.error(f"Unexpected error in notification system: {outer_error}")
        return False

async def _periodic_sender(is_trial_active: bool):
    """
    An async function that sends a notification every 4 minutes, unless in trial.
    Enhanced with better error handling and system compatibility checks.
    """
    if is_trial_active:
        logger.info("Trial mode active - backup notifications disabled")
        return

    # Initial delay to let the app fully start
    await asyncio.sleep(30)
    
    # Get the icon path
    icon_path = Path(__file__).parent / "icons" / "main.ico"
    
    # Check if we're on Windows and have potential permission issues
    if sys.platform == "win32":
        try:
            # Test if notifications work at startup
            test_success = await send_safe_notification(
                "SecureVault Pro", 
                "Notification system initialized successfully.",
                icon_path
            )
            if not test_success:
                logger.warning("Notification system test failed - notifications may not work")
        except Exception as test_error:
            logger.error(f"Notification system test error: {test_error}")
    
    notification_count = 0
    max_notifications = 50  # Prevent infinite notifications if something goes wrong
    
    while notification_count < max_notifications:
        try:
            await asyncio.sleep(240)  # 4 minutes
            
            success = await send_safe_notification(
                "Backup Reminder",
                "It's time to back up your data to keep everything safe and secure.",
                icon_path
            )
            
            if success:
                notification_count += 1
                logger.info(f"Backup reminder #{notification_count} sent successfully")
            else:
                logger.warning(f"Failed to send backup reminder #{notification_count + 1}")
                # Don't increment counter for failed notifications
                
        except asyncio.CancelledError:
            logger.info("Periodic notification sender was cancelled")
            break
        except Exception as e:
            logger.error(f"Error in periodic notification loop: {e}")
            await asyncio.sleep(60)  # Wait a bit before retrying
    
    logger.info("Periodic notification sender completed")

async def send_trial_notification(remaining_time: str):
    """
    Send a trial expiration notification with enhanced error handling.
    """
    icon_path = Path(__file__).parent / "icons" / "main.ico"
    
    success = await send_safe_notification(
        "Trial Period Ending Soon",
        f"Your trial is about to end in {remaining_time}. Please activate to keep using SecureVault Pro.",
        icon_path
    )
    
    if not success:
        logger.warning("Failed to send trial notification")
    
    return success

def send_trial_notification_sync(remaining_time: str):
    """
    Synchronous wrapper for send_trial_notification.
    This can be called from non-async contexts.
    """
    try:
        # First try the system fallback method (more reliable on Windows)
        logger.info("Attempting to send trial notification via system fallback...")
        success = show_system_notification_fallback(
            "Trial Period Ending Soon",
            f"Your trial is about to end in {remaining_time}. Please activate to keep using SecureVault Pro."
        )
        
        if success:
            logger.info("Trial notification sent successfully via system fallback")
            return True
        
        # If system fallback fails, try the async method
        logger.info("System fallback failed, trying async notification...")
        try:
            # Try to get the existing event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If the loop is running, schedule the coroutine as a task
                task = asyncio.create_task(send_trial_notification(remaining_time))
                logger.info("Trial notification scheduled as async task")
                return task
            else:
                # If no loop is running, run until complete
                return asyncio.run(send_trial_notification(remaining_time))
        except RuntimeError:
            # If we can't get a loop, try to create one
            try:
                return asyncio.run(send_trial_notification(remaining_time))
            except Exception as e:
                logger.error(f"Failed to send trial notification via async method: {e}")
                return False
                
    except Exception as e:
        logger.error(f"Failed to send trial notification: {e}")
        return False

# Alternative notification method for systems where desktop_notifier fails
def show_system_notification_fallback(title: str, message: str):
    """
    Fallback notification method using system-specific approaches.
    """
    try:
        if sys.platform == "win32":
            # Windows notification fallback - try multiple methods
            logger.info("Attempting Windows notification methods...")
            
            # Method 1: Try win32gui (most reliable for Windows)
            try:
                import win32gui
                import win32con
                logger.info("Using win32gui for notification")
                win32gui.MessageBox(0, message, title, win32con.MB_ICONINFORMATION | win32con.MB_TOPMOST)
                return True
            except ImportError:
                logger.warning("win32gui not available, trying alternative methods...")
            except Exception as win32_error:
                logger.warning(f"win32gui failed: {win32_error}, trying alternatives...")
            
            # Method 2: Try tkinter messagebox (always available with Python)
            try:
                import tkinter as tk
                from tkinter import messagebox
                logger.info("Using tkinter messagebox for notification")
                root = tk.Tk()
                root.withdraw()  # Hide the main window
                root.attributes('-topmost', True)  # Make it topmost
                root.lift()  # Bring to front
                messagebox.showinfo(title, message)
                root.destroy()
                return True
            except Exception as tk_error:
                logger.error(f"Tkinter fallback failed: {tk_error}")
            
            # Method 3: Try Windows toast notification via PowerShell
            try:
                import subprocess
                logger.info("Using PowerShell for Windows toast notification")
                ps_script = f'''
                Add-Type -AssemblyName System.Windows.Forms
                $notification = New-Object System.Windows.Forms.NotifyIcon
                $notification.Icon = [System.Drawing.SystemIcons]::Information
                $notification.BalloonTipTitle = "{title}"
                $notification.BalloonTipText = "{message}"
                $notification.Visible = $true
                $notification.ShowBalloonTip(5000)
                Start-Sleep -Seconds 6
                $notification.Dispose()
                '''
                subprocess.run([
                    "powershell", "-Command", ps_script
                ], check=True, timeout=10)
                return True
            except Exception as ps_error:
                logger.error(f"PowerShell notification failed: {ps_error}")
            
            # Method 4: Try Windows 10+ toast notification via ctypes
            try:
                import ctypes
                from ctypes import wintypes
                logger.info("Using ctypes for Windows notification")
                
                # Load user32.dll
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32
                
                # Show a simple message box using ctypes
                result = user32.MessageBoxW(
                    0,  # hWnd
                    message,  # lpText
                    title,  # lpCaption
                    0x40 | 0x1000  # MB_ICONINFORMATION | MB_TOPMOST
                )
                return result != 0
            except Exception as ctypes_error:
                logger.error(f"ctypes notification failed: {ctypes_error}")
        
        elif sys.platform == "darwin":  # macOS
            try:
                import subprocess
                subprocess.run([
                    "osascript", "-e", 
                    f'display notification "{message}" with title "{title}"'
                ], check=True)
                return True
            except subprocess.CalledProcessError as mac_error:
                logger.error(f"macOS notification failed: {mac_error}")
        
        elif sys.platform.startswith("linux"):  # Linux
            try:
                import subprocess
                subprocess.run([
                    "notify-send", title, message
                ], check=True)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError) as linux_error:
                logger.error(f"Linux notification failed: {linux_error}")
    
    except Exception as fallback_error:
        logger.error(f"System notification fallback failed: {fallback_error}")
    
    # Final fallback: Console notification
    try:
        print(f"\n{'='*60}")
        print(f"NOTIFICATION: {title}")
        print(f"{'='*60}")
        print(f"{message}")
        print(f"{'='*60}\n")
        logger.info("Notification displayed via console fallback")
        return True
    except Exception as console_error:
        logger.error(f"Console notification fallback failed: {console_error}")
    
    return False

# Initialize logging for the notification system
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test the notification system
    async def test_notifications():
        print("Testing notification system...")
        
        # Test basic notification
        success1 = await send_safe_notification("Test", "Basic notification test")
        print(f"Basic notification: {'Success' if success1 else 'Failed'}")
        
        # Test notification with icon
        icon_path = Path("icons/main.ico")
        success2 = await send_safe_notification("Test", "Icon notification test", icon_path)
        print(f"Icon notification: {'Success' if success2 else 'Failed'}")
        
        # Test fallback method
        success3 = show_system_notification_fallback("Test", "Fallback notification test")
        print(f"Fallback notification: {'Success' if success3 else 'Failed'}")
    
    # Run test
    asyncio.run(test_notifications())