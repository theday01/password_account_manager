import asyncio
import logging
from datetime import timedelta
from notification_manager import send_safe_notification, show_system_notification_fallback
from pathlib import Path

logger = logging.getLogger(__name__)


def format_remaining_time(remaining_seconds: float) -> str:
    """Format remaining seconds into a readable string."""
    if remaining_seconds <= 0:
        return "0 seconds"
    
    remaining_seconds = int(remaining_seconds)
    days = remaining_seconds // 86400
    hours = (remaining_seconds % 86400) // 3600
    minutes = (remaining_seconds % 3600) // 60
    seconds = remaining_seconds % 60
    
    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days > 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours > 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes > 1 else ''}")
    if seconds > 0 and not parts:  # Only show seconds if nothing else
        parts.append(f"{seconds} second{'s' if seconds > 1 else ''}")
    
    if len(parts) > 1:
        return ", ".join(parts[:-1]) + f" and {parts[-1]}"
    return parts[0] if parts else "0 seconds"


async def trial_notification_loop(trial_manager, notification_interval_seconds: float = 120):
    """
    Periodically sends a notification about trial time remaining.
    
    Args:
        trial_manager: The TrialManager instance to check trial status
        notification_interval_seconds: How often to send notifications (default 120 = 2 minutes)
    """
    logger.info(f"Starting trial notification loop with {notification_interval_seconds}s interval")
    
    # Initial delay to let the app fully start
    await asyncio.sleep(5)
    
    icon_path = Path(__file__).parent / "icons" / "icon.png"
    notification_count = 0
    max_notifications = 1000  # Prevent infinite notifications
    
    try:
        while notification_count < max_notifications:
            try:
                # Check if trial is still active
                if not trial_manager.is_trial_active and trial_manager.status != "TRIAL":
                    logger.info("Trial is no longer active, stopping notification loop")
                    break
                
                # Get remaining time
                remaining_seconds = trial_manager.get_remaining_seconds()
                
                if remaining_seconds <= 0:
                    logger.info("Trial time expired, stopping notification loop")
                    break
                
                # Format the remaining time
                remaining_time_str = format_remaining_time(remaining_seconds)
                
                # Create notification message
                title = "SecureVault Pro - Trial Expiring"
                message = f"Your trial will expire in {remaining_time_str}. Please activate to continue using the program."
                
                logger.info(f"Sending trial notification: {remaining_time_str} remaining")
                
                # Try to send notification
                try:
                    success = await send_safe_notification(
                        title=title,
                        message=message,
                        icon_path=icon_path
                    )
                    
                    if not success:
                        # Fallback to system notification
                        logger.warning("Async notification failed, trying system fallback")
                        show_system_notification_fallback(title, message)
                    
                    notification_count += 1
                    
                except Exception as notify_error:
                    logger.error(f"Error sending trial notification: {notify_error}")
                    # Try fallback anyway
                    try:
                        show_system_notification_fallback(title, message)
                    except Exception as fallback_error:
                        logger.error(f"Fallback notification also failed: {fallback_error}")
                
                # Wait for the specified interval before sending next notification
                await asyncio.sleep(notification_interval_seconds)
                
            except asyncio.CancelledError:
                logger.info("Trial notification loop was cancelled")
                break
            except Exception as loop_error:
                logger.error(f"Error in trial notification loop: {loop_error}")
                await asyncio.sleep(10)  # Wait before retrying on error
        
        logger.info(f"Trial notification loop completed ({notification_count} notifications sent)")
        
    except Exception as outer_error:
        logger.error(f"Unexpected error in trial notification loop: {outer_error}")


def start_trial_notifications(trial_manager, asyncio_manager, notification_interval_seconds: float = 120):
    """
    Starts the trial notification loop using the asyncio manager.
    
    Args:
        trial_manager: The TrialManager instance
        asyncio_manager: The AsyncioEventLoopManager instance
        notification_interval_seconds: How often to send notifications (default 120 = 2 minutes)
    
    Returns:
        The asyncio Future/Task object, or None if it couldn't be started
    """
    try:
        logger.info("Submitting trial notification coroutine to asyncio manager")
        future = asyncio_manager.submit_coroutine(
            trial_notification_loop(trial_manager, notification_interval_seconds)
        )
        logger.info("Trial notification coroutine submitted successfully")
        return future
    except Exception as e:
        logger.error(f"Failed to start trial notifications: {e}")
        return None
