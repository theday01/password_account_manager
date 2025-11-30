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


async def trial_notification_loop(trial_manager, notification_interval_seconds: float = 600):
    """
    Periodically sends notifications about trial status.
    
    Behavior:
    - During active trial: Sends notifications at specified interval (default 600s = 10 minutes)
    - After trial expires: Sends notifications EVERY 10 minutes to remind user to activate
    
    Args:
        trial_manager: The TrialManager instance to check trial status
        notification_interval_seconds: How often to send notifications (default 600 = 10 minutes)
    """
    logger.info(f"Starting trial notification loop with {notification_interval_seconds}s interval")
    
    # Initial delay to let the app fully start
    await asyncio.sleep(2)
    
    icon_path = Path(__file__).parent / "icons" / "icon.png"
    notification_count = 0
    max_notifications = 10000  # Prevent infinite notifications (allows ~70 days of 10min notifications)
    last_notification_time = None
    
    try:
        while notification_count < max_notifications:
            try:
                # Check trial status
                trial_status = trial_manager.status
                is_trial_active = trial_manager.is_trial_active
                
                # Get remaining seconds
                remaining_seconds = trial_manager.get_remaining_seconds()
                
                logger.info(f"Trial check - Status: {trial_status}, Active: {is_trial_active}, Remaining: {remaining_seconds}s")
                
                # Determine if we should send a notification
                should_notify = False
                title = ""
                message = ""
                
                if trial_status == "EXPIRED":
                    # Trial has expired - SEND NOTIFICATION EVERY 10 MINUTES
                    should_notify = True
                    title = "SecureVault Pro - Trial Expired"
                    message = "Your trial period has ended. Please activate the program to continue using it.\n\nClick to activate now."
                    logger.warning("Trial expired - sending reminder notification")
                
                elif trial_status == "TRIAL" and is_trial_active and remaining_seconds > 0:
                    # Trial is still active - send notification at interval
                    remaining_time_str = format_remaining_time(remaining_seconds)
                    should_notify = True
                    title = "SecureVault Pro - Trial Active"
                    message = f"Your trial will expire in {remaining_time_str}.\n\nPlease activate to continue using the program after trial ends."
                    logger.info(f"Trial active - sending notification: {remaining_time_str} remaining")
                
                elif trial_status == "TAMPERED":
                    # Tampering detected - send notification
                    should_notify = True
                    title = "SecureVault Pro - Security Alert"
                    message = "Critical security components have been modified.\n\nPlease contact support immediately."
                    logger.error("Tampering detected - sending alert notification")
                
                elif trial_status == "FULL":
                    # Full version activated - stop notifications
                    logger.info("Full version activated - stopping trial notifications")
                    break
                
                # Send the notification if determined necessary
                if should_notify:
                    try:
                        logger.info(f"Sending notification: {title}")
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
                        last_notification_time = asyncio.get_event_loop().time()
                        
                    except Exception as notify_error:
                        logger.error(f"Error sending notification: {notify_error}")
                        # Try fallback anyway
                        try:
                            show_system_notification_fallback(title, message)
                        except Exception as fallback_error:
                            logger.error(f"Fallback notification also failed: {fallback_error}")
                
                # Wait for the specified interval before sending next notification
                logger.info(f"Waiting {notification_interval_seconds}s before next notification check")
                await asyncio.sleep(notification_interval_seconds)
                
            except asyncio.CancelledError:
                logger.info("Trial notification loop was cancelled")
                break
            except Exception as loop_error:
                logger.error(f"Error in trial notification loop: {loop_error}", exc_info=True)
                await asyncio.sleep(30)  # Wait before retrying on error
        
        logger.info(f"Trial notification loop completed ({notification_count} notifications sent)")
        
    except Exception as outer_error:
        logger.error(f"Unexpected error in trial notification loop: {outer_error}", exc_info=True)


def start_trial_notifications(trial_manager, asyncio_manager, notification_interval_seconds: float = 600):
    """
    Starts the trial notification loop using the asyncio manager.
    
    This will send notifications:
    - Every 10 minutes (600 seconds) during trial period
    - Every 10 minutes after trial expires to remind user to activate
    
    Args:
        trial_manager: The TrialManager instance
        asyncio_manager: The AsyncioEventLoopManager instance
        notification_interval_seconds: How often to send notifications (default 600 = 10 minutes)
    
    Returns:
        The asyncio Future/Task object, or None if it couldn't be started
    """
    try:
        logger.info(f"Starting trial notifications with {notification_interval_seconds}s interval")
        future = asyncio_manager.submit_coroutine(
            trial_notification_loop(trial_manager, notification_interval_seconds)
        )
        logger.info("Trial notification coroutine submitted successfully")
        return future
    except Exception as e:
        logger.error(f"Failed to start trial notifications: {e}")
        return None
