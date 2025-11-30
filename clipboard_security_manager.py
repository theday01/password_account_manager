"""
ClipboardSecurityManager: Advanced clipboard protection and monitoring
Implements secure password clipboard operations with automatic clearing,
monitoring, and prevention of unauthorized clipboard access.

Features:
- Auto-clear clipboard after configurable timeout
- Clipboard content obfuscation
- Clipboard access monitoring
- Prevent accidental password leaks
- Optional clipboard disable mode
"""

import os
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
import json

logger = logging.getLogger(__name__)

# Try to import clipboard libraries
try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False
    logger.warning("pyperclip not available. Install with: pip install pyperclip")

try:
    import ctypes
    from ctypes import wintypes
    CTYPES_AVAILABLE = True
except ImportError:
    CTYPES_AVAILABLE = False

# Try to import Tkinter as fallback
try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


@dataclass
class ClipboardEvent:
    """Represents a clipboard access event."""
    event_type: str  # "copy", "clear", "access_attempt"
    timestamp: str
    content_length: Optional[int] = None
    source: Optional[str] = None  # "user", "system", "unknown"
    

class ClipboardSecurityManager:
    """
    Advanced clipboard security management system.
    Protects passwords and sensitive data in the clipboard.
    """
    
    # Default timeout for auto-clearing (seconds)
    DEFAULT_CLEAR_TIMEOUT = 30
    
    # Obfuscation character for display
    OBFUSCATION_CHAR = "•"
    
    def __init__(self, auto_clear_timeout: int = DEFAULT_CLEAR_TIMEOUT,
                 enable_monitoring: bool = True, enable_obfuscation: bool = True):
        """
        Initialize the ClipboardSecurityManager.
        
        Args:
            auto_clear_timeout: Seconds before auto-clearing (0 to disable)
            enable_monitoring: Whether to monitor clipboard access
            enable_obfuscation: Whether to obfuscate sensitive content in display
        """
        self.auto_clear_timeout = auto_clear_timeout
        self.enable_monitoring = enable_monitoring
        self.enable_obfuscation = enable_obfuscation
        
        # State tracking
        self.current_sensitive_content: Optional[str] = None
        self.is_sensitive_content_in_clipboard = False
        self.access_events: List[ClipboardEvent] = []
        self.clear_timer: Optional[threading.Timer] = None
        self.monitoring_thread: Optional[threading.Thread] = None
        self.is_monitoring = False
        self.stop_monitoring_flag = False
        
        # Statistics
        self.copy_count = 0
        self.clear_count = 0
        self.access_attempts = 0
        
        logger.info("ClipboardSecurityManager initialized")
        logger.info(f"Auto-clear timeout: {auto_clear_timeout}s")
        logger.info(f"Monitoring enabled: {enable_monitoring}")
        logger.info(f"Obfuscation enabled: {enable_obfuscation}")
    
    def copy_to_clipboard(self, content: str, is_sensitive: bool = True) -> bool:
        """
        Copy content to clipboard with optional auto-clearing.
        
        Args:
            content: Content to copy
            is_sensitive: Whether this is sensitive data (will be auto-cleared)
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self._use_pyperclip():
                pyperclip.copy(content)
            elif self._use_tkinter():
                self._copy_via_tkinter(content)
            else:
                logger.error("No clipboard mechanism available")
                return False
            
            self.copy_count += 1
            self.current_sensitive_content = content if is_sensitive else None
            self.is_sensitive_content_in_clipboard = is_sensitive
            
            # Record event
            event = ClipboardEvent(
                event_type="copy",
                timestamp=datetime.utcnow().isoformat(),
                content_length=len(content),
                source="user"
            )
            self.access_events.append(event)
            
            logger.info(f"Content copied to clipboard ({'sensitive' if is_sensitive else 'normal'})")
            
            # Start auto-clear timer if enabled and content is sensitive
            if is_sensitive and self.auto_clear_timeout > 0:
                self._schedule_auto_clear(self.auto_clear_timeout)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to copy to clipboard: {e}")
            return False
    
    def clear_clipboard(self, verify: bool = True) -> bool:
        """
        Clear the clipboard securely.
        
        Args:
            verify: Whether to verify clipboard was cleared
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Cancel pending auto-clear timer
            self._cancel_auto_clear()
            
            # Clear via available method
            if self._use_pyperclip():
                pyperclip.copy("")
            elif self._use_tkinter():
                self._copy_via_tkinter("")
            else:
                logger.error("No clipboard mechanism available")
                return False
            
            self.clear_count += 1
            self.current_sensitive_content = None
            self.is_sensitive_content_in_clipboard = False
            
            # Record event
            event = ClipboardEvent(
                event_type="clear",
                timestamp=datetime.utcnow().isoformat(),
                source="system"
            )
            self.access_events.append(event)
            
            logger.info("Clipboard cleared securely")
            
            # Verify if requested
            if verify:
                self._verify_clipboard_cleared()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear clipboard: {e}")
            return False
    
    def _schedule_auto_clear(self, timeout_seconds: int) -> None:
        """
        Schedule automatic clipboard clearing after timeout.
        
        Args:
            timeout_seconds: Seconds until auto-clear
        """
        # Cancel previous timer
        self._cancel_auto_clear()
        
        # Schedule new timer
        self.clear_timer = threading.Timer(
            timeout_seconds,
            self._auto_clear_callback
        )
        self.clear_timer.daemon = True
        self.clear_timer.start()
        
        logger.debug(f"Auto-clear scheduled in {timeout_seconds}s")
    
    def _cancel_auto_clear(self) -> None:
        """Cancel pending auto-clear timer."""
        if self.clear_timer:
            self.clear_timer.cancel()
            self.clear_timer = None
            logger.debug("Auto-clear timer cancelled")
    
    def _auto_clear_callback(self) -> None:
        """Callback for automatic clipboard clearing."""
        logger.info("Auto-clearing clipboard")
        self.clear_clipboard(verify=False)
    
    def _use_pyperclip(self) -> bool:
        """Check if pyperclip is available and working."""
        return PYPERCLIP_AVAILABLE
    
    def _use_tkinter(self) -> bool:
        """Check if Tkinter is available."""
        return TKINTER_AVAILABLE
    
    def _copy_via_tkinter(self, content: str) -> None:
        """Copy content to clipboard using Tkinter."""
        try:
            root = tk.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.clipboard_append(content)
            root.update()
            root.destroy()
        except Exception as e:
            logger.error(f"Tkinter clipboard operation failed: {e}")
            raise
    
    def _verify_clipboard_cleared(self) -> bool:
        """
        Verify that clipboard has been cleared.
        
        Returns:
            bool: True if clipboard appears to be empty
        """
        try:
            if self._use_pyperclip():
                content = pyperclip.paste()
                return len(content) == 0
            return True
        except Exception as e:
            logger.warning(f"Could not verify clipboard cleared: {e}")
            return True
    
    def start_monitoring(self) -> bool:
        """
        Start monitoring clipboard for unauthorized access.
        
        Returns:
            bool: True if monitoring started, False otherwise
        """
        if not self.enable_monitoring:
            logger.warning("Monitoring is disabled")
            return False
        
        if self.is_monitoring:
            logger.warning("Monitoring is already active")
            return False
        
        try:
            self.stop_monitoring_flag = False
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            self.is_monitoring = True
            logger.info("Clipboard monitoring started")
            return True
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self) -> None:
        """Stop clipboard monitoring."""
        self.stop_monitoring_flag = True
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Clipboard monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Monitor clipboard for unauthorized access."""
        previous_content = None
        
        while not self.stop_monitoring_flag:
            try:
                if not self._use_pyperclip():
                    time.sleep(1)
                    continue
                
                current_content = pyperclip.paste()
                
                # Detect unexpected changes
                if current_content != previous_content:
                    # Check if sensitive content was accidentally copied elsewhere
                    if (self.current_sensitive_content and 
                        self.current_sensitive_content != current_content):
                        
                        event = ClipboardEvent(
                            event_type="access_attempt",
                            timestamp=datetime.utcnow().isoformat(),
                            content_length=len(current_content),
                            source="unknown"
                        )
                        self.access_events.append(event)
                        self.access_attempts += 1
                        logger.warning(f"Clipboard content changed. Access attempt detected.")
                    
                    previous_content = current_content
                
                time.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                logger.debug(f"Monitoring loop error: {e}")
                time.sleep(1)
    
    def get_obfuscated_display(self, content: str = None, max_chars: int = 4) -> str:
        """
        Get an obfuscated display of sensitive content.
        
        Args:
            content: Content to obfuscate (uses current content if None)
            max_chars: Maximum visible characters before and after
        
        Returns:
            str: Obfuscated display string
        """
        content = content or self.current_sensitive_content
        if not content:
            return "[empty]"
        
        if len(content) <= max_chars * 2:
            return self.OBFUSCATION_CHAR * len(content)
        
        visible_start = content[:max_chars]
        visible_end = content[-max_chars:]
        hidden_count = len(content) - max_chars * 2
        
        return f"{visible_start}{self.OBFUSCATION_CHAR * hidden_count}{visible_end}"
    
    def get_security_status(self) -> Dict[str, Any]:
        """
        Get comprehensive security status.
        
        Returns:
            dict: Security status information
        """
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "sensitive_content_in_clipboard": self.is_sensitive_content_in_clipboard,
            "content_obfuscated": self.get_obfuscated_display() if self.enable_obfuscation else None,
            "auto_clear_timeout": self.auto_clear_timeout,
            "monitoring_enabled": self.enable_monitoring,
            "monitoring_active": self.is_monitoring,
            "auto_clear_pending": self.clear_timer is not None,
            "statistics": {
                "copy_count": self.copy_count,
                "clear_count": self.clear_count,
                "access_attempts": self.access_attempts,
                "total_events": len(self.access_events)
            }
        }
    
    def get_access_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get the clipboard access log.
        
        Args:
            limit: Maximum number of events to return
        
        Returns:
            list: Recent clipboard access events
        """
        events = self.access_events[-limit:]
        return [asdict(event) for event in events]
    
    def export_report(self, file_path: str) -> bool:
        """
        Export security report to JSON file.
        
        Args:
            file_path: Where to save the report
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            report = {
                "timestamp": datetime.utcnow().isoformat(),
                "security_status": self.get_security_status(),
                "access_log": self.get_access_log()
            }
            
            with open(file_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Report exported to: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return False
    
    def clear_access_log(self) -> None:
        """Clear the access event log."""
        self.access_events.clear()
        logger.info("Access log cleared")
    
    def set_auto_clear_timeout(self, timeout_seconds: int) -> None:
        """
        Update auto-clear timeout.
        
        Args:
            timeout_seconds: New timeout in seconds (0 to disable)
        """
        self.auto_clear_timeout = timeout_seconds
        logger.info(f"Auto-clear timeout updated to {timeout_seconds}s")
        
        # If sensitive content is already in clipboard, reschedule
        if self.is_sensitive_content_in_clipboard and timeout_seconds > 0:
            self._schedule_auto_clear(timeout_seconds)
    
    def __del__(self):
        """Cleanup on destruction."""
        try:
            self.stop_monitoring()
            self._cancel_auto_clear()
        except Exception:
            pass


if __name__ == "__main__":
    # Test the ClipboardSecurityManager
    logging.basicConfig(level=logging.INFO)
    
    manager = ClipboardSecurityManager(
        auto_clear_timeout=5,
        enable_monitoring=True,
        enable_obfuscation=True
    )
    
    print("=== Clipboard Security Manager Test ===\n")
    
    # Test copy
    test_password = "MySecurePassword123!@#"
    print(f"1. Copying password: {test_password}")
    manager.copy_to_clipboard(test_password, is_sensitive=True)
    
    # Test obfuscation
    obfuscated = manager.get_obfuscated_display()
    print(f"2. Obfuscated display: {obfuscated}\n")
    
    # Test status
    status = manager.get_security_status()
    print(f"3. Security status:")
    print(f"   - Sensitive content: {status['sensitive_content_in_clipboard']}")
    print(f"   - Auto-clear pending: {status['auto_clear_pending']}\n")
    
    # Test auto-clear
    print(f"4. Waiting for auto-clear ({manager.auto_clear_timeout}s)...")
    time.sleep(manager.auto_clear_timeout + 1)
    
    # Test status after clear
    status = manager.get_security_status()
    print(f"5. After auto-clear:")
    print(f"   - Sensitive content: {status['sensitive_content_in_clipboard']}")
    print(f"   - Copy count: {status['statistics']['copy_count']}")
    print(f"   - Clear count: {status['statistics']['clear_count']}\n")
    
    # Test monitoring
    print(f"6. Starting monitoring...")
    manager.start_monitoring()
    
    print(f"7. Access log: {len(manager.get_access_log())} events")
    
    # Export report
    print(f"\n8. Exporting report...")
    manager.export_report("clipboard_report.json")
    
    manager.stop_monitoring()
    print("Done!")
