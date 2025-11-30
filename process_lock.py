"""
Process Lock Manager
Prevents multiple instances of the program from running simultaneously.
Uses a lock file to track if the program is already running.
"""

import os
import sys
import atexit
from pathlib import Path


class ProcessLock:
    """Manages application-level process locking to prevent duplicate instances."""
    
    def __init__(self, lock_file=None):
        """
        Initialize the process lock manager.
        
        Args:
            lock_file: Path to the lock file. If None, creates one in AppData/Local/Temp
        """
        if lock_file is None:
            # Store lock file in user's temp directory
            temp_dir = Path(os.getenv('APPDATA')) / 'Local' / 'Temp'
            lock_file = temp_dir / 'password_manager.lock'
        
        self.lock_file = Path(lock_file)
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.is_locked = False
        
        # Register cleanup on exit
        atexit.register(self.release)
    
    def acquire(self):
        """
        Attempt to acquire the process lock.
        
        Returns:
            bool: True if lock was acquired, False if program is already running
        """
        if self.lock_file.exists():
            try:
                with open(self.lock_file, 'r') as f:
                    pid = f.read().strip()
                
                # Check if the PID in the lock file is still running
                if self._is_process_running(int(pid)):
                    print(f"⚠️  Program is already running (PID: {pid})")
                    print("❌ Cannot start multiple instances. Exiting...")
                    return False
                else:
                    # Process is not running, remove stale lock file
                    self.lock_file.unlink()
            except (ValueError, OSError):
                # Lock file is corrupted or inaccessible, remove it
                try:
                    self.lock_file.unlink()
                except OSError:
                    pass
        
        # Write current process ID to lock file
        try:
            with open(self.lock_file, 'w') as f:
                f.write(str(os.getpid()))
            self.is_locked = True
            print("✅ Process lock acquired successfully")
            return True
        except OSError as e:
            print(f"❌ Failed to acquire process lock: {e}")
            return False
    
    def release(self):
        """Release the process lock by removing the lock file."""
        if self.is_locked and self.lock_file.exists():
            try:
                self.lock_file.unlink()
                self.is_locked = False
                print("✅ Process lock released")
            except OSError as e:
                print(f"⚠️  Failed to release process lock: {e}")
    
    @staticmethod
    def _is_process_running(pid):
        """
        Check if a process with the given PID is still running.
        
        Args:
            pid: Process ID to check
            
        Returns:
            bool: True if process is running, False otherwise
        """
        try:
            # On Windows, use tasklist command
            import subprocess
            result = subprocess.run(
                ['tasklist', '/FI', f'PID eq {pid}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return str(pid) in result.stdout
        except Exception:
            # If we can't check, assume process is running (safer)
            return True


def check_single_instance(lock_file=None):
    """
    Convenience function to check and enforce single instance.
    Call this at the start of your main() function.
    
    Args:
        lock_file: Optional path to lock file
        
    Returns:
        ProcessLock: The lock manager instance if successful, None if another instance is running
    """
    lock = ProcessLock(lock_file)
    if lock.acquire():
        return lock
    else:
        sys.exit(1)


if __name__ == '__main__':
    # Test the process lock
    print("Testing Process Lock Manager...")
    lock = check_single_instance()
    print("Lock acquired. Program can run.")
    print("Waiting 10 seconds... (try running this script again in another terminal)")
    import time
    time.sleep(10)
    print("Done.")
