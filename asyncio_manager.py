import asyncio
import threading
import logging
from typing import Coroutine, Any

logger = logging.getLogger(__name__)

class AsyncioEventLoopManager:
    """
    Manages a single asyncio event loop running in a dedicated background thread.
    This class ensures that all asyncio tasks are run in a single, consistent loop,
    preventing "RuntimeError: Event loop is closed" in multi-threaded applications.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True
        
        self.loop = None
        self.thread = None
        self.is_running = False
        self.lock = threading.Lock()

    def _run_loop(self):
        """The target function for the background thread."""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.is_running = True
            logger.info("Asyncio event loop started in background thread.")
            self.loop.run_forever()
        except Exception as e:
            logger.error(f"Exception in asyncio event loop: {e}", exc_info=True)
        finally:
            self.is_running = False
            logger.info("Asyncio event loop has been stopped.")

    def start(self):
        """Starts the asyncio event loop in a background thread."""
        with self.lock:
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(target=self._run_loop, daemon=True, name="AsyncioLoopThread")
                self.thread.start()

    def stop(self):
        """Stops the asyncio event loop gracefully."""
        with self.lock:
            if self.loop and self.is_running:
                logger.info("Requesting asyncio event loop to stop.")
                # Stop all running tasks before closing the loop
                tasks = asyncio.all_tasks(loop=self.loop)
                for task in tasks:
                    task.cancel()

                # Gather tasks to ensure they are cancelled before stopping the loop
                async def _gather_and_stop():
                    await asyncio.gather(*tasks, return_exceptions=True)
                    self.loop.stop()

                self.submit_coroutine(_gather_and_stop())
                
                # Wait for the thread to finish
                if self.thread:
                    self.thread.join(timeout=5)
                    if self.thread.is_alive():
                        logger.warning("Asyncio thread did not terminate cleanly.")
                    self.thread = None
                
                self.loop.close()
                logger.info("Asyncio event loop has been closed.")

    def submit_coroutine(self, coro: Coroutine) -> Any:
        """
        Submits a coroutine to be executed on the event loop.
        This method is thread-safe.
        """
        if not self.loop or not self.is_running:
            logger.error("Cannot submit coroutine: Event loop is not running.")
            return None
        
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

# Global instance for easy access
asyncio_manager = AsyncioEventLoopManager()