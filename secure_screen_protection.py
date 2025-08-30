import threading
import time
import sys
import os
import logging
import subprocess

try:
    import tkinter as tk
except Exception:
    tk = None

if sys.platform == "win32":
    try:
        import ctypes
        from ctypes import wintypes
        WDA_NONE = 0
        WDA_MONITOR = 1
        WDA_EXCLUDEFROMCAPTURE = 0x00000011
        WIN_HARDENING_AVAILABLE = True
    except ImportError:
        WIN_HARDENING_AVAILABLE = False
else:
    WIN_HARDENING_AVAILABLE = False

# Optional dependencies
try:
    from PIL import ImageGrab
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


# Common recorder/screencap process names (lowercase). Extend as needed.
KNOWN_RECORDER_PROCS = {
    # OBS Studio
    "obs64.exe", "obs.exe",
    # Windows Game Bar
    "xboxgamebar.exe", "gamebarpresencewriter.exe",
    # Camtasia / Snagit / Bandicam / Fraps
    "camtasia.exe", "snagit32.exe", "snagit32editor.exe", "bandicam.exe", "fraps.exe",
    # Common cross-platform recorders
    "screenrecorder", "screenrecorder.exe", "loopy", "kap", "quicktimeplayer", "quicktime",
    # Browser-driven recorders (heuristic names)
    "chrome", "chrome.exe", "firefox", "firefox.exe", "edge", "edge.exe", "msedge.exe",
    # Communication tools with screen sharing
    "slack.exe", "teams.exe", "discord.exe", "skype.exe", "zoom.exe",
    # Remote desktop tools
    "anydesk.exe", "teamviewer.exe",
    # Other popular recorders/tools
    "vlc.exe", "ffmpeg.exe", "kazam", "simplescreenrecorder"
}

class ScreenProtector:
    def __init__(self, root, action="blackout", check_interval=0.7, on_protect_callback=None,
                 blacklist_processes=None, enable_clipboard_check=True, watermark_text=""):
        """
        root: the Tk/CTk root window
        action: "blackout", "close", or "watermark"
        check_interval: seconds between checks (0.5 - 1.5 recommended)
        on_protect_callback: optional callback(reason) executed after protection triggers
        blacklist_processes: additional process names (iterable of lowercase names)
        enable_clipboard_check: whether to try clipboard-image detection
        watermark_text: text to display for the watermark action
        """
        if tk is None:
            raise RuntimeError("tkinter is required by secure_screen_protection.py")
        self.root = root
        self.action = action.lower()
        self.watermark_text = watermark_text
        self.check_interval = float(check_interval)
        self.on_protect_callback = on_protect_callback
        self.enable_clipboard_check = enable_clipboard_check and PIL_AVAILABLE
        self._running = False
        self._thread = None
        self._blackout_window = None
        self._watermark_window = None
        self._last_clipboard_time = 0
        self._suppress_for_seconds = 2.0  # avoid duplicate triggers
        self.known_procs = set(KNOWN_RECORDER_PROCS)
        if blacklist_processes:
            self.known_procs.update(p.lower() for p in blacklist_processes)
        # allow user to temporarily disable protection via attribute
        self.enabled = True
        self._is_win_hardened = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._apply_windows_hardening()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Screen protector started (action=%s, clipboard_check=%s, psutil=%s, win_harden=%s)",
                    self.action, self.enable_clipboard_check, PSUTIL_AVAILABLE, self._is_win_hardened)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        self._thread = None
        self._remove_blackout()
        self._remove_watermark()
        self._remove_windows_hardening()
        logger.info("Screen protector stopped")

    def _apply_windows_hardening(self):
        if not WIN_HARDENING_AVAILABLE:
            return
        try:
            user32 = ctypes.windll.user32
            hwnd = self.root.winfo_id()
            result = user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
            if result == 1: # On success, the function returns a non-zero value in older docs, but 1 is safer
                self._is_win_hardened = True
                logger.info("Successfully applied Windows screen capture hardening (WDA_EXCLUDEFROMCAPTURE).")
            else:
                error = ctypes.get_last_error()
                if error == 0:
                    # Some systems might return 0 on success. We can assume it worked.
                    self._is_win_hardened = True
                    logger.info("Applied Windows screen capture hardening (SetWindowDisplayAffinity returned 0, assuming success).")
                else:
                    logger.warning(f"SetWindowDisplayAffinity failed with error code: {error}. The window may still be capturable.")
        except Exception as e:
            logger.error(f"Failed to apply Windows screen capture hardening: {e}")

    def _remove_windows_hardening(self):
        if not self._is_win_hardened or not WIN_HARDENING_AVAILABLE:
            return
        try:
            user32 = ctypes.windll.user32
            hwnd = self.root.winfo_id()
            user32.SetWindowDisplayAffinity(hwnd, WDA_NONE)
            self._is_win_hardened = False
            logger.info("Removed Windows screen capture hardening.")
        except Exception as e:
            logger.error(f"Failed to remove Windows screen capture hardening: {e}")

    def _monitor_loop(self):
        while self._running:
            try:
                if not self.enabled:
                    time.sleep(self.check_interval)
                    continue

                # 1) Clipboard image check (PrintScreen -> clipboard typical on Windows)
                if self.enable_clipboard_check:
                    try:
                        img = ImageGrab.grabclipboard()
                        if img is not None:
                            now = time.time()
                            if now - self._last_clipboard_time > self._suppress_for_seconds:
                                self._last_clipboard_time = now
                                self._log_and_protect("screenshot_clipboard_detected")
                    except Exception:
                        # ignore PIL errors (platforms may not support)
                        pass

                # 2) Process scan for known screen recorders
                try:
                    if PSUTIL_AVAILABLE:
                        for proc in psutil.process_iter(attrs=("name",)):
                            name = (proc.info.get("name") or "").lower()
                            if not name:
                                continue
                            # check startswith or equality to avoid partial matches causing false positives
                            for known in self.known_procs:
                                if known in name:
                                    self._log_and_protect(f"recorder_process_detected: {name}")
                                    raise StopIteration  # break out quickly
                    else:
                        # fallback: use platform process listing
                        if sys.platform.startswith("win"):
                            out = subprocess.check_output(["tasklist"], creationflags=0x08000000).decode(errors="ignore").lower()
                        else:
                            out = subprocess.check_output(["ps", "aux"]).decode(errors="ignore").lower()
                        for known in self.known_procs:
                            if known in out:
                                self._log_and_protect(f"recorder_process_detected: {known}")
                                break
                except StopIteration:
                    pass
                except Exception:
                    # ignore process listing errors
                    pass

            except Exception as e:
                logger.exception("Exception in monitor loop: %s", e)
            time.sleep(self.check_interval)

    def _log_and_protect(self, reason):
        logger.info("Protection triggered: %s", reason)
        # schedule GUI actions on main thread
        try:
            self.root.after(0, lambda: self._apply_protection_ui(reason))
        except Exception:
            # fallback: try to call directly
            self._apply_protection_ui(reason)
        # call optional callback
        try:
            if callable(self.on_protect_callback):
                self.on_protect_callback(reason)
        except Exception:
            logger.exception("on_protect_callback failed")

    def _apply_protection_ui(self, reason):
        # Default behaviors: blackout or close
        if self.action == "blackout":
            self._create_blackout(reason)
        elif self.action == "close":
            self._close_application(reason)
        elif self.action == "watermark":
            self._create_watermark()
        else:
            # unknown action -> blackout as safe default
            self._create_blackout(reason)

    def _create_watermark(self):
        if self._watermark_window is not None:
            return
        try:
            w = tk.Toplevel(self.root)
            w.overrideredirect(True)
            w.attributes("-topmost", True)
            w.attributes("-alpha", 0.15) # semi-transparent
            
            # Make window click-through
            if sys.platform == "win32":
                try:
                    user32 = ctypes.windll.user32
                    # Get window handle
                    hwnd = w.winfo_id()
                    # Get existing window style
                    style = user32.GetWindowLongW(hwnd, -20) # GWL_EXSTYLE
                    # Add transparent style
                    user32.SetWindowLongW(hwnd, -20, style | 0x00080000 | 0x00000020) # WS_EX_LAYERED | WS_EX_TRANSPARENT
                except Exception as e:
                    logger.warning(f"Could not set click-through property on watermark: {e}")
            else:
                 # On Linux, this can be complex. A simple approach is to disable input.
                try:
                    w.grab_release()
                except:
                    pass

            # Fullscreen size
            width = w.winfo_screenwidth()
            height = w.winfo_screenheight()
            w.geometry(f"{width}x{height}+0+0")
            
            # Create a canvas to tile the text
            canvas = tk.Canvas(w, bg="black", highlightthickness=0)
            canvas.pack(fill="both", expand=True)

            # Tile the watermark text
            text_to_display = self.watermark_text or "Protected"
            font_size = 14
            for y in range(0, height, font_size * 5):
                for x in range(0, width, len(text_to_display) * font_size * 2):
                    canvas.create_text(x, y, text=text_to_display, angle=30,
                                       fill="white", font=("Arial", font_size, "bold"))

            self._watermark_window = w
            logger.info("Watermark created.")
        except Exception as e:
            logger.exception("Failed to create watermark: %s", e)

    def _remove_watermark(self):
        try:
            if self._watermark_window:
                self._watermark_window.destroy()
                self._watermark_window = None
                logger.info("Watermark removed.")
        except Exception:
            pass

    def _create_blackout(self, reason=None):
        # if blackout already present, do nothing
        if self._blackout_window is not None:
            return
        try:
            # Build a borderless fullscreen Toplevel on the same screen as root
            w = tk.Toplevel(self.root)
            w.overrideredirect(True)
            w.attributes("-topmost", True)
            # try to remove focus and block input
            try:
                w.grab_set()
            except Exception:
                pass
            # get screen size
            try:
                width = w.winfo_screenwidth()
                height = w.winfo_screenheight()
            except Exception:
                width = self.root.winfo_screenwidth()
                height = self.root.winfo_screenheight()
            w.geometry(f"{width}x{height}+0+0")
            # black background
            frame = tk.Frame(w, bg="black")
            frame.pack(fill="both", expand=True)
            # show optional message for a brief moment (hidden by default)
            # keep reference so we can remove later
            self._blackout_window = w
            logger.info("Blackout window created (reason=%s)", reason)
        except Exception as e:
            logger.exception("Failed to create blackout window: %s", e)
            # fallback: close application
            self._close_application(reason)

    def _remove_blackout(self):
        try:
            if self._blackout_window:
                try:
                    self._blackout_window.grab_release()
                except Exception:
                    pass
                try:
                    self._blackout_window.destroy()
                except Exception:
                    pass
                self._blackout_window = None
                logger.info("Blackout window removed")
        except Exception:
            pass

    def _close_application(self, reason=None):
        try:
            logger.info("Closing application due to screen-protection trigger: %s", reason)
            # give GUI a moment to flush logs / sync if needed
            try:
                # if root has a 'secure_file_manager' attribute it may implement sync_all_files
                # attempt to call it before quitting (best-effort)
                sfm = getattr(self.root, "secure_file_manager", None)
                if sfm and hasattr(sfm, "sync_all_files"):
                    try:
                        sfm.sync_all_files()
                    except Exception:
                        logger.exception("sync_all_files failed before closing")
            except Exception:
                pass
            try:
                # schedule quit on mainloop
                self.root.after(50, lambda: self.root.quit())
            except Exception:
                try:
                    self.root.quit()
                except Exception:
                    pass
            # as a last resort, force exit
            time.sleep(0.2)
            try:
                sys.exit(0)
            except SystemExit:
                raise
        except Exception:
            logger.exception("Exception while trying to close application")

if __name__ == "__main__":
    # Quick manual test if run standalone (no GUI): spawn a simple Tk root and run protector
    if tk is None:
        print("Tkinter is required to run this module.")
        sys.exit(1)
    r = tk.Tk()
    r.title("Screen Protector Test")
    protector = ScreenProtector(r, action="blackout", check_interval=1.0)
    protector.start()
    tk.Button(r, text="Stop protector & exit", command=lambda: (protector.stop(), r.destroy())).pack(padx=20, pady=20)
    r.mainloop()
