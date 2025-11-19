import threading
import time
from datetime import datetime, timedelta

class PasswordReminder:
    def __init__(self, db_manager, parent_window):
        self.db_manager = db_manager
        self.parent_window = parent_window
        self.REMINDER_INTERVAL = 60  # Check every 60 seconds
        self.reminded_accounts = set()
        self.timer = None
        self.is_running = False
        # Don't start immediately - will be started after UI loads
        logger = __import__('logging').getLogger(__name__)
        logger.info("PasswordReminder initialized but not started (will start after UI loads)")

    def _check_accounts(self):
        try:
            now = datetime.now()
            five_minutes_ago = now - timedelta(minutes=5)
            
            metadata_conn = self.db_manager.get_metadata_connection()
            cursor = metadata_conn.execute(
                "SELECT id, name, updated_at FROM accounts WHERE updated_at <= ? AND id != 'master_account'",
                (five_minutes_ago.isoformat(),)
            )
            accounts_to_remind = cursor.fetchall()
            metadata_conn.close()

            for account_id, name, updated_at in accounts_to_remind:
                if account_id not in self.reminded_accounts:
                    self.reminded_accounts.add(account_id)
                    # Schedule UI refresh in main thread
                    if self.parent_window and hasattr(self.parent_window, 'root'):
                        try:
                            self.parent_window.root.after(0, self.parent_window.load_password_cards)
                            self.parent_window.root.after(0, self.parent_window.update_expired_passwords_count)
                        except Exception as e:
                            logger = __import__('logging').getLogger(__name__)
                            logger.debug(f"Failed to schedule UI update: {e}")
                    
        except Exception as e:
            logger = __import__('logging').getLogger(__name__)
            logger.error(f"Error checking accounts: {e}")
        finally:
            # Reschedule the next check
            if self.is_running:
                self.timer = threading.Timer(self.REMINDER_INTERVAL, self._check_accounts)
                self.timer.daemon = True
                self.timer.start()

    def start(self):
        """Start the reminder check loop"""
        if self.is_running:
            return
        
        self.is_running = True
        logger = __import__('logging').getLogger(__name__)
        logger.info("Starting PasswordReminder background check")
        
        # Initial delay to avoid blocking UI
        self.timer = threading.Timer(3, self._check_accounts)
        self.timer.daemon = True
        self.timer.start()

    def stop(self):
        """Stop the reminder check loop"""
        self.is_running = False
        if self.timer:
            self.timer.cancel()
            self.timer = None
        logger = __import__('logging').getLogger(__name__)
        logger.info("Stopped PasswordReminder background check")

    def get_reminded_accounts(self):
        return self.reminded_accounts.copy()

    def mark_as_changed(self, account_id):
        if account_id in self.reminded_accounts:
            self.reminded_accounts.remove(account_id)


# 2. Modify the show_main_interface method in main.py
# Replace the existing implementation with this optimized version:

def show_main_interface_optimized(self):
    """Show main interface with deferred background task loading"""
    
    for widget in self.main_frame.winfo_children():
        widget.destroy()

    self.root.state('zoomed')
    self.root.resizable(True, True)
    self.root.minsize(800, 600)

    self.reset_inactivity_timer()
    self.root.bind("<KeyPress>", self.reset_inactivity_timer)
    self.root.bind("<Motion>", self.reset_inactivity_timer)
    self.root.bind("<Button-1>", self.reset_inactivity_timer)

    def on_closing():
        # Stop trial check timer if running
        self._stop_trial_check_timer()
        if self.trial_manager and self.trial_manager.anchor:
            self.trial_manager.anchor.update_shutdown_status('SHUTDOWN_CLEAN')
        if hasattr(self, 'tamper_manager'):
            self.tamper_manager.update_shutdown_status('SHUTDOWN_CLEAN')
        # Sync files to secure storage before closing
        if self.secure_file_manager and self.authenticated and self.database:
            try:
                logger.info("Syncing files to secure storage before closing...")
                self.database._checkpoint_databases()
                self.secure_file_manager.sync_all_files()
                logger.info("Files synced successfully")
            except Exception as e:
                logger.error(f"Failed to sync files before closing: {e}")
        self.root.destroy()
    
    self.root.protocol("WM_DELETE_WINDOW", on_closing)

    # Build UI immediately (fast)
    toolbar = ctk.CTkFrame(self.main_frame, height=70)
    toolbar.pack(fill="x", padx=10, pady=10)
    toolbar.pack_propagate(False)
    
    if self.trial_manager and self.trial_manager.is_trial_active:
        remaining_minutes = int(self.trial_manager.minutes_remaining)
        remaining_days = remaining_minutes // (24 * 60)

        def _english_time(n, unit):
            if unit == "day":
                return f"{n} day" if n == 1 else f"{n} days"
            if unit == "hour":
                return f"{n} hour" if n == 1 else f"{n} hours"
            return f"{n} minute" if n == 1 else f"{n} minutes"

        if remaining_minutes >= 24 * 60:
            time_text = _english_time(remaining_days, "day")
        elif remaining_minutes >= 60:
            remaining_hours = remaining_minutes // 60
            time_text = _english_time(remaining_hours, "hour")
        else:
            time_text = _english_time(remaining_minutes, "minute")

        trial_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        trial_frame.pack(side="left", padx=20, pady=8)

        text_color = "#FF7A18"
        if remaining_days <= 3:
            text_color = "red"

        primary_label = ctk.CTkLabel(
            trial_frame,
            text=f"⏳ Trial — {time_text} remaining",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=text_color,
            anchor="w",
            justify="left"
        )
        primary_label.pack(anchor="w")

        secondary_label = ctk.CTkLabel(
            trial_frame,
            text="When the trial ends, you'll need to activate the full version to continue.",
            font=ctk.CTkFont(size=11),
            text_color="#6B7280",
            anchor="w",
            justify="left"
        )
        secondary_label.pack(anchor="w", pady=(4, 0))
    
    left_toolbar_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
    left_toolbar_frame.pack(side="left", fill="y", padx=25, pady=10)

    ctk.CTkLabel(
        left_toolbar_frame,
        text=self.lang_manager.get_string("main_toolbar_title"),
        font=ctk.CTkFont(size=24, weight="bold")
    ).pack(anchor="w")
    
    welcome_message = self._generate_welcome_message()
    ctk.CTkLabel(
        left_toolbar_frame,
        text=welcome_message,
        font=ctk.CTkFont(size=12),
        justify="left",
        anchor="w"
    ).pack(anchor="w", pady=(5, 0))
    
    ctk.CTkButton(
        toolbar, 
        text=self.lang_manager.get_string("logout"), 
        width=100, 
        height=55,
        image=logout,
        compound="left",
        command=self.lock_vault,
        font=ctk.CTkFont(size=18)
    ).pack(side="right", padx=10, pady=8)
    
    ctk.CTkButton(
        toolbar,
        text=self.lang_manager.get_string("about"),
        width=120,
        height=55,
        image=info,
        compound="left",
        command=self.show_about_dialog,
        font=ctk.CTkFont(size=18)
    ).pack(side="right", padx=10, pady=8)

    backup_restore_state = "disabled"
    if self.trial_manager and self.trial_manager.status == 'FULL':
        backup_restore_state = "normal"

    ctk.CTkButton(
        toolbar,
        text=self.lang_manager.get_string("backup"),
        width=120,
        height=55,
        image=save,
        compound="left",
        command=self.show_backup_dialog,
        font=ctk.CTkFont(size=18),
        state=backup_restore_state
    ).pack(side="right", padx=10, pady=8)

    ctk.CTkButton(
        toolbar,
        text=self.lang_manager.get_string("restore_old_backup"),
        width=160,
        height=55,
        image=restore_icon,
        compound="left",
        command=self.show_restore_dialog,
        font=ctk.CTkFont(size=16),
        state=backup_restore_state
    ).pack(side="right", padx=8, pady=8)
    
    content_frame = ctk.CTkFrame(self.main_frame)
    content_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    self.create_sidebar(content_frame)
    self.main_panel = ctk.CTkFrame(content_frame)
    self.main_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)
    
    if self.trial_manager and self.trial_manager.is_trial_active:
        self._start_trial_check_timer()

    # Show passwords immediately (fast initial load)
    self.show_passwords()
    
    # DEFERRED: Start expensive operations after UI is visible
    # Use root.after to schedule these tasks for later execution
    def deferred_startup_tasks():
        """Heavy operations deferred to after UI is shown"""
        logger.info("Starting deferred startup tasks...")
        
        try:
            # Initialize password reminder (now with deferred start)
            self.password_reminder = PasswordReminder(self.database, self)
            self.password_reminder.start()  # Now starts the background thread
            logger.info("Password reminder initialized and started")
        except Exception as e:
            logger.error(f"Error initializing password reminder: {e}")
        
        try:
            # Update expired passwords count
            self.update_expired_passwords_count()
            logger.info("Expired passwords count updated")
        except Exception as e:
            logger.error(f"Error updating expired passwords: {e}")
        
        logger.info("Deferred startup tasks completed")
    
    # Schedule deferred tasks after a short delay to allow UI to render
    # Using a longer delay (500ms) to ensure UI is fully visible before heavy work
    self.root.after(500, deferred_startup_tasks)


# 3. Update the show_loading_screen method to show proper feedback
# Add this enhanced loading feedback:

def show_loading_screen_enhanced(self):
    """Show loading screen with proper feedback"""
    bg_color = "#f5f5f5"      
    accent_color = "#2b6cb0" 
    text_color = "#1a202c"     
    slogan_color = "#4a5568"
    
    width, height = 700, 300
    loading_window = ThemedToplevel(self.root, fg_color=bg_color)
    loading_window.title(self.lang_manager.get_string("loading"))
    loading_window.geometry(f"{width}x{height}")
    loading_window.resizable(False, False)
    loading_window.overrideredirect(True)
    loading_window.grab_set()
    
    self.root.update_idletasks()
    x = (self.root.winfo_screenwidth() // 2) - (width // 2)
    y = (self.root.winfo_screenheight() // 2) - (height // 2)
    loading_window.geometry(f"{width}x{height}+{x}+{y}")

    main_frame = ctk.CTkFrame(loading_window, fg_color=bg_color, corner_radius=10)
    main_frame.pack(fill="both", expand=True, padx=2, pady=2)

    left_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
    left_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)

    try:
        load_icon_path = os.path.join("icons", "load.png")
        if os.path.exists(load_icon_path):
            load_image = Image.open(load_icon_path)
            load_icon = ctk.CTkImage(light_image=load_image, size=(250, 200))
            icon_label = ctk.CTkLabel(left_frame, image=load_icon, text="", fg_color="transparent")
            icon_label.pack(expand=True)
    except Exception as e:
        logger.warning(f"Could not display loading icon: {e}")

    right_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
    right_frame.pack(side="right", fill="both", expand=True, padx=20, pady=20)
    
    right_content_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
    right_content_frame.pack(expand=True)

    ctk.CTkLabel(
        right_content_frame,
        text=self.lang_manager.get_string("app_title"),
        font=ctk.CTkFont(size=32, weight="bold"),
        text_color=text_color
    ).pack(pady=(5, 5), anchor="w")

    ctk.CTkLabel(
        right_content_frame,
        text=self.lang_manager.get_string("app_slogan"),
        font=ctk.CTkFont(size=12, slant="italic"),
        text_color=slogan_color
    ).pack(pady=(0, 25), anchor="w")

    status_label = ctk.CTkLabel(
        right_content_frame,
        text=self.lang_manager.get_string("initializing"),
        font=ctk.CTkFont(size=12),
        text_color=accent_color
    )
    status_label.pack(pady=(10, 5), anchor="w")

    progress_bar = ctk.CTkProgressBar(
        right_content_frame,
        width=320,
        height=8,
        progress_color=accent_color,
        fg_color="#333333",
        corner_radius=4
    )
    progress_bar.pack(pady=5, anchor="w")

    ctk.CTkLabel(
        loading_window,
        text="© 2024 SecureVault Pro. All rights reserved.",
        font=ctk.CTkFont(size=9),
        text_color=slogan_color
    ).pack(side="bottom", pady=10)

    def update_loading(progress, status_text):
        progress_bar.set(progress)
        status_label.configure(text=status_text)
        loading_window.update_idletasks()

    def animate_progress(current_progress, target_progress, status_text, duration_ms, steps=20):
        step_progress = (target_progress - current_progress) / steps
        step_delay = duration_ms // steps
        
        def step_func(step_num):
            if step_num <= steps:
                new_progress = current_progress + step_progress * step_num
                update_loading(new_progress, status_text)
                loading_window.after(step_delay, lambda: step_func(step_num + 1))
        
        step_func(1)

    def sequence_loader():
        update_loading(0, self.lang_manager.get_string("initializing"))
        loading_window.after(500)

        animate_progress(0, 0.25, self.lang_manager.get_string("loading_components"), 500)
        loading_window.after(700, lambda: sequence_step_2())

    def sequence_step_2():
        animate_progress(0.25, 0.55, self.lang_manager.get_string("verifying_security"), 800)
        loading_window.after(1000, lambda: sequence_step_3())

    def sequence_step_3():
        animate_progress(0.55, 0.85, self.lang_manager.get_string("preparing_workspace"), 600)
        loading_window.after(600, lambda: sequence_step_4())

    def sequence_step_4():
        animate_progress(0.85, 1.0, self.lang_manager.get_string("launching_application"), 500)
        loading_window.after(500, lambda: finish_loading())

    def finish_loading():
        loading_window.destroy()
        self.root.deiconify()

        # Rest of initialization...
        self._setup_secure_file_manager()
        
        self.trial_manager = TrialManager(self.root, self.secure_file_manager, restart_callback=self.restart_program)
        self.reminder_manager = ReminderManager(self.trial_manager, self)
        
        logger.info(f"Trial status at startup: {self.trial_manager.status}")
        if self.trial_manager.status in ["EXPIRED", "TAMPERED"]:
            logger.warning("Trial has expired or is tampered.")
            if not self.trial_manager.show_trial_expired_dialog():
                logger.warning("User exited from trial dialog.")
                self.root.quit()
                return
        
        self.tamper_manager = TamperManager()
        self._initialize_app()

    loading_window.after(200, sequence_loader)