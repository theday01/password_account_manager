"""
Enhanced Professional Loading Screen Module
Provides enterprise-grade loading screen with modern design
"""
import os
import customtkinter as ctk
from PIL import Image
import logging
from ui_utils import ThemedToplevel

logger = logging.getLogger(__name__)


class EnhancedLoadingScreen:
    """Professional enterprise-grade loading screen"""
    
    def __init__(self, root, lang_manager, version_data):
        self.root = root
        self.lang_manager = lang_manager
        self.version_data = version_data
        self.loading_window = None
        self.loading_dots = []
        self.step_indicators = []
        
    def show(self, on_complete_callback):
        """Display the loading screen with animations"""
        # Professional color scheme inspired by leading tech companies
        primary_color = "#1e40af"      # Deep professional blue
        accent_color = "#3b82f6"       # Bright accent blue
        secondary_accent = "#06b6d4"   # Cyan accent
        bg_color = "#0f172a"           # Dark navy background
        text_color = "#f8fafc"         # Light text
        subtext_color = "#cbd5e1"      # Muted text
        progress_color = "#06b6d4"     # Cyan progress
        
        width, height = 1050, 520
        self.loading_window = ThemedToplevel(self.root, fg_color=bg_color)
        self.loading_window.title(self.lang_manager.get_string("loading"))
        self.loading_window.geometry(f"{width}x{height}")
        self.loading_window.resizable(False, False)
        self.loading_window.overrideredirect(True)
        self.loading_window.grab_set()
        
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.loading_window.geometry(f"{width}x{height}+{x}+{y}")

        # Main container with subtle border effect
        main_frame = ctk.CTkFrame(self.loading_window, fg_color=bg_color, corner_radius=0)
        main_frame.pack(fill="both", expand=True, padx=0, pady=0)

        # Left side: Animated logo and visual element
        left_frame = ctk.CTkFrame(main_frame, fg_color=primary_color, corner_radius=0)
        left_frame.pack(side="left", fill="both", expand=True, padx=0, pady=0)

        # Decorative gradient-like effect on left side
        gradient_frame = ctk.CTkFrame(left_frame, fg_color=primary_color, corner_radius=0)
        gradient_frame.pack(fill="both", expand=True)

        # Logo and branding on left
        left_content = ctk.CTkFrame(gradient_frame, fg_color="transparent")
        left_content.pack(fill="both", expand=True, padx=30, pady=40)

        try:
            load_icon_path = os.path.join("icons", "load.png")
            if os.path.exists(load_icon_path):
                load_image = Image.open(load_icon_path)
                load_icon = ctk.CTkImage(light_image=load_image, size=(260, 200))
                icon_label = ctk.CTkLabel(left_content, image=load_icon, text="", fg_color="transparent")
                icon_label.pack(expand=True, pady=20)
        except Exception as e:
            logger.warning(f"Could not display loading icon: {e}")

        # Pulsing dot animation indicator
        dot_frame = ctk.CTkFrame(left_content, fg_color="transparent")
        dot_frame.pack(pady=10)
        
        self.loading_dots = []
        for i in range(3):
            dot = ctk.CTkLabel(
                dot_frame,
                text="●",
                font=ctk.CTkFont(size=16),
                text_color=text_color
            )
            dot.pack(side="left", padx=5)
            self.loading_dots.append(dot)

        # Right side: Content and progress
        right_frame = ctk.CTkFrame(main_frame, fg_color=bg_color, corner_radius=0)
        right_frame.pack(side="right", fill="both", expand=True, padx=0, pady=0)

        # Content area with padding
        content_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=40, pady=40)

        # Title with modern styling
        title_label = ctk.CTkLabel(
            content_frame,
            text=self.lang_manager.get_string("app_title"),
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color=text_color
        )
        title_label.pack(pady=(0, 5), anchor="w")

        # Slogan/subtitle
        slogan_label = ctk.CTkLabel(
            content_frame,
            text=self.lang_manager.get_string("app_slogan"),
            font=ctk.CTkFont(size=13, weight="normal"),
            text_color=subtext_color
        )
        slogan_label.pack(pady=(0, 30), anchor="w")

        # Separator line
        separator = ctk.CTkFrame(content_frame, height=1, fg_color=accent_color, corner_radius=0)
        separator.pack(fill="x", pady=(0, 30))

        # Status and progress section
        status_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        status_frame.pack(fill="x", pady=(0, 15))

        status_label = ctk.CTkLabel(
            status_frame,
            text=self.lang_manager.get_string("initializing"),
            font=ctk.CTkFont(size=13, weight="normal"),
            text_color=progress_color
        )
        status_label.pack(anchor="w")

        # Modern progress bar (thicker and more visible)
        progress_bar = ctk.CTkProgressBar(
            content_frame,
            width=300,
            height=6,
            progress_color=progress_color,
            fg_color="#1e293b",
            corner_radius=3
        )
        progress_bar.pack(pady=15, anchor="w", fill="x")

        # Step indicators with professional styling
        steps_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        steps_frame.pack(fill="both", pady=30)

        self.step_indicators = []
        steps = [
            self.lang_manager.get_string("loading_components"),
            self.lang_manager.get_string("verifying_security"),
            self.lang_manager.get_string("preparing_workspace"),
            self.lang_manager.get_string("launching_application")
        ]

        for i, step_name in enumerate(steps):
            step_container = ctk.CTkFrame(steps_frame, fg_color="transparent")
            step_container.pack(side="left", fill="both", expand=True, padx=4)

            # Step indicator circle
            step_label = ctk.CTkLabel(
                step_container,
                text=str(i + 1),
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=text_color,
                fg_color="#1e293b",
                width=32,
                height=32,
                corner_radius=16
            )
            step_label.pack(side="left", padx=4)
            
            # Step name
            name_label = ctk.CTkLabel(
                step_container,
                text=step_name,
                font=ctk.CTkFont(size=9),
                text_color=subtext_color
            )
            name_label.pack(side="left", padx=3, fill="x", expand=True)

            self.step_indicators.append({
                "label": step_label,
                "name": name_label,
                "container": step_container
            })

        # Bottom info section
        info_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        info_frame.pack(fill="x", pady=(20, 0), side="bottom")

        version_text = f"Version {self.version_data.get('version', 'N/A')} • Enterprise Edition"
        version_label = ctk.CTkLabel(
            info_frame,
            text=version_text,
            font=ctk.CTkFont(size=10),
            text_color="#64748b"
        )
        version_label.pack(anchor="w")

        copyright_label = ctk.CTkLabel(
            info_frame,
            text="© 2024 SecureVault Pro. All rights reserved.",
            font=ctk.CTkFont(size=9),
            text_color="#475569"
        )
        copyright_label.pack(anchor="w", pady=(3, 0))

        # Animation and logic
        current_step = {"value": 0}

        def animate_dot_pulse():
            """Animate the loading dots."""
            if self.loading_window and self.loading_window.winfo_exists():
                for i, dot in enumerate(self.loading_dots):
                    colors = ["#6b7280", "#9ca3af", "#f8fafc"]
                    dot.configure(text_color=colors[i])
                self.loading_window.after(500, animate_dot_pulse)

        def update_step_indicator(step_num):
            """Update the step indicator UI."""
            for i, indicator in enumerate(self.step_indicators):
                if i < step_num:
                    # Completed steps - cyan color
                    indicator["label"].configure(fg_color=progress_color, text_color="white")
                    indicator["name"].configure(text_color=progress_color)
                elif i == step_num:
                    # Current step - bright blue
                    indicator["label"].configure(fg_color=accent_color, text_color="white")
                    indicator["name"].configure(text_color=accent_color)
                else:
                    # Future steps - muted
                    indicator["label"].configure(fg_color="#1e293b", text_color=subtext_color)
                    indicator["name"].configure(text_color="#64748b")

        def update_loading(progress, status_text, step_num=0):
            if self.loading_window and self.loading_window.winfo_exists():
                progress_bar.set(progress)
                status_label.configure(text=status_text)
                update_step_indicator(step_num)
                self.loading_window.update_idletasks()

        def animate_progress(current_progress, target_progress, status_text, step_num, duration_ms, steps=25):
            step_progress = (target_progress - current_progress) / steps
            step_delay = duration_ms // steps
            
            def step_func(step_count):
                if step_count <= steps and self.loading_window and self.loading_window.winfo_exists():
                    new_progress = current_progress + step_progress * step_count
                    update_loading(new_progress, status_text, step_num)
                    self.loading_window.after(step_delay, lambda: step_func(step_count + 1))
            
            step_func(1)

        def sequence_loader():
            current_step["value"] = 0
            animate_dot_pulse()
            update_loading(0, self.lang_manager.get_string("initializing"), 0)
            if self.loading_window and self.loading_window.winfo_exists():
                self.loading_window.after(800, lambda: sequence_step_1())

        def sequence_step_1():
            current_step["value"] = 1
            animate_progress(0, 0.25, self.lang_manager.get_string("loading_components"), 1, 900, 25)
            if self.loading_window and self.loading_window.winfo_exists():
                self.loading_window.after(950, lambda: sequence_step_2())

        def sequence_step_2():
            current_step["value"] = 2
            animate_progress(0.25, 0.55, self.lang_manager.get_string("verifying_security"), 2, 1100, 25)
            if self.loading_window and self.loading_window.winfo_exists():
                self.loading_window.after(1150, lambda: sequence_step_3())

        def sequence_step_3():
            current_step["value"] = 3
            animate_progress(0.55, 0.85, self.lang_manager.get_string("preparing_workspace"), 3, 800, 25)
            if self.loading_window and self.loading_window.winfo_exists():
                self.loading_window.after(850, lambda: sequence_step_4())

        def sequence_step_4():
            current_step["value"] = 4
            animate_progress(0.85, 1.0, self.lang_manager.get_string("launching_application"), 4, 500, 20)
            if self.loading_window and self.loading_window.winfo_exists():
                self.loading_window.after(550, lambda: finish_loading())

        def finish_loading():
            if self.loading_window and self.loading_window.winfo_exists():
                self.loading_window.destroy()
            self.root.deiconify()
            if on_complete_callback:
                on_complete_callback()

        self.loading_window.after(300, sequence_loader)
