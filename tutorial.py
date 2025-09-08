import customtkinter as ctk
from PIL import Image
import os
from icon_manager import ThemedToplevel

class TutorialManager:
    def __init__(self, parent, lang_manager):
        self.parent = parent
        self.lang_manager = lang_manager
        self.tutorial_window = None
        self.current_step = 0
        self._current_image = None  # keep a reference to the image to avoid GC

        # Window dimensions (increased width so titles won't be clipped)
        self.win_width = 650
        self.win_height = 470

        self.steps = self._get_tutorial_steps()

    def _center_window(self, window, width, height, parent=None):
        """
        Center `window` of size (width,height) relative to parent if possible,
        otherwise center on the screen.
        """
        window.update_idletasks()
        if parent:
            try:
                parent.update_idletasks()
                px = parent.winfo_rootx()
                py = parent.winfo_rooty()
                pw = parent.winfo_width()
                ph = parent.winfo_height()
                if pw <= 1 or ph <= 1:
                    raise RuntimeError("parent geometry too small, fallback to screen center")
                x = px + (pw // 2) - (width // 2)
                y = py + (ph // 2) - (height // 2)
            except Exception:
                screen_w = window.winfo_screenwidth()
                screen_h = window.winfo_screenheight()
                x = (screen_w // 2) - (width // 2)
                y = (screen_h // 2) - (height // 2)
        else:
            screen_w = window.winfo_screenwidth()
            screen_h = window.winfo_screenheight()
            x = (screen_w // 2) - (width // 2)
            y = (screen_h // 2) - (height // 2)

        if x < 0: x = 0
        if y < 0: y = 0
        window.geometry(f"{width}x{height}+{x}+{y}")

    def _get_tutorial_steps(self):
        """
        Defines the tutorial steps with translated content.
        """
        return [
            {
                "title": self.lang_manager.get_string("tutorial_step_1_title"),
                "text": self.lang_manager.get_string("tutorial_step_1_text"),
                "image": "info.png"
            },
            {
                "title": self.lang_manager.get_string("tutorial_step_2_title"),
                "text": self.lang_manager.get_string("tutorial_step_2_text"),
                "image": "user.png"
            },
            {
                "title": self.lang_manager.get_string("tutorial_step_3_title"),
                "text": self.lang_manager.get_string("tutorial_step_3_text"),
                "image": "security.png"
            },
            {
                "title": self.lang_manager.get_string("tutorial_step_4_title"),
                "text": self.lang_manager.get_string("tutorial_step_4_text"),
                "image": "settings.png"
            },
            {
                "title": self.lang_manager.get_string("tutorial_step_5_title"),
                "text": self.lang_manager.get_string("tutorial_step_5_text"),
                "image": "password.png"
            },
            {
                "title": self.lang_manager.get_string("tutorial_step_6_title"),
                "text": self.lang_manager.get_string("tutorial_step_6_text"),
                "image": "done.png"
            },
            {
                "title": self.lang_manager.get_string("tutorial_step_7_title"),
                "text": self.lang_manager.get_string("tutorial_step_7_text"),
                "image": "love.png"
            }
        ]

    def show_tutorial_window(self):
        # Create window with increased width to avoid clipping titles
        self.tutorial_window = ThemedToplevel(self.parent)
        self.tutorial_window.title(self.lang_manager.get_string("tutorial_title"))
        width, height = self.win_width, self.win_height
        self.tutorial_window.overrideredirect(False)
        self.tutorial_window.resizable(False, False)
        self.tutorial_window.grab_set()
        self.tutorial_window.transient(self.parent)

        # Center relative to parent (or screen fallback)
        self._center_window(self.tutorial_window, width, height, parent=self.parent)

        # Main frame with comfortable padding
        self.main_frame = ctk.CTkFrame(self.tutorial_window, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=18, pady=18)

        # Show the first step (Welcome)
        self.current_step = 0
        self.show_step()

        # Wait until tutorial is closed
        self.parent.wait_window(self.tutorial_window)

    def show_step(self):
        # Clear existing widgets
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        step_data = self.steps[self.current_step]

        # Title: allow it to expand horizontally so it's never clipped
        title_label = ctk.CTkLabel(
            self.main_frame,
            text=step_data["title"],
            font=ctk.CTkFont(size=20, weight="bold"),
            anchor="center",
            justify="center"
        )
        # fill the horizontal space and give horizontal padding
        title_label.pack(fill="x", padx=12, pady=(6, 12))

        # Progress indicator
        progress_text = self.lang_manager.get_string(
            "tutorial_progress_text",
            current_step=self.current_step + 1,
            total_steps=len(self.steps)
        )
        progress_label = ctk.CTkLabel(
            self.main_frame,
            text=progress_text,
            font=ctk.CTkFont(size=12, slant="italic"),
            anchor="center",
            justify="center"
        )
        progress_label.pack(fill="x", padx=12, pady=(0, 10))

        # Image (optional)
        if step_data.get("image"):
            try:
                icon_path = os.path.join("icons", step_data["image"])
                if os.path.exists(icon_path):
                    pil_img = Image.open(icon_path)
                    img = ctk.CTkImage(pil_img, size=(72, 72))
                    self._current_image = img  # keep reference to avoid GC
                    img_label = ctk.CTkLabel(self.main_frame, image=img, text="")
                    img_label.pack(pady=(0, 10))
            except Exception as e:
                print(f"Error loading image {step_data.get('image')}: {e}")

        # Body text: match wraplength to window width so lines are readable
        wrap_len = self.win_width - 100
        text_label = ctk.CTkLabel(
            self.main_frame,
            text=step_data["text"],
            wraplength=wrap_len,
            font=ctk.CTkFont(size=13),
            justify="left"
        )
        text_label.pack(pady=(4, 12), padx=8)

        self.create_navigation_buttons()

    def create_navigation_buttons(self):
        button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        button_frame.pack(side="bottom", fill="x", pady=(8, 6), padx=6)

        # Use grid inside the button_frame so "Previous" stays left and "Next/Finish" stays right
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        left_container = ctk.CTkFrame(button_frame, fg_color="transparent")
        left_container.grid(row=0, column=0, sticky="w")
        right_container = ctk.CTkFrame(button_frame, fg_color="transparent")
        right_container.grid(row=0, column=1, sticky="e")

        if self.current_step > 0:
            prev_button = ctk.CTkButton(left_container, text=self.lang_manager.get_string("previous_button"), command=self.prev_step, width=110)
            prev_button.pack(side="left", padx=4)

        if self.current_step < len(self.steps) - 1:
            skip_button = ctk.CTkButton(right_container, text=self.lang_manager.get_string("skip_button"), command=self.finish_tutorial, width=110)
            skip_button.pack(side="right", padx=4)
            next_button = ctk.CTkButton(right_container, text=self.lang_manager.get_string("next_button"), command=self.next_step, width=110)
            next_button.pack(side="right", padx=4)
        else:
            finish_button = ctk.CTkButton(right_container, text=self.lang_manager.get_string("finish_button"), command=self.finish_tutorial, width=110)
            finish_button.pack(side="right", padx=4)

    def next_step(self):
        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self.show_step()
            # re-center in case parent moved while tutorial open:
            self._center_window(self.tutorial_window, self.win_width, self.win_height, parent=self.parent)

    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.show_step()
            self._center_window(self.tutorial_window, self.win_width, self.win_height, parent=self.parent)

    def finish_tutorial(self):
        self.tutorial_window.destroy()