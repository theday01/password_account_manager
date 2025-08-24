import customtkinter as ctk
from PIL import Image, ImageTk
import os

class TutorialManager:
    def __init__(self, parent):
        self.parent = parent
        self.tutorial_window = None
        self.current_step = 0

        self.steps = [
            {
                "title": "Welcome to SecureVault!",
                "text": "This quick tutorial will guide you through the main features of the application.",
                "image": "info.png" 
            },
            {
                "title": "The Master Password",
                "text": "Your Master Password is the one and only key to your vault. Keep it safe and don't forget it!",
                "image": "security.png"
            },
            {
                "title": "Adding an Account",
                "text": "Click 'Add New Account' to save new login credentials. You can generate a strong password or enter your own.",
                "image": "user.png"
            },
            {
                "title": "Password Generator",
                "text": "Use the built-in generator to create strong, unique passwords for your accounts.",
                "image": "password.png"
            },
            {
                "title": "All Done!",
                "text": "You're now ready to use SecureVault. Stay secure!",
                "image": "logout.png"
            }
        ]

    def show_tutorial_window(self):
        self.tutorial_window = ctk.CTkToplevel(self.parent)
        self.tutorial_window.title("Welcome to SecureVault")
        self.tutorial_window.geometry("500x400")
        self.tutorial_window.resizable(False, False)
        self.tutorial_window.overrideredirect(True)
        self.tutorial_window.grab_set()

        self.main_frame = ctk.CTkFrame(self.tutorial_window)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.show_step()
        
        self.parent.wait_window(self.tutorial_window)

    def show_step(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        step_data = self.steps[self.current_step]

        title_label = ctk.CTkLabel(self.main_frame, text=step_data["title"], font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=(10, 20))

        if "image" in step_data:
            try:
                icon_path = os.path.join("icons", step_data["image"])
                if os.path.exists(icon_path):
                    img = ctk.CTkImage(Image.open(icon_path), size=(64, 64))
                    img_label = ctk.CTkLabel(self.main_frame, image=img, text="")
                    img_label.pack(pady=10)
            except Exception as e:
                print(f"Error loading image {step_data['image']}: {e}")

        text_label = ctk.CTkLabel(self.main_frame, text=step_data["text"], wraplength=400, font=ctk.CTkFont(size=14))
        text_label.pack(pady=10, padx=20)

        self.create_navigation_buttons()

    def create_navigation_buttons(self):
        button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        button_frame.pack(side="bottom", fill="x", pady=20)

        if self.current_step > 0:
            prev_button = ctk.CTkButton(button_frame, text="Previous", command=self.prev_step)
            prev_button.pack(side="left", padx=20)

        if self.current_step < len(self.steps) - 1:
            next_button = ctk.CTkButton(button_frame, text="Next", command=self.next_step)
            next_button.pack(side="right", padx=20)
        else:
            finish_button = ctk.CTkButton(button_frame, text="Finish", command=self.finish_tutorial)
            finish_button.pack(side="right", padx=20)

    def next_step(self):
        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self.show_step()

    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.show_step()

    def finish_tutorial(self):
        self.tutorial_window.destroy()

if __name__ == "__main__":
    # This is for testing the tutorial window independently
    root = ctk.CTk()
    root.geometry("800x600")
    
    def open_tutorial():
        tutorial = TutorialManager(root)
        tutorial.show_tutorial_window()

    button = ctk.CTkButton(root, text="Show Tutorial", command=open_tutorial)
    button.pack(pady=50)

    root.mainloop()
