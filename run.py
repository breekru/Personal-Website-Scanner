import argparse
import tkinter as tk
from ui import WebsiteVerificationTool
from ui.theme import _HAS_TTKB

def main():
    parser = argparse.ArgumentParser(description="Website Verification")
    if _HAS_TTKB:
        parser.add_argument(
            "--theme",
            default="litera",
            help="ttkbootstrap theme to use",
        )
    args = parser.parse_args()

    root = tk.Tk()
    root.title("Website Verification")
    theme = getattr(args, "theme", None)
    app = WebsiteVerificationTool(root, db_path="website_verification.db", theme=theme)
    app.load_websites()  # populate initial table
    root.mainloop()

if __name__ == "__main__":
    main()
