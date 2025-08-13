import tkinter as tk
from ui import WebsiteVerificationTool

def main():
    root = tk.Tk()
    root.title("Website Verification")
    app = WebsiteVerificationTool(root, db_path="website_verification.db")
    app.load_websites()           # populate initial table
    root.mainloop()

if __name__ == "__main__":
    main()
