import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
from datetime import datetime

class ToolDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Tool Dashboard")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # Data storage
        self.data = {
            'projects': [
                {'id': 1, 'name': 'Project Alpha', 'status': 'Active', 'progress': 75},
                {'id': 2, 'name': 'Project Beta', 'status': 'Pending', 'progress': 30},
                {'id': 3, 'name': 'Project Gamma', 'status': 'Complete', 'progress': 100}
            ],
            'settings': {
                'theme': 'light',
                'notifications': True
            }
        }
        
        self.current_tab = 'dashboard'
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left sidebar
        self.setup_sidebar(main_frame)
        
        # Right content area
        self.setup_content_area(main_frame)
        
        # Load dashboard by default
        self.show_dashboard()
    
    def setup_sidebar(self, parent):
        sidebar_frame = ttk.Frame(parent, width=200)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar_frame.pack_propagate(False)
        
        # Title
        title_label = ttk.Label(sidebar_frame, text="Tool Dashboard", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Navigation buttons
        nav_buttons = [
            ('Dashboard', self.show_dashboard),
            ('Projects', self.show_projects),
            ('Data', self.show_data),
            ('Analytics', self.show_analytics),
            ('Users', self.show_users),
            ('Settings', self.show_settings)
        ]
        
        self.nav_buttons = {}
        for text, command in nav_buttons:
            btn = ttk.Button(sidebar_frame, text=text, command=command, width=20)
            btn.pack(pady=2, fill=tk.X)
            self.nav_buttons[text.lower()] = btn
    
    def setup_content_area(self, parent):
        # Content frame with scrollable area
        self.content_frame = ttk.Frame(parent)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Header
        self.header_frame = ttk.Frame(self.content_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.header_label = ttk.Label(self.header_frame, text="Dashboard", 
                                     font=('Arial', 16, 'bold'))
        self.header_label.pack(side=tk.LEFT)
        
        # Scrollable content
        self.canvas = tk.Canvas(self.content_frame, bg='white')
        self.scrollbar = ttk.Scrollbar(self.content_frame, orient="vertical", 
                                      command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
    
    def clear_content(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
    
    def show_dashboard(self):
        self.clear_content()
        self.header_label.config(text="Dashboard")
        self.current_tab = 'dashboard'
        
        # Stats cards
        stats_frame = ttk.Frame(self.scrollable_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 20))
        
        stats = [
            ("Total Projects", len(self.data['projects']), '#3b82f6'),
            ("Active", len([p for p in self.data['projects'] if p['status'] == 'Active']), '#10b981'),
            ("Completed", len([p for p in self.data['projects'] if p['status'] == 'Complete']), '#8b5cf6')
        ]
        
        for i, (title, value, color) in enumerate(stats):
            card = ttk.LabelFrame(stats_frame, text=title, padding=10)
            card.grid(row=0, column=i, padx=10, sticky='ew')
            stats_frame.grid_columnconfigure(i, weight=1)
            
            value_label = ttk.Label(card, text=str(value), font=('Arial', 24, 'bold'))
            value_label.pack()
        
        # Recent activity
        activity_frame = ttk.LabelFrame(self.scrollable_frame, text="Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview for projects
        columns = ('Name', 'Status', 'Progress')
        tree = ttk.Treeview(activity_frame, columns=columns, show='headings', height=6)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        for project in self.data['projects']:
            tree.insert('', tk.END, values=(
                project['name'], 
                project['status'], 
                f"{project['progress']}%"
            ))
        
        tree.pack(fill=tk.BOTH, expand=True)
    
    def show_projects(self):
        self.clear_content()
        self.header_label.config(text="Projects")
        
        # Header with add button
        header_frame = ttk.Frame(self.scrollable_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        add_btn = ttk.Button(header_frame, text="New Project", command=self.add_project)
        add_btn.pack(side=tk.RIGHT)
        
        # Projects table
        columns = ('ID', 'Name', 'Status', 'Progress', 'Actions')
        self.projects_tree = ttk.Treeview(self.scrollable_frame, columns=columns, show='headings')
        
        for col in columns:
            self.projects_tree.heading(col, text=col)
            if col == 'Actions':
                self.projects_tree.column(col, width=100)
            else:
                self.projects_tree.column(col, width=120)
        
        self.refresh_projects_table()
        
        self.projects_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind double-click to edit
        self.projects_tree.bind('<Double-1>', self.edit_project)
    
    def refresh_projects_table(self):
        for item in self.projects_tree.get_children():
            self.projects_tree.delete(item)
            
        for project in self.data['projects']:
            self.projects_tree.insert('', tk.END, values=(
                project['id'],
                project['name'],
                project['status'],
                f"{project['progress']}%",
                "Edit/Delete"
            ))
    
    def add_project(self):
        self.project_dialog()
    
    def edit_project(self, event=None):
        selection = self.projects_tree.selection()
        if selection:
            item = self.projects_tree.item(selection[0])
            project_id = int(item['values'][0])
            project = next(p for p in self.data['projects'] if p['id'] == project_id)
            self.project_dialog(project)
    
    def project_dialog(self, project=None):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Project" if project is None else "Edit Project")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        ttk.Label(dialog, text="Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=40)
        name_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Status:").pack(pady=5)
        status_combo = ttk.Combobox(dialog, values=['Active', 'Pending', 'Complete'], width=37)
        status_combo.pack(pady=5)
        
        ttk.Label(dialog, text="Progress:").pack(pady=5)
        progress_var = tk.IntVar()
        progress_scale = ttk.Scale(dialog, from_=0, to=100, orient=tk.HORIZONTAL, 
                                  variable=progress_var, length=300)
        progress_scale.pack(pady=5)
        
        progress_label = ttk.Label(dialog, text="0%")
        progress_label.pack()
        
        def update_progress_label(event=None):
            progress_label.config(text=f"{int(progress_var.get())}%")
        
        progress_scale.configure(command=update_progress_label)
        
        # Fill existing data
        if project:
            name_entry.insert(0, project['name'])
            status_combo.set(project['status'])
            progress_var.set(project['progress'])
            update_progress_label()
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=20)
        
        def save_project():
            name = name_entry.get().strip()
            status = status_combo.get()
            progress = int(progress_var.get())
            
            if not name or not status:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            if project:  # Edit existing
                project['name'] = name
                project['status'] = status
                project['progress'] = progress
            else:  # Add new
                new_id = max([p['id'] for p in self.data['projects']], default=0) + 1
                self.data['projects'].append({
                    'id': new_id,
                    'name': name,
                    'status': status,
                    'progress': progress
                })
            
            if hasattr(self, 'projects_tree'):
                self.refresh_projects_table()
            
            dialog.destroy()
        
        ttk.Button(btn_frame, text="Save", command=save_project).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def show_data(self):
        self.clear_content()
        self.header_label.config(text="Data Management")
        
        # Import section
        import_frame = ttk.LabelFrame(self.scrollable_frame, text="Import Data", padding=10)
        import_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(import_frame, text="Import data from files").pack(pady=5)
        ttk.Button(import_frame, text="Choose Files", command=self.import_data).pack(pady=5)
        
        # Export section
        export_frame = ttk.LabelFrame(self.scrollable_frame, text="Export Data", padding=10)
        export_frame.pack(fill=tk.X)
        
        ttk.Button(export_frame, text="Export as JSON", command=self.export_json).pack(pady=2, fill=tk.X)
        ttk.Button(export_frame, text="Export as CSV", command=self.export_csv).pack(pady=2, fill=tk.X)
    
    def import_data(self):
        filename = filedialog.askopenfilename(
            title="Select data file",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    imported_data = json.load(f)
                    if 'projects' in imported_data:
                        self.data['projects'] = imported_data['projects']
                        messagebox.showinfo("Success", "Data imported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import data: {str(e)}")
    
    def export_json(self):
        filename = filedialog.asksaveasfilename(
            title="Save as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.data, f, indent=2)
                messagebox.showinfo("Success", "Data exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def export_csv(self):
        filename = filedialog.asksaveasfilename(
            title="Save as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Name', 'Status', 'Progress'])
                    for project in self.data['projects']:
                        writer.writerow([project['id'], project['name'], 
                                       project['status'], project['progress']])
                messagebox.showinfo("Success", "Data exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def show_analytics(self):
        self.clear_content()
        self.header_label.config(text="Analytics")
        
        analytics_frame = ttk.LabelFrame(self.scrollable_frame, text="Performance Metrics", padding=10)
        analytics_frame.pack(fill=tk.BOTH, expand=True)
        
        # Calculate metrics
        total_projects = len(self.data['projects'])
        avg_progress = sum(p['progress'] for p in self.data['projects']) / total_projects if total_projects > 0 else 0
        completed = len([p for p in self.data['projects'] if p['status'] == 'Complete'])
        
        metrics = [
            ("Completion Rate", f"{avg_progress:.1f}%"),
            ("Tasks Completed", str(completed)),
            ("Total Projects", str(total_projects)),
            ("Active Projects", str(len([p for p in self.data['projects'] if p['status'] == 'Active'])))
        ]
        
        for i, (label, value) in enumerate(metrics):
            row = i // 2
            col = i % 2
            
            metric_frame = ttk.Frame(analytics_frame)
            metric_frame.grid(row=row, column=col, padx=20, pady=20, sticky='ew')
            
            ttk.Label(metric_frame, text=value, font=('Arial', 20, 'bold')).pack()
            ttk.Label(metric_frame, text=label).pack()
        
        analytics_frame.grid_columnconfigure(0, weight=1)
        analytics_frame.grid_columnconfigure(1, weight=1)
    
    def show_users(self):
        self.clear_content()
        self.header_label.config(text="User Management")
        
        users_frame = ttk.LabelFrame(self.scrollable_frame, text="Users", padding=10)
        users_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(users_frame, text="User management functionality will be implemented here.").pack(pady=20)
        ttk.Button(users_frame, text="Add User", command=lambda: messagebox.showinfo("Info", "Add User functionality")).pack()
    
    def show_settings(self):
        self.clear_content()
        self.header_label.config(text="Settings")
        
        settings_frame = ttk.LabelFrame(self.scrollable_frame, text="Preferences", padding=10)
        settings_frame.pack(fill=tk.X)
        
        # Notifications setting
        notifications_var = tk.BooleanVar(value=self.data['settings']['notifications'])
        notifications_cb = ttk.Checkbutton(
            settings_frame, 
            text="Enable Notifications", 
            variable=notifications_var,
            command=lambda: self.update_setting('notifications', notifications_var.get())
        )
        notifications_cb.pack(anchor='w', pady=5)
        
        # Theme setting
        theme_frame = ttk.Frame(settings_frame)
        theme_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(theme_frame, text="Theme:").pack(side=tk.LEFT)
        theme_var = tk.StringVar(value=self.data['settings']['theme'])
        theme_combo = ttk.Combobox(
            theme_frame, 
            textvariable=theme_var, 
            values=['light', 'dark'], 
            state='readonly'
        )
        theme_combo.pack(side=tk.RIGHT)
        theme_combo.bind('<<ComboboxSelected>>', 
                        lambda e: self.update_setting('theme', theme_var.get()))
    
    def update_setting(self, key, value):
        self.data['settings'][key] = value
        # Here you could save settings to file or apply theme changes

def main():
    root = tk.Tk()
    app = ToolDashboard(root)
    
    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()