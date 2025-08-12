import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sqlite3
import requests
import ssl
import socket
import whois
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import threading
import os
import json
from urllib.parse import urlparse
import subprocess
import sys
import warnings

# Suppress SSL warnings for intentional unverified requests
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


def get_whois_info(domain):
    """Retrieve WHOIS information using whichever whois library is available."""
    if hasattr(whois, "whois"):
        return whois.whois(domain)
    if hasattr(whois, "query"):
        return whois.query(domain)
    raise AttributeError("whois module has no whois or query function")

class WebsiteVerificationTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Website Legitimacy Verification Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg='#f0f0f0')
        
        # Database setup
        self.db_path = "website_verification.db"
        self.init_database()
        
        # Settings
        self.settings = self.load_settings()
        
        self.setup_ui()
        self.load_websites()
        
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Websites table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                name TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP,
                status TEXT DEFAULT 'pending',
                notes TEXT
            )
        ''')
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website_id INTEGER,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                registrar TEXT,
                page_title TEXT,
                status_code INTEGER,
                ssl_valid BOOLEAN,
                ssl_issuer TEXT,
                ssl_expiry TEXT,
                source_code_hash TEXT,
                changes_detected BOOLEAN DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                additional_checks TEXT,
                FOREIGN KEY (website_id) REFERENCES websites (id)
            )
        ''')
        
        # Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_settings(self):
        """Load settings from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT key, value FROM settings")
        settings_data = dict(cursor.fetchall())
        
        # Default settings - UPDATED to include retry settings
        defaults = {
            'email_smtp_server': 'smtp.gmail.com',
            'email_smtp_port': '587',
            'email_username': '',
            'email_password': '',
            'notification_emails': '',
            'scan_frequency_days': '7',
            'github_repo': '',
            'scan_retries': '5',  # NEW: Default 5 retries
            'retry_delay_seconds': '3'  # NEW: Default 3 second delay
        }
        
        for key, default_value in defaults.items():
            if key not in settings_data:
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", 
                            (key, default_value))
                settings_data[key] = default_value
        
        conn.commit()
        conn.close()
        return settings_data
    
    def save_setting(self, key, value):
        """Save setting to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()
        self.settings[key] = value
    
    def analyze_content_changes(self, old_hash, new_hash, old_length, new_length, old_norm_length, new_norm_length):
        """Analyze content changes and categorize them"""
        
        # If hashes are the same, no change
        if old_hash == new_hash:
            return {'has_changes': False, 'change_type': 'none', 'change_pct': 0}
        
        # If we don't have length data, assume it's significant
        if not old_length or not new_length:
            print(f"    No length data available - treating as significant")
            return {'has_changes': True, 'change_type': 'significant', 'change_pct': None}
        
        # Calculate percentage change in content length
        length_change_pct = abs(new_length - old_length) / old_length * 100
        
        # Use normalized length if available for better comparison
        norm_change_pct = None
        if old_norm_length and new_norm_length:
            norm_change_pct = abs(new_norm_length - old_norm_length) / old_norm_length * 100
            print(f"    Normalized content change: {norm_change_pct:.1f}%")
        
        print(f"    Raw content length change: {length_change_pct:.1f}%")
        
        # Use the better metric for classification
        primary_change_pct = norm_change_pct if norm_change_pct is not None else length_change_pct
        
        # Categorize changes
        if primary_change_pct < 2:
            print(f"    Minor/informational change detected ({primary_change_pct:.1f}%)")
            return {'has_changes': True, 'change_type': 'informational', 'change_pct': primary_change_pct}
        elif primary_change_pct > 15:
            print(f"    Major change detected ({primary_change_pct:.1f}%) - high priority")
            return {'has_changes': True, 'change_type': 'major', 'change_pct': primary_change_pct}
        else:
            print(f"    Moderate change detected ({primary_change_pct:.1f}%) - medium priority")
            return {'has_changes': True, 'change_type': 'moderate', 'change_pct': primary_change_pct}

    def setup_ui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Websites tab
        self.websites_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.websites_frame, text="Websites")
        self.setup_websites_tab()
        
        # Scan Results tab
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="Scan Results")
        self.setup_results_tab()
        
        # Settings tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        self.setup_settings_tab()
        
        # Reports tab
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text="Reports")
        self.setup_reports_tab()
    
    def setup_websites_tab(self):
        # Top frame for controls
        controls_frame = ttk.Frame(self.websites_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add website section
        add_frame = ttk.LabelFrame(controls_frame, text="Add Website", padding=10)
        add_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(add_frame, text="URL:").grid(row=0, column=0, sticky='w')
        self.url_entry = ttk.Entry(add_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(add_frame, text="Name:").grid(row=0, column=2, sticky='w', padx=(20, 0))
        self.name_entry = ttk.Entry(add_frame, width=30)
        self.name_entry.grid(row=0, column=3, padx=5)
        
        ttk.Button(add_frame, text="Add Website", command=self.add_website).grid(row=0, column=4, padx=10)
        
        # Bulk operations
        bulk_frame = ttk.Frame(controls_frame)
        bulk_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(bulk_frame, text="Import from File", command=self.import_websites).pack(side=tk.LEFT, padx=5)
        ttk.Button(bulk_frame, text="Scan All", command=self.scan_all_websites).pack(side=tk.LEFT, padx=5)
        ttk.Button(bulk_frame, text="Scan Selected", command=self.scan_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(bulk_frame, text="Delete Selected", command=self.delete_selected).pack(side=tk.LEFT, padx=5)
        
        # Websites list
        list_frame = ttk.LabelFrame(self.websites_frame, text="Monitored Websites", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Treeview for websites with comprehensive columns - UPDATED to include Domain Age
        columns = ('ID', 'Name', 'URL', 'Last Checked', 'Status Code', 'SSL', 'Registrar', 'Domain Age', 'Changes', 'Risk Score', 'Issues')
        self.websites_tree = ttk.Treeview(list_frame, columns=columns, show='headings', selectmode='extended')
        
        # Configure column widths and headings - UPDATED to include Domain Age
        column_configs = {
            'ID': 40,
            'Name': 150,
            'URL': 220,  # Slightly reduced to make room
            'Last Checked': 110,  # Slightly reduced
            'Status Code': 80,
            'SSL': 60,
            'Registrar': 110,  # Slightly reduced
            'Domain Age': 90,  # NEW COLUMN
            'Changes': 70,
            'Risk Score': 80,
            'Issues': 180  # Slightly reduced
        }
        
        for col in columns:
            self.websites_tree.heading(col, text=col)
            self.websites_tree.column(col, width=column_configs.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.websites_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient="horizontal", command=self.websites_tree.xview)
        self.websites_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.websites_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Bind double-click to view details
        self.websites_tree.bind('<Double-1>', self.view_website_details)

    
    def setup_results_tab(self):
        # Filter frame
        filter_frame = ttk.LabelFrame(self.results_frame, text="Filters", padding=10)
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Website:").grid(row=0, column=0, sticky='w')
        self.filter_website = ttk.Combobox(filter_frame, width=30)
        self.filter_website.grid(row=0, column=1, padx=5)
        
        ttk.Label(filter_frame, text="Date Range:").grid(row=0, column=2, sticky='w', padx=(20, 0))
        self.filter_days = ttk.Combobox(filter_frame, values=['7', '30', '90', 'All'], width=10)
        self.filter_days.set('30')
        self.filter_days.grid(row=0, column=3, padx=5)
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_results_filter).grid(row=0, column=4, padx=10)
        
        # Results list
        results_list_frame = ttk.LabelFrame(self.results_frame, text="Scan Results", padding=10)
        results_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        columns = ('Date', 'Website', 'Status Code', 'SSL Valid', 'Registrar', 'Changes', 'Risk Score')
        self.results_tree = ttk.Treeview(results_list_frame, columns=columns, show='headings')
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120)
        
        # Scrollbar for results
        results_scrollbar = ttk.Scrollbar(results_list_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky='nsew')
        results_scrollbar.grid(row=0, column=1, sticky='ns')
        
        results_list_frame.grid_rowconfigure(0, weight=1)
        results_list_frame.grid_columnconfigure(0, weight=1)
        
        self.load_scan_results()
    
    def setup_settings_tab(self):
        # Email settings
        email_frame = ttk.LabelFrame(self.settings_frame, text="Email Notification Settings", padding=10)
        email_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # SMTP settings
        ttk.Label(email_frame, text="SMTP Server:").grid(row=0, column=0, sticky='w')
        self.smtp_server_entry = ttk.Entry(email_frame, width=30)
        self.smtp_server_entry.insert(0, self.settings.get('email_smtp_server', ''))
        self.smtp_server_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(email_frame, text="SMTP Port:").grid(row=0, column=2, sticky='w', padx=(20, 0))
        self.smtp_port_entry = ttk.Entry(email_frame, width=10)
        self.smtp_port_entry.insert(0, self.settings.get('email_smtp_port', ''))
        self.smtp_port_entry.grid(row=0, column=3, padx=5)
        
        ttk.Label(email_frame, text="Username:").grid(row=1, column=0, sticky='w')
        self.email_username_entry = ttk.Entry(email_frame, width=30)
        self.email_username_entry.insert(0, self.settings.get('email_username', ''))
        self.email_username_entry.grid(row=1, column=1, padx=5)
        
        ttk.Label(email_frame, text="Password:").grid(row=1, column=2, sticky='w', padx=(20, 0))
        self.email_password_entry = ttk.Entry(email_frame, width=20, show='*')
        self.email_password_entry.insert(0, self.settings.get('email_password', ''))
        self.email_password_entry.grid(row=1, column=3, padx=5)
        
        ttk.Label(email_frame, text="Notification Emails:").grid(row=2, column=0, sticky='w')
        self.notification_emails_entry = ttk.Entry(email_frame, width=50)
        self.notification_emails_entry.insert(0, self.settings.get('notification_emails', ''))
        self.notification_emails_entry.grid(row=2, column=1, columnspan=2, padx=5)
        
        # Scan settings - UPDATED to include retry settings
        scan_frame = ttk.LabelFrame(self.settings_frame, text="Scan Settings", padding=10)
        scan_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(scan_frame, text="Scan Frequency (days):").grid(row=0, column=0, sticky='w')
        self.scan_frequency_entry = ttk.Entry(scan_frame, width=10)
        self.scan_frequency_entry.insert(0, self.settings.get('scan_frequency_days', '7'))
        self.scan_frequency_entry.grid(row=0, column=1, padx=5)
        
        # NEW: Retry settings
        ttk.Label(scan_frame, text="Scan Retries:").grid(row=0, column=2, sticky='w', padx=(20, 0))
        self.scan_retries_entry = ttk.Entry(scan_frame, width=10)
        self.scan_retries_entry.insert(0, self.settings.get('scan_retries', '5'))
        self.scan_retries_entry.grid(row=0, column=3, padx=5)
        
        ttk.Label(scan_frame, text="Retry Delay (seconds):").grid(row=1, column=0, sticky='w')
        self.retry_delay_entry = ttk.Entry(scan_frame, width=10)
        self.retry_delay_entry.insert(0, self.settings.get('retry_delay_seconds', '3'))
        self.retry_delay_entry.grid(row=1, column=1, padx=5)
        
        # GitHub settings
        github_frame = ttk.LabelFrame(self.settings_frame, text="GitHub Integration", padding=10)
        github_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(github_frame, text="GitHub Repository:").grid(row=0, column=0, sticky='w')
        self.github_repo_entry = ttk.Entry(github_frame, width=50)
        self.github_repo_entry.insert(0, self.settings.get('github_repo', ''))
        self.github_repo_entry.grid(row=0, column=1, padx=5)
        
        ttk.Button(github_frame, text="Sync to GitHub", command=self.sync_to_github).grid(row=0, column=2, padx=10)
        ttk.Button(github_frame, text="Pull from GitHub", command=self.pull_from_github).grid(row=0, column=3, padx=5)
        
        # Save button
        ttk.Button(self.settings_frame, text="Save Settings", command=self.save_settings).pack(pady=20)

    
    def setup_reports_tab(self):
        # Report generation
        report_frame = ttk.LabelFrame(self.reports_frame, text="Generate Reports", padding=10)
        report_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(report_frame, text="Risk Assessment Report", command=self.generate_risk_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(report_frame, text="Changes Report", command=self.generate_changes_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(report_frame, text="Weekly Summary", command=self.generate_weekly_summary).pack(side=tk.LEFT, padx=5)
        
        # Report display
        self.report_text = scrolledtext.ScrolledText(self.reports_frame, height=30)
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def add_website(self):
        """Add a new website to monitor"""
        url = self.url_entry.get().strip()
        name = self.name_entry.get().strip() or url
        
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        # Add http if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO websites (url, name) VALUES (?, ?)", (url, name))
            conn.commit()
            conn.close()
            
            self.url_entry.delete(0, tk.END)
            self.name_entry.delete(0, tk.END)
            self.load_websites()
            messagebox.showinfo("Success", f"Added {url} to monitoring list")
            
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Website already exists in database")
    
    def load_websites(self):
        """Load websites into the treeview with comprehensive information including domain age"""
        for item in self.websites_tree.get_children():
            self.websites_tree.delete(item)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # First get all websites
        cursor.execute('SELECT id, name, url, last_checked FROM websites ORDER BY name')
        websites = cursor.fetchall()
        
        # Then get latest scan data for each website individually
        for website in websites:
            website_id, name, url, last_checked = website
            
            # Get the most recent scan result for this specific website
            cursor.execute('''
                SELECT status_code, ssl_valid, registrar, changes_detected, 
                    risk_score, additional_checks
                FROM scan_results 
                WHERE website_id = ? 
                ORDER BY scan_date DESC 
                LIMIT 1
            ''', (website_id,))
            
            scan_data = cursor.fetchone()
            
            if scan_data:
                status_code, ssl_valid, registrar, changes_detected, risk_score, additional_checks = scan_data
            else:
                # No scan data available
                status_code, ssl_valid, registrar, changes_detected, risk_score, additional_checks = 0, None, None, None, 0, '{}'
            
            # Format display values with proper handling of NULL/default values
            if status_code == 0 or status_code is None:
                status_display = 'Not Scanned'
            else:
                status_display = str(status_code)
            
            # SSL display - fix the logic
            if ssl_valid == 1 or ssl_valid is True:
                ssl_display = '✓ Valid'
            elif ssl_valid == 0 or ssl_valid is False:
                ssl_display = '✗ Invalid'
            else:
                ssl_display = 'Not Scanned'
            
            # Registrar display
            if registrar and registrar not in ['Unknown', 'Whois lookup failed']:
                registrar_display = registrar
            elif status_code and status_code != 0:
                registrar_display = 'Unknown'
            else:
                registrar_display = 'Not Scanned'
            
            # Domain Age display - NEW LOGIC
            domain_age_display = 'Not Scanned'
            if additional_checks and additional_checks != '{}':
                try:
                    checks = json.loads(additional_checks) if isinstance(additional_checks, str) else additional_checks
                    domain_age_days = checks.get('domain_age_days')
                    
                    if domain_age_days is not None:
                        if domain_age_days < 30:
                            domain_age_display = f"{domain_age_days}d ⚠️"  # Warning for new domains
                        elif domain_age_days < 365:
                            domain_age_display = f"{domain_age_days}d"
                        elif domain_age_days < 3650:  # Less than 10 years
                            years = domain_age_days // 365
                            remaining_days = domain_age_days % 365
                            if remaining_days > 30:
                                domain_age_display = f"{years}y {remaining_days // 30}m"
                            else:
                                domain_age_display = f"{years}y"
                        else:  # 10+ years
                            years = domain_age_days // 365
                            domain_age_display = f"{years}y+"
                    elif status_code and status_code != 0:
                        domain_age_display = 'Unknown'
                except:
                    if status_code and status_code != 0:
                        domain_age_display = 'Unknown'
            
            # Changes display
            if changes_detected == 1:
                changes_display = '⚠ Yes'
            elif changes_detected == 0:
                changes_display = '✓ No'
            else:
                changes_display = 'Not Scanned'
            
            # Risk score display
            if risk_score is None or (risk_score == 0 and status_code == 0):
                risk_display = 'Not Scanned'
            else:
                risk_display = f"{risk_score}/100"
            
            # Analyze issues from additional checks
            issues = []
            if additional_checks and additional_checks != '{}':
                try:
                    checks = json.loads(additional_checks) if isinstance(additional_checks, str) else additional_checks
                    if 'suspicious_domain' in checks:
                        issues.append('Suspicious Domain')
                    if 'new_domain_warning' in checks:
                        issues.append('New Domain')
                    if checks.get('https_redirect') == False:
                        issues.append('No HTTPS Redirect')
                    if 'http_error' in checks:
                        issues.append('HTTP Error')
                    if 'scan_error' in checks:
                        issues.append('Scan Error')
                except:
                    pass
            
            # Add scan-based issues only if actually scanned
            if status_code and status_code != 0:
                if status_code >= 400:
                    issues.append(f'HTTP {status_code}')
                if ssl_valid == 0 or ssl_valid is False:
                    issues.append('SSL Issues')
                if risk_score and risk_score >= 50:
                    issues.append('High Risk')
            
            if issues:
                issues_display = '; '.join(issues[:3])
                if len(issues) > 3:
                    issues_display += f' (+{len(issues)-3} more)'
            elif status_code and status_code != 0:
                issues_display = 'None'
            else:
                issues_display = 'Not Scanned'
            
            # Determine tag for color coding (enhanced with domain age)
            if status_code == 0 or status_code is None:
                tag = 'not_scanned'
            elif risk_score and risk_score >= 50:
                tag = 'high_risk'
            elif risk_score and risk_score >= 20:
                tag = 'medium_risk'
            elif domain_age_display.endswith('⚠️'):  # New domain warning
                tag = 'new_domain'
            else:
                tag = 'low_risk'
            
            # Insert the row - UPDATED to include domain age
            self.websites_tree.insert('', tk.END, values=(
                website_id, name, url, 
                last_checked[:16] if last_checked else 'Never',
                status_display, ssl_display, registrar_display,
                domain_age_display,  # NEW COLUMN DATA
                changes_display, risk_display, issues_display
            ), tags=(tag,))
        
        conn.close()
        
        # Configure tags for color coding (enhanced with new domain tag)
        self.websites_tree.tag_configure('high_risk', background='#ffebee')  # Light red
        self.websites_tree.tag_configure('medium_risk', background='#fff3e0')  # Light orange
        self.websites_tree.tag_configure('low_risk', background='#e8f5e8')  # Light green
        self.websites_tree.tag_configure('not_scanned', background='#f5f5f5')  # Light gray
        self.websites_tree.tag_configure('new_domain', background='#fff9c4')  # Light yellow for new domains
    
    def scan_website(self, website_id, url):
        """Perform comprehensive scan of a website with improved change detection"""
        try:
            print(f"Scanning website: {url}")
            
            # Get previous scan for comparison
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT source_code_hash, page_title, registrar, additional_checks FROM scan_results 
                WHERE website_id = ? 
                ORDER BY scan_date DESC LIMIT 1
            ''', (website_id,))
            
            previous_scan = cursor.fetchone()
            previous_hash = previous_scan[0] if previous_scan else None
            previous_title = previous_scan[1] if previous_scan else None
            previous_registrar = previous_scan[2] if previous_scan else None
            previous_additional = previous_scan[3] if previous_scan else None
            
            # Get previous content metrics for comparison
            previous_content_length = None
            previous_normalized_length = None
            if previous_additional:
                try:
                    prev_checks = json.loads(previous_additional)
                    previous_content_length = prev_checks.get('content_length')
                    previous_normalized_length = prev_checks.get('normalized_length')
                except:
                    pass
            
            print(f"Previous scan data:")
            print(f"  Previous hash: {previous_hash}")
            print(f"  Previous content length: {previous_content_length}")
            print(f"  Previous normalized length: {previous_normalized_length}")
            
            # Perform current scan
            scan_result = self.perform_website_checks(url)
            scan_result['website_id'] = website_id
            
            current_hash = scan_result.get('source_code_hash', '')
            current_content_length = scan_result.get('additional_checks', {}).get('content_length')
            current_normalized_length = scan_result.get('additional_checks', {}).get('normalized_length')
            
            print(f"Current scan data:")
            print(f"  Current hash: {current_hash}")
            print(f"  Current content length: {current_content_length}")
            print(f"  Current normalized length: {current_normalized_length}")
            
            # Enhanced change detection
            changes_detected = False
            change_details = []
            
            # 1. Content hash comparison with categorization
            if previous_hash and current_hash:
                if previous_hash != current_hash:
                    # Content has changed - analyze the type of change
                    change_analysis = self.analyze_content_changes(
                        previous_hash, current_hash,
                        previous_content_length, current_content_length,
                        previous_normalized_length, current_normalized_length
                    )
                    
                    change_type = change_analysis['change_type']
                    change_pct = change_analysis['change_pct']
                    
                    # Always flag as a change, but categorize it
                    changes_detected = True
                    
                    # Create appropriate change details based on type
                    if change_type == 'informational':
                        if change_pct is not None:
                            change_details.append(f'Minor content change ({change_pct:.1f}% - informational)')
                        else:
                            change_details.append('Minor content change (informational)')
                        print(f"  ℹ INFORMATIONAL content change detected")
                        
                    elif change_type == 'moderate':
                        if change_pct is not None:
                            change_details.append(f'Moderate content change ({change_pct:.1f}%)')
                        else:
                            change_details.append('Moderate content change')
                        print(f"  ⚠ MODERATE content change detected")
                        
                    elif change_type == 'major':
                        if change_pct is not None:
                            change_details.append(f'Major content change ({change_pct:.1f}%)')
                        else:
                            change_details.append('Major content change')
                        print(f"  🚨 MAJOR content change detected")
                    
                    # Store change type for later use
                    scan_result['additional_checks']['content_change_type'] = change_type
                    if change_pct is not None:
                        scan_result['additional_checks']['content_change_percentage'] = round(change_pct, 1)
                        
                else:
                    print(f"  ✓ No content changes")
            elif not previous_hash and current_hash:
                # First scan - not a change
                print(f"  ○ First scan - baseline established")
            elif previous_hash and not current_hash:
                # Current scan failed to get content
                print(f"  ⚠ Current scan failed to retrieve content")
            
            # 2. Page title comparison
            current_title = scan_result.get('page_title', '')
            if previous_title and current_title:
                if not self.titles_similar(previous_title, current_title):
                    changes_detected = True
                    change_details.append(f'Title changed: "{previous_title}" → "{current_title}"')
                    print(f"  ✓ Significant title change detected")
                elif previous_title != current_title:
                    print(f"  ○ Minor title change ignored")
            
            # 3. Registrar change (always significant)
            current_registrar = scan_result.get('registrar', '')
            if previous_registrar and current_registrar:
                if (previous_registrar != current_registrar and 
                    current_registrar not in ['Unknown', 'Whois lookup failed'] and
                    previous_registrar not in ['Unknown', 'Whois lookup failed']):
                    changes_detected = True
                    change_details.append(f'Registrar changed: {previous_registrar} → {current_registrar}')
                    print(f"  ✓ Registrar change detected")
            
            # Store change detection results
            scan_result['changes_detected'] = changes_detected
            if change_details:
                scan_result['additional_checks']['change_details'] = '; '.join(change_details)
                scan_result['additional_checks']['change_count'] = len(change_details)
            
            print(f"Final change detection result: {'CHANGES DETECTED' if changes_detected else 'NO SIGNIFICANT CHANGES'}")
            if change_details:
                print(f"Change details: {'; '.join(change_details)}")
            
            # Calculate risk score
            risk_score = self.calculate_risk_score(scan_result)
            scan_result['risk_score'] = risk_score
            
            # Save results to database
            cursor.execute('''
                INSERT INTO scan_results 
                (website_id, registrar, page_title, status_code, ssl_valid, 
                ssl_issuer, ssl_expiry, source_code_hash, changes_detected, 
                risk_score, additional_checks)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_result['website_id'], scan_result['registrar'], 
                scan_result['page_title'], scan_result['status_code'],
                scan_result['ssl_valid'], scan_result['ssl_issuer'],
                scan_result['ssl_expiry'], scan_result['source_code_hash'],
                scan_result['changes_detected'], scan_result['risk_score'],
                json.dumps(scan_result.get('additional_checks', {}))
            ))
            
            # Update website last_checked timestamp
            cursor.execute('''
                UPDATE websites SET last_checked = CURRENT_TIMESTAMP, status = ?
                WHERE id = ?
            ''', ('scanned', website_id))
            
            conn.commit()
            conn.close()
            
            # Send notifications based on change type and risk
            if changes_detected:
                self.send_change_notification(url, scan_result, change_details)
            
            print(f"Scan completed for {url}. Risk score: {risk_score}, Changes: {changes_detected}")
            return scan_result
            
        except Exception as e:
            print(f"Error scanning {url}: {str(e)}")
            # Save error result
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scan_results 
                    (website_id, additional_checks)
                    VALUES (?, ?)
                ''', (website_id, json.dumps({'scan_error': str(e)})))
                conn.commit()
                conn.close()
            except:
                pass
            return None

    def scan_website_with_retries(self, website_id, url):
        """Perform website scan with configurable retry logic"""
        import time
        
        max_retries = int(self.settings.get('scan_retries', 5))
        retry_delay = int(self.settings.get('retry_delay_seconds', 3))
        
        print(f"Starting scan for {url} (max retries: {max_retries}, delay: {retry_delay}s)")
        
        last_error = None
        
        for attempt in range(max_retries + 1):  # +1 because we want initial attempt + retries
            try:
                if attempt > 0:
                    print(f"  Retry attempt {attempt}/{max_retries} for {url}")
                    time.sleep(retry_delay)
                else:
                    print(f"  Initial scan attempt for {url}")
                
                # Call the original scan method
                result = self.scan_website(website_id, url)
                
                if result is not None:
                    # Check if scan was successful (no major errors)
                    additional_checks = result.get('additional_checks', {})
                    
                    # Define what constitutes a "retry-worthy" error
                    retry_worthy_errors = ['scan_error', 'http_error', 'ssl_error']
                    has_retry_worthy_error = any(error in additional_checks for error in retry_worthy_errors)
                    
                    # If no retry-worthy errors, consider it successful
                    if not has_retry_worthy_error:
                        if attempt > 0:
                            print(f"  ✓ Scan succeeded on retry attempt {attempt} for {url}")
                        else:
                            print(f"  ✓ Scan succeeded on first attempt for {url}")
                        return result
                    else:
                        # Log the error but continue to retry
                        error_details = [f"{k}: {v}" for k, v in additional_checks.items() if k in retry_worthy_errors]
                        print(f"  ⚠ Scan completed with errors on attempt {attempt + 1}: {'; '.join(error_details)}")
                        last_error = f"Scan errors: {'; '.join(error_details)}"
                        
                        # If this was our last attempt, we'll save this result anyway
                        if attempt == max_retries:
                            print(f"  ✗ Max retries reached for {url}, saving last result with errors")
                            return result
                else:
                    # Scan returned None (complete failure)
                    last_error = "Scan returned None - complete failure"
                    print(f"  ✗ Complete scan failure on attempt {attempt + 1} for {url}")
                    
            except Exception as e:
                last_error = str(e)
                print(f"  ✗ Exception on attempt {attempt + 1} for {url}: {last_error}")
                
                # If this was our last attempt, save the error
                if attempt == max_retries:
                    print(f"  ✗ Max retries reached for {url}, saving error result")
                    try:
                        conn = sqlite3.connect(self.db_path)
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO scan_results 
                            (website_id, additional_checks)
                            VALUES (?, ?)
                        ''', (website_id, json.dumps({
                            'scan_error': f'Failed after {max_retries} retries: {last_error}',
                            'retry_attempts': max_retries,
                            'final_error': last_error
                        })))
                        conn.commit()
                        conn.close()
                    except Exception as db_error:
                        print(f"  ✗ Failed to save error result: {db_error}")
                    return None
        
        # This should never be reached, but just in case
        print(f"  ✗ Unexpected end of retry loop for {url}")
        return None

    def send_change_notification(self, url, scan_result, change_details):
        """Send notification about detected changes (only for moderate/major changes)"""
        if not self.settings.get('notification_emails'):
            return
        
        # Only send notifications for moderate or major content changes, or other significant changes
        content_change_type = scan_result.get('additional_checks', {}).get('content_change_type')
        high_risk = scan_result.get('risk_score', 0) >= 70
        
        # Check if we should send notification
        should_notify = False
        if high_risk:
            should_notify = True
        elif content_change_type in ['moderate', 'major']:
            should_notify = True
        elif any('Title changed' in detail or 'Registrar changed' in detail for detail in change_details):
            should_notify = True
        
        if not should_notify:
            print(f"  ○ Informational changes only - no notification sent")
            return
        
        try:
            # Categorize urgency
            if content_change_type == 'major' or high_risk:
                urgency = "HIGH PRIORITY"
                emoji = "🚨"
            elif content_change_type == 'moderate':
                urgency = "MEDIUM PRIORITY"
                emoji = "⚠️"
            else:
                urgency = "INFORMATIONAL"
                emoji = "ℹ️"
            
            subject = f"{emoji} Website Change Alert [{urgency}]: {url}"
            
            body = f"""
    Website Change Detection Alert

    URL: {url}
    Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Risk Score: {scan_result.get('risk_score', 0)}/100
    Priority: {urgency}

    CHANGES DETECTED:
    {chr(10).join('• ' + detail for detail in change_details)}

    Current Status:
    • HTTP Status: {scan_result.get('status_code', 'Unknown')}
    • SSL Valid: {'Yes' if scan_result.get('ssl_valid') else 'No'}
    • Page Title: {scan_result.get('page_title', 'Unknown')}
    • Registrar: {scan_result.get('registrar', 'Unknown')}

    {f"Content Change Type: {content_change_type.upper()}" if content_change_type else ""}

    Please review this website for potential security issues.

    ---
    Website Verification Tool
            """.strip()
            
            self.send_notification_email(subject, body)
            print(f"  📧 {urgency} notification email sent for {url}")
            
        except Exception as e:
            print(f"  Failed to send change notification: {e}")

    def normalize_content_for_hashing(self, content):
        """Improved content normalization for better change detection"""
        import re
        
        # Convert to lowercase for consistency
        content = content.lower()
        
        # Remove elements that change frequently but aren't meaningful
        patterns_to_remove = [
            # Comments and scripts (most dynamic)
            r'<!--.*?-->',
            r'<script[^>]*>.*?</script>',
            r'<style[^>]*>.*?</style>',
            r'<noscript[^>]*>.*?</noscript>',
            
            # Time-based content
            r'timestamp["\'][^"\']*["\']',
            r'data-timestamp["\'][^"\']*["\']',
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[Z\d\-\+:]*',  # ISO timestamps
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # Standard timestamps
            r'last[_\-]?modified["\'][^"\']*["\']',
            r'generated[_\-]?at["\'][^"\']*["\']',
            
            # Security tokens (change on every request)
            r'csrf[_\-]?token["\'][^"\']*["\']',
            r'_token["\'][^"\']*["\']',
            r'nonce["\'][^"\']*["\']',
            r'session[_\-]?id["\'][^"\']*["\']',
            
            # Analytics and tracking
            r'gtag\([^)]*\)',
            r'ga\([^)]*\)',
            r'fbq\([^)]*\)',
            r'dataLayer\.push\([^)]*\)',
            
            # Cache busters and version parameters
            r'\?v=[\d\.]+',
            r'\?ver=[\d\.]+',
            r'\?_=\d+',
            r'&t=\d+',
            r'&cache=\d+',
            
            # Random IDs and UUIDs
            r'id=["\'][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}["\']',
            r'data-id=["\'][a-f0-9]+["\']',
            
            # External tracking URLs
            r'https?://[^"\'\s]*google-analytics\.com[^"\'\s]*',
            r'https?://[^"\'\s]*googletagmanager\.com[^"\'\s]*',
            r'https?://[^"\'\s]*facebook\.net[^"\'\s]*',
            r'https?://[^"\'\s]*doubleclick\.net[^"\'\s]*',
        ]
        
        # Apply all removal patterns
        for pattern in patterns_to_remove:
            content = re.sub(pattern, '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # Normalize whitespace while preserving structure
        content = re.sub(r'\s+', ' ', content)  # Multiple spaces to single space
        content = re.sub(r'>\s+<', '><', content)  # Remove spaces between tags
        content = re.sub(r'\s*=\s*', '=', content)  # Normalize attribute spacing
        
        # Remove empty attributes
        content = re.sub(r'\s+(class|id|style)=["\']["\']', '', content)
        
        # Focus on body content if available (head section is very dynamic)
        body_match = re.search(r'<body[^>]*>(.*)</body>', content, re.DOTALL | re.IGNORECASE)
        if body_match:
            content = body_match.group(1)
        
        # Remove leading/trailing whitespace
        content = content.strip()
        
        return content    
    
    def titles_similar(self, title1, title2):
        """Check if two titles are similar enough to not be considered a change"""
        import re
        
        # Normalize titles for comparison
        def normalize_title(title):
            # Remove extra whitespace and common variations
            title = re.sub(r'\s+', ' ', title.strip())
            title = re.sub(r'[^\w\s]', '', title.lower())  # Remove punctuation
            return title
        
        norm_title1 = normalize_title(title1)
        norm_title2 = normalize_title(title2)
        
        # If normalized titles are the same, consider them similar
        if norm_title1 == norm_title2:
            return True
        
        # Check if one title contains the other (common with site name variations)
        if norm_title1 in norm_title2 or norm_title2 in norm_title1:
            return True
        
        # Calculate simple similarity (number of common words)
        words1 = set(norm_title1.split())
        words2 = set(norm_title2.split())
        
        if not words1 or not words2:
            return False
        
        common_words = words1.intersection(words2)
        similarity = len(common_words) / min(len(words1), len(words2))
        
        # If 80% of words are common, consider similar
        return similarity >= 0.8
    
    def perform_website_checks(self, url):
        """Perform all website verification checks with improved SSL handling"""
        result = {
            'registrar': 'Unknown',
            'page_title': 'Unknown',
            'status_code': 0,
            'ssl_valid': False,
            'ssl_issuer': 'None',
            'ssl_expiry': 'Unknown',
            'source_code_hash': '',
            'additional_checks': {}
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            print(f"Starting checks for {url} (domain: {domain})")
            
            # 1. Registrar check using whois
            try:
                print("Checking whois...")
                w = get_whois_info(domain)
                registrar = getattr(w, 'registrar', None)
                if isinstance(registrar, list):
                    registrar = registrar[0]
                result['registrar'] = str(registrar) if registrar else 'Unknown'
                print(f"  Registrar: {result['registrar']}")
            except Exception as whois_error:
                result['registrar'] = 'Whois lookup failed'
                print(f"  Whois error: {whois_error}")
            
            # 2. SSL Certificate check (for HTTPS URLs)
            if parsed_url.scheme == 'https' or not parsed_url.scheme:
                print("Performing SSL check...")
                ssl_result = self.perform_ssl_check(domain)
                
                result['ssl_valid'] = ssl_result['ssl_valid']
                result['ssl_issuer'] = ssl_result['ssl_issuer']
                result['ssl_expiry'] = ssl_result['ssl_expiry']
                
                if ssl_result['ssl_error']:
                    result['additional_checks']['ssl_error'] = ssl_result['ssl_error']
                if ssl_result['ssl_version']:
                    result['additional_checks']['ssl_version'] = ssl_result['ssl_version']
                if ssl_result['ssl_cipher']:
                    result['additional_checks']['ssl_cipher'] = ssl_result['ssl_cipher']
            
            # 3. HTTP request for page title and status
            try:
                print("Making HTTP request...")
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                # Try HTTPS first, fall back to HTTP if needed
                test_url = url
                if not url.startswith(('http://', 'https://')):
                    test_url = 'https://' + url
                
                response = requests.get(test_url, timeout=15, verify=False, headers=headers, allow_redirects=True)
                result['status_code'] = response.status_code
                print(f"  HTTP Status: {response.status_code}")
                
                # Extract title and hash content
                if 'text/html' in response.headers.get('content-type', '').lower():
                    content = response.text
                    
                    # Extract title more robustly
                    import re
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        result['page_title'] = title_match.group(1).strip()[:200]  # Limit length
                        print(f"  Title: {result['page_title']}")
                    
                    # Create normalized content for change detection
                    normalized_content = self.normalize_content_for_hashing(content)
                    result['source_code_hash'] = hashlib.md5(normalized_content.encode('utf-8', errors='ignore')).hexdigest()
                    
                    # Store content length for additional validation
                    result['additional_checks']['content_length'] = len(content)
                    result['additional_checks']['normalized_length'] = len(normalized_content)
                else:
                    # For non-HTML content, hash the raw response
                    result['source_code_hash'] = hashlib.md5(response.content).hexdigest()
                    
            except requests.exceptions.SSLError as ssl_error:
                print(f"  HTTP SSL Error: {ssl_error}")
                result['additional_checks']['http_ssl_error'] = str(ssl_error)
                # Try HTTP version if HTTPS fails
                try:
                    http_url = url.replace('https://', 'http://')
                    response = requests.get(http_url, timeout=15, headers=headers, allow_redirects=True)
                    result['status_code'] = response.status_code
                    result['additional_checks']['https_fallback'] = 'Used HTTP due to SSL error'
                except Exception as http_error:
                    result['additional_checks']['http_error'] = str(http_error)
                    
            except Exception as http_error:
                result['additional_checks']['http_error'] = str(http_error)
                print(f"  HTTP error: {http_error}")
            
            # 4. Additional security checks
            result['additional_checks'].update(self.additional_security_checks(url, domain))
            
        except Exception as e:
            result['additional_checks']['scan_error'] = str(e)
            print(f"General scan error for {url}: {str(e)}")
        
        return result
    
    def perform_ssl_check(self, domain, port=443):
        """Enhanced SSL certificate check with better error handling"""
        ssl_result = {
            'ssl_valid': False,
            'ssl_issuer': 'None',
            'ssl_expiry': 'Unknown',
            'ssl_error': None,
            'ssl_version': None,
            'ssl_cipher': None
        }
        
        try:
            print(f"Checking SSL for {domain}:{port}")
            
            # Create SSL context with more permissive settings
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Set timeout for socket operations
            socket.setdefaulttimeout(15)
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            
            try:
                # Connect to the server
                print(f"  Connecting to {domain}:{port}...")
                sock.connect((domain, port))
                
                # Wrap socket with SSL
                print(f"  Wrapping socket with SSL...")
                ssl_sock = context.wrap_socket(sock, server_hostname=domain)
                
                # Get certificate information
                cert = ssl_sock.getpeercert()
                cipher = ssl_sock.cipher()
                version = ssl_sock.version()
                
                print(f"  SSL connection successful!")
                print(f"  Protocol: {version}")
                print(f"  Cipher: {cipher}")
                
                # Parse certificate
                ssl_result['ssl_valid'] = True
                ssl_result['ssl_version'] = version
                ssl_result['ssl_cipher'] = str(cipher) if cipher else 'Unknown'
                
                # Extract issuer information more robustly
                if cert and 'issuer' in cert:
                    issuer_parts = cert['issuer']
                    issuer_name = 'Unknown'
                    
                    # Look for organization name in issuer
                    for part in issuer_parts:
                        for key, value in part:
                            if key in ['organizationName', 'O']:
                                issuer_name = value
                                break
                        if issuer_name != 'Unknown':
                            break
                    
                    # If no org name found, try common name
                    if issuer_name == 'Unknown':
                        for part in issuer_parts:
                            for key, value in part:
                                if key in ['commonName', 'CN']:
                                    issuer_name = value
                                    break
                            if issuer_name != 'Unknown':
                                break
                    
                    ssl_result['ssl_issuer'] = issuer_name
                    print(f"  Issuer: {issuer_name}")
                
                # Extract expiry date
                if cert and 'notAfter' in cert:
                    ssl_result['ssl_expiry'] = cert['notAfter']
                    print(f"  Expires: {cert['notAfter']}")
                    
                    # Check if certificate is expired or expiring soon
                    try:
                        from datetime import datetime
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        if days_until_expiry < 0:
                            ssl_result['ssl_error'] = 'Certificate expired'
                            ssl_result['ssl_valid'] = False
                        elif days_until_expiry < 30:
                            ssl_result['ssl_error'] = f'Certificate expires in {days_until_expiry} days'
                            
                    except Exception as date_error:
                        print(f"  Warning: Could not parse expiry date: {date_error}")
                
                # Extract subject information for additional validation
                if cert and 'subject' in cert:
                    subject_parts = cert['subject']
                    for part in subject_parts:
                        for key, value in part:
                            if key in ['commonName', 'CN']:
                                print(f"  Subject CN: {value}")
                                # Verify domain matches certificate
                                if not self.domain_matches_cert(domain, value):
                                    ssl_result['ssl_error'] = f'Domain mismatch: {domain} vs {value}'
                                break
                
            except ssl.SSLError as ssl_error:
                error_msg = str(ssl_error)
                print(f"  SSL Error: {error_msg}")
                ssl_result['ssl_error'] = f'SSL Error: {error_msg}'
                
                # Specific SSL error handling
                if 'certificate verify failed' in error_msg.lower():
                    ssl_result['ssl_error'] = 'Certificate verification failed'
                elif 'wrong version number' in error_msg.lower():
                    ssl_result['ssl_error'] = 'SSL/TLS version mismatch'
                elif 'handshake failure' in error_msg.lower():
                    ssl_result['ssl_error'] = 'SSL handshake failed'
                    
            except socket.timeout:
                print(f"  Timeout connecting to {domain}:{port}")
                ssl_result['ssl_error'] = 'Connection timeout'
                
            except socket.gaierror as dns_error:
                print(f"  DNS resolution failed: {dns_error}")
                ssl_result['ssl_error'] = f'DNS resolution failed: {dns_error}'
                
            except ConnectionRefusedError:
                print(f"  Connection refused to {domain}:{port}")
                ssl_result['ssl_error'] = 'Connection refused'
                
            except Exception as conn_error:
                print(f"  Connection error: {conn_error}")
                ssl_result['ssl_error'] = f'Connection error: {conn_error}'
                
            finally:
                # Always close the socket
                try:
                    sock.close()
                except:
                    pass
                    
        except Exception as general_error:
            print(f"  General SSL check error: {general_error}")
            ssl_result['ssl_error'] = f'General error: {general_error}'
        
        finally:
            # Reset default timeout
            socket.setdefaulttimeout(None)
        
        print(f"  SSL check result: Valid={ssl_result['ssl_valid']}, Error={ssl_result['ssl_error']}")
        return ssl_result

    def domain_matches_cert(self, domain, cert_domain):
        """Check if domain matches certificate domain (including wildcards)"""
        # Remove www. prefix for comparison
        domain = domain.lower().replace('www.', '')
        cert_domain = cert_domain.lower().replace('www.', '')
        
        # Exact match
        if domain == cert_domain:
            return True
        
        # Wildcard match (*.example.com)
        if cert_domain.startswith('*.'):
            cert_base = cert_domain[2:]  # Remove *.
            if domain.endswith(cert_base):
                # Make sure it's a subdomain, not just a suffix
                if domain == cert_base or domain.endswith('.' + cert_base):
                    return True
        
        return False

    
    def debug_content_changes(self, url, old_hash, new_hash, old_content, new_content):
        """Debug function to help understand what's changing in content"""
        if old_hash == new_hash:
            print(f"DEBUG: No content changes for {url}")
            return
        
        print(f"DEBUG: Content change detected for {url}")
        print(f"  Old hash: {old_hash}")
        print(f"  New hash: {new_hash}")
        print(f"  Old content length: {len(old_content) if old_content else 'N/A'}")
        print(f"  New content length: {len(new_content) if new_content else 'N/A'}")
        
        # Sample comparison of first 200 characters
        if old_content and new_content:
            old_sample = old_content[:200].replace('\n', '\\n').replace('\r', '\\r')
            new_sample = new_content[:200].replace('\n', '\\n').replace('\r', '\\r')
            print(f"  Old content start: {old_sample}")
            print(f"  New content start: {new_sample}")
        
        print("  " + "="*50)
    
    def additional_security_checks(self, url, domain):
        """Additional security and legitimacy checks"""
        checks = {}
        
        try:
            # Check for suspicious patterns in domain
            suspicious_patterns = ['paypal', 'amazon', 'microsoft', 'google', 'apple']
            domain_lower = domain.lower()
            
            for pattern in suspicious_patterns:
                if pattern in domain_lower and not domain_lower.endswith(f'{pattern}.com'):
                    checks['suspicious_domain'] = f"Contains '{pattern}' but not official domain"
            
            # Check domain age (simplified)
            try:
                w = get_whois_info(domain)
                creation_date = getattr(w, 'creation_date', None)
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    checks['domain_age_days'] = age_days
                    if age_days < 30:
                        checks['new_domain_warning'] = "Domain is less than 30 days old"
            except Exception:
                pass
            
            # Check for HTTPS redirect
            if not url.startswith('https://'):
                try:
                    http_response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
                    if http_response.status_code in [301, 302] and 'https' in http_response.headers.get('Location', ''):
                        checks['https_redirect'] = True
                    else:
                        checks['https_redirect'] = False
                except:
                    checks['https_redirect'] = 'unknown'
            
        except Exception as e:
            checks['additional_checks_error'] = str(e)
        
        return checks
    
    def calculate_risk_score(self, scan_result):
        """Calculate risk score based on scan results"""
        score = 0
        
        # SSL issues
        if not scan_result['ssl_valid']:
            score += 30
        
        # HTTP status issues
        if scan_result['status_code'] >= 400:
            score += 20
        
        # Registrar issues
        if scan_result['registrar'] in ['Unknown', 'Whois lookup failed']:
            score += 15
        
        # Additional checks
        additional = scan_result.get('additional_checks', {})
        
        if 'suspicious_domain' in additional:
            score += 40
        
        if 'new_domain_warning' in additional:
            score += 25
        
        if additional.get('https_redirect') == False:
            score += 10
        
        # Changes detected
        if scan_result.get('changes_detected'):
            score += 20
        
        return min(score, 100)  # Cap at 100
    
    def scan_all_websites(self):
        """Scan all websites in separate thread with retry logic"""
        def scan_thread():
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, url FROM websites")
            websites = cursor.fetchall()
            conn.close()
            
            total_websites = len(websites)
            for i, (website_id, url) in enumerate(websites, 1):
                print(f"\n--- Scanning {i}/{total_websites}: {url} ---")
                result = self.scan_website_with_retries(website_id, url)  # Use retry method
                # Update UI in main thread after each scan
                self.root.after(0, self.load_websites)
                self.root.after(0, self.load_scan_results)
            
            self.root.after(0, lambda: messagebox.showinfo("Complete", f"All {total_websites} websites scanned with retry logic"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
        messagebox.showinfo("Scanning", f"Scanning all websites with up to {self.settings.get('scan_retries', 5)} retries each...")

        
    def scan_selected(self):
        """Scan selected websites with retry logic"""
        selection = self.websites_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select websites to scan")
            return
        
        def scan_thread():
            total_selected = len(selection)
            for i, item in enumerate(selection, 1):
                values = self.websites_tree.item(item)['values']
                website_id, url = values[0], values[2]
                print(f"\n--- Scanning {i}/{total_selected}: {url} ---")
                self.scan_website_with_retries(website_id, url)  # Use retry method
                # Update UI after each scan
                self.root.after(0, self.load_websites)
                self.root.after(0, self.load_scan_results)
            
            self.root.after(0, lambda: messagebox.showinfo("Complete", f"Selected {total_selected} websites scanned with retry logic"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
        messagebox.showinfo("Scanning", f"Scanning selected websites with up to {self.settings.get('scan_retries', 5)} retries each...")    
        
    def delete_selected(self):
        """Delete selected websites"""
        selection = self.websites_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select websites to delete")
            return
        
        if messagebox.askyesno("Confirm", "Delete selected websites and all their scan results?"):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for item in selection:
                website_id = self.websites_tree.item(item)['values'][0]
                cursor.execute("DELETE FROM scan_results WHERE website_id = ?", (website_id,))
                cursor.execute("DELETE FROM websites WHERE id = ?", (website_id,))
            
            conn.commit()
            conn.close()
            self.load_websites()
    
    def import_websites(self):
        """Import websites from file"""
        filename = filedialog.askopenfilename(
            title="Select file with websites",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    lines = f.readlines()
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                added = 0
                for line in lines:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        if not url.startswith(('http://', 'https://')):
                            url = 'https://' + url
                        
                        try:
                            cursor.execute("INSERT INTO websites (url, name) VALUES (?, ?)", (url, url))
                            added += 1
                        except sqlite3.IntegrityError:
                            pass  # Skip duplicates
                
                conn.commit()
                conn.close()
                self.load_websites()
                messagebox.showinfo("Success", f"Added {added} websites")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import: {str(e)}")
    
    def load_scan_results(self):
        """Load scan results into treeview"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT sr.scan_date, w.name, sr.status_code, sr.ssl_valid,
                   sr.registrar, sr.changes_detected, sr.risk_score
            FROM scan_results sr
            JOIN websites w ON sr.website_id = w.id
            ORDER BY sr.scan_date DESC
            LIMIT 1000
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        for result in results:
            # Format the data
            formatted_result = (
                result[0][:16] if result[0] else '',  # Date
                result[1],  # Website name
                result[2],  # Status code
                'Yes' if result[3] else 'No',  # SSL valid
                result[4],  # Registrar
                'Yes' if result[5] else 'No',  # Changes detected
                result[6]  # Risk score
            )
            self.results_tree.insert('', tk.END, values=formatted_result)
    
    def apply_results_filter(self):
        """Apply filters to scan results"""
        self.load_scan_results()  # For now, just reload all
    
    def view_website_details(self, event=None):
        """View detailed information for selected website"""
        selection = self.websites_tree.selection()
        if not selection:
            return
        
        website_id = self.websites_tree.item(selection[0])['values'][0]
        self.show_website_details_window(website_id)
    
    def show_website_details_window(self, website_id):
        """Show detailed window for website"""
        details_window = tk.Toplevel(self.root)
        details_window.title("Website Details")
        details_window.geometry("800x600")
        details_window.transient(self.root)
        
        # Get website and scan data
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM websites WHERE id = ?", (website_id,))
        website = cursor.fetchone()
        
        cursor.execute('''
            SELECT * FROM scan_results WHERE website_id = ? 
            ORDER BY scan_date DESC LIMIT 10
        ''', (website_id,))
        scans = cursor.fetchall()
        conn.close()
        
        if not website:
            return
        
        # Website info
        info_frame = ttk.LabelFrame(details_window, text="Website Information", padding=10)
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(info_frame, text=f"Name: {website[2]}").pack(anchor='w')
        ttk.Label(info_frame, text=f"URL: {website[1]}").pack(anchor='w')
        ttk.Label(info_frame, text=f"Added: {website[3]}").pack(anchor='w')
        ttk.Label(info_frame, text=f"Last Checked: {website[4] or 'Never'}").pack(anchor='w')
        
        # Recent scans
        scans_frame = ttk.LabelFrame(details_window, text="Recent Scans", padding=10)
        scans_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scan_text = scrolledtext.ScrolledText(scans_frame, height=20)
        scan_text.pack(fill=tk.BOTH, expand=True)
        
        # Database column order: id, website_id, scan_date, registrar, page_title, status_code, 
        # ssl_valid, ssl_issuer, ssl_expiry, source_code_hash, changes_detected, risk_score, additional_checks
        for scan in scans:
            scan_info = f"""
Scan Date: {scan[2]}
Status Code: {scan[5]}
Page Title: {scan[4]}
SSL Valid: {'Yes' if scan[6] else 'No'}
SSL Issuer: {scan[7]}
SSL Expiry: {scan[8]}
Registrar: {scan[3]}
Changes Detected: {'Yes' if scan[10] else 'No'}
Risk Score: {scan[11]}
Source Code Hash: {scan[9][:16]}...
Additional Checks: {scan[12]}
{'='*50}
"""
            scan_text.insert(tk.END, scan_info)
        
        scan_text.config(state='disabled')
    
    def save_settings(self):
        """Save all settings to database"""
        settings_to_save = {
            'email_smtp_server': self.smtp_server_entry.get(),
            'email_smtp_port': self.smtp_port_entry.get(),
            'email_username': self.email_username_entry.get(),
            'email_password': self.email_password_entry.get(),
            'notification_emails': self.notification_emails_entry.get(),
            'scan_frequency_days': self.scan_frequency_entry.get(),
            'github_repo': self.github_repo_entry.get(),
            'scan_retries': self.scan_retries_entry.get(),  # NEW
            'retry_delay_seconds': self.retry_delay_entry.get()  # NEW
        }
        
        # Validate retry settings
        try:
            retries = int(settings_to_save['scan_retries'])
            delay = int(settings_to_save['retry_delay_seconds'])
            
            if retries < 0 or retries > 20:
                messagebox.showerror("Error", "Scan retries must be between 0 and 20")
                return
            
            if delay < 1 or delay > 60:
                messagebox.showerror("Error", "Retry delay must be between 1 and 60 seconds")
                return
                
        except ValueError:
            messagebox.showerror("Error", "Retry settings must be valid numbers")
            return
        
        for key, value in settings_to_save.items():
            self.save_setting(key, value)
        
        messagebox.showinfo("Success", "Settings saved successfully")
    
    def send_notification_email(self, subject, body):
        """Send notification email"""
        try:
            if not self.settings.get('notification_emails'):
                return
            
            msg = MIMEMultipart()
            msg['From'] = self.settings['email_username']
            msg['To'] = self.settings['notification_emails']
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.settings['email_smtp_server'], 
                                 int(self.settings['email_smtp_port']))
            server.starttls()
            server.login(self.settings['email_username'], 
                        self.settings['email_password'])
            
            text = msg.as_string()
            server.sendmail(self.settings['email_username'], 
                           self.settings['notification_emails'], text)
            server.quit()
            
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
    
    def sync_to_github(self):
        """Sync database to GitHub repository"""
        if not self.settings.get('github_repo'):
            messagebox.showerror("Error", "Please configure GitHub repository")
            return
        
        try:
            # Simple git commands (requires git to be installed)
            repo_path = self.settings['github_repo'].split('/')[-1].replace('.git', '')
            
            if not os.path.exists(repo_path):
                subprocess.run(['git', 'clone', self.settings['github_repo']], check=True)
            
            # Copy database to repo
            import shutil
            shutil.copy(self.db_path, os.path.join(repo_path, self.db_path))
            
            # Git commands
            subprocess.run(['git', 'add', '.'], cwd=repo_path, check=True)
            subprocess.run(['git', 'commit', '-m', f'Database update {datetime.now()}'], 
                          cwd=repo_path, check=True)
            subprocess.run(['git', 'push'], cwd=repo_path, check=True)
            
            messagebox.showinfo("Success", "Database synced to GitHub")
            
        except Exception as e:
            messagebox.showerror("Error", f"GitHub sync failed: {str(e)}")
    
    def pull_from_github(self):
        """Pull database from GitHub repository"""
        if not self.settings.get('github_repo'):
            messagebox.showerror("Error", "Please configure GitHub repository")
            return
        
        try:
            repo_path = self.settings['github_repo'].split('/')[-1].replace('.git', '')
            
            if os.path.exists(repo_path):
                subprocess.run(['git', 'pull'], cwd=repo_path, check=True)
                
                # Copy database from repo
                import shutil
                repo_db_path = os.path.join(repo_path, self.db_path)
                if os.path.exists(repo_db_path):
                    shutil.copy(repo_db_path, self.db_path)
                    self.load_websites()
                    self.load_scan_results()
                    messagebox.showinfo("Success", "Database updated from GitHub")
                else:
                    messagebox.showwarning("Warning", "No database found in repository")
            else:
                messagebox.showerror("Error", "Repository not cloned locally")
                
        except Exception as e:
            messagebox.showerror("Error", f"GitHub pull failed: {str(e)}")
    
    def generate_risk_report(self):
        """Generate risk assessment report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT w.name, w.url, sr.risk_score, sr.scan_date,
                   sr.ssl_valid, sr.changes_detected, sr.additional_checks
            FROM websites w
            LEFT JOIN scan_results sr ON w.id = sr.website_id
            WHERE sr.scan_date = (
                SELECT MAX(scan_date) FROM scan_results sr2 WHERE sr2.website_id = w.id
            )
            ORDER BY sr.risk_score DESC
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        report = f"WEBSITE RISK ASSESSMENT REPORT\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += "="*60 + "\n\n"
        
        high_risk = [r for r in results if r[2] and r[2] >= 50]
        medium_risk = [r for r in results if r[2] and 20 <= r[2] < 50]
        low_risk = [r for r in results if r[2] and r[2] < 20]
        
        report += f"SUMMARY:\n"
        report += f"High Risk Sites (50+): {len(high_risk)}\n"
        report += f"Medium Risk Sites (20-49): {len(medium_risk)}\n"
        report += f"Low Risk Sites (0-19): {len(low_risk)}\n\n"
        
        if high_risk:
            report += "HIGH RISK WEBSITES:\n" + "-"*30 + "\n"
            for site in high_risk:
                report += f"• {site[0]} ({site[1]})\n"
                report += f"  Risk Score: {site[2]}\n"
                report += f"  Last Scan: {site[3]}\n"
                report += f"  SSL Valid: {'Yes' if site[4] else 'No'}\n"
                report += f"  Changes Detected: {'Yes' if site[5] else 'No'}\n\n"
        
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(1.0, report)
    
    def generate_changes_report(self):
        """Generate changes detection report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT w.name, w.url, sr.scan_date, sr.changes_detected, sr.risk_score
            FROM websites w
            JOIN scan_results sr ON w.id = sr.website_id
            WHERE sr.changes_detected = 1
            ORDER BY sr.scan_date DESC
            LIMIT 50
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        report = f"WEBSITE CHANGES DETECTION REPORT\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += "="*60 + "\n\n"
        
        if results:
            report += f"RECENT CHANGES DETECTED ({len(results)} total):\n\n"
            for site in results:
                report += f"• {site[0]} ({site[1]})\n"
                report += f"  Change Detected: {site[2]}\n"
                report += f"  Current Risk Score: {site[4]}\n\n"
        else:
            report += "No changes detected in recent scans.\n"
        
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(1.0, report)
    
    def generate_weekly_summary(self):
        """Generate weekly summary report"""
        week_ago = datetime.now() - timedelta(days=7)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM scan_results 
            WHERE scan_date >= ?
        ''', (week_ago.isoformat(),))
        scans_this_week = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM scan_results 
            WHERE scan_date >= ? AND changes_detected = 1
        ''', (week_ago.isoformat(),))
        changes_this_week = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM scan_results 
            WHERE scan_date >= ? AND risk_score >= 50
        ''', (week_ago.isoformat(),))
        high_risk_this_week = cursor.fetchone()[0]
        
        conn.close()
        
        report = f"WEEKLY SUMMARY REPORT\n"
        report += f"Period: {week_ago.strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}\n"
        report += "="*60 + "\n\n"
        report += f"Total Scans Performed: {scans_this_week}\n"
        report += f"Changes Detected: {changes_this_week}\n"
        report += f"High Risk Detections: {high_risk_this_week}\n\n"
        
        if changes_this_week > 0 or high_risk_this_week > 0:
            report += "⚠️  ACTION REQUIRED: Review high-risk sites and investigate changes\n"
        else:
            report += "✅ No critical issues detected this week\n"
        
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(1.0, report)
        
        # Send email notification if enabled
        if self.settings.get('notification_emails'):
            self.send_notification_email("Weekly Website Security Summary", report)

def install_requirements():
    """Install required packages"""
    required_packages = ['requests', 'python-whois']

    for package in required_packages:
        try:
            if package == 'python-whois':
                __import__('whois')
            else:
                __import__(package.replace('-', '_'))
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def main():
    try:
        # Check and install requirements
        install_requirements()
        
        root = tk.Tk()
        app = WebsiteVerificationTool(root)
        
        # Center window
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
        y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
        root.geometry(f"+{x}+{y}")
        
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start application: {str(e)}")

if __name__ == "__main__":
    main()