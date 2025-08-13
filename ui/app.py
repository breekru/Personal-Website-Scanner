"""Tkinter application components."""
import tkinter as tk
from urllib.parse import urlparse
import sqlite3

from db import DatabaseManager
from scanner import additional_security_checks
from .theme import ThemeManager
from .widgets import TaggedTreeview


class WebsiteVerificationTool:
    """Main application class extracted from the monolithic script."""

    def __init__(self, root: tk.Misc, db_path: str = "website_verification.db"):
        self.root = root
        self.db_path = db_path
        self.db = DatabaseManager(db_path)
        self.theme_manager = ThemeManager()
        columns = (
            "id",
            "url",
            "name",
            "added",
            "last_checked",
            "status",
            "manual_status",
            "notes",
            "risk",
        )
        self.websites_tree = TaggedTreeview(root, columns=columns, show="headings")
        for col in columns:
            self.websites_tree.heading(col, text=col.title())
        self.websites_tree.pack(fill="both", expand=True)

    # ---- Database passthrough -------------------------------------------------
    def _ensure_db(self):  # pragma: no cover - used when constructed via __new__
        if not hasattr(self, "db"):
            self.db = DatabaseManager(getattr(self, "db_path", "website_verification.db"))

    def toggle_manual_status(self, website_id, status):
        self._ensure_db()
        return self.db.toggle_manual_status(website_id, status)

    def load_websites(self):  # pragma: no cover - simplified for tests
        """Load websites from the database into the tree widget."""
        self._ensure_db()
        for item in getattr(self, 'websites_tree').get_children():
            self.websites_tree.delete(item)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, url, name, added_date, last_checked, status, manual_status FROM websites ORDER BY id"
        )
        rows = cursor.fetchall()
        for row in rows:
            website_id, url, name, added, last_checked, status, manual_status = row
            cursor.execute(
                "SELECT risk_score FROM scan_results WHERE website_id=? ORDER BY scan_date DESC LIMIT 1",
                (website_id,),
            )
            risk_row = cursor.fetchone()
            if manual_status == 'high_risk' and not risk_row:
                risk_display = '100/100'
            elif risk_row:
                risk_display = f"{risk_row[0]}/100"
            else:
                risk_display = '0/100'

            values = (
                website_id,
                url,
                name,
                added,
                last_checked,
                status,
                manual_status,
                '',
                risk_display,
            )
            self.websites_tree.insert('', 'end', iid=str(website_id), text=url, values=values, tags=())
        conn.close()

    # ---- Scanning utilities ---------------------------------------------------
    def additional_security_checks(self, url, domain, rdap_data=None):
        return additional_security_checks(url, domain, rdap_data)

    def perform_mx_check(self, domain):  # pragma: no cover - stub
        return {
            'mx_record_count': 0,
            'mx_records': '',
            'mx_check_status': 'error',
            'mx_error': 'not_implemented',
        }

    def perform_ssl_check(self, domain):  # pragma: no cover - stub
        return {
            'ssl_valid': False,
            'ssl_issuer': '',
            'ssl_expiry': '',
            'ssl_error': 'not_implemented',
            'ssl_version': None,
            'ssl_cipher': None,
        }

    def normalize_content_for_hashing(self, content):  # pragma: no cover - stub
        return content

    def perform_website_checks(self, url):
        """Perform registrar, MX, SSL and additional checks for *url*."""
        result = {
            'registrar': 'Unknown',
            'page_title': 'Unknown',
            'status_code': 0,
            'ssl_valid': False,
            'ssl_issuer': 'None',
            'ssl_expiry': 'Unknown',
            'source_code_hash': '',
            'mx_record_count': 0,
            'mx_records': '',
            'mx_check_status': 'not_checked',
            'additional_checks': {},
        }

        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        variants = [domain]
        if domain.startswith('www.'):
            variants.append(domain[4:])
        else:
            variants.append('www.' + domain)
        variants = list(dict.fromkeys(variants))

        selected_domain = None
        rdap_data = None
        from mainV3 import fetch_rdap, parse_registrar_from_rdap  # late import for patchability
        for candidate in variants:
            rdap_candidate = fetch_rdap(candidate)
            if rdap_candidate:
                registrar = parse_registrar_from_rdap(rdap_candidate)
                result['registrar'] = registrar or 'Unknown'
                rdap_data = rdap_candidate
                selected_domain = candidate
                break
        if rdap_data is None:
            result['registrar'] = 'RDAP lookup failed'

        mx_result = None
        for candidate in ([selected_domain] if selected_domain else []) + [d for d in variants if d != selected_domain]:
            mx_candidate = self.perform_mx_check(candidate)
            mx_result = mx_candidate
            if mx_candidate['mx_check_status'] != 'error':
                selected_domain = candidate
                break
        if mx_result:
            result['mx_record_count'] = mx_result['mx_record_count']
            result['mx_records'] = mx_result['mx_records']
            result['mx_check_status'] = mx_result['mx_check_status']
            if mx_result['mx_error']:
                result['additional_checks']['mx_error'] = mx_result['mx_error']

        if parsed_url.scheme in ('https', ''):
            ssl_result = self.perform_ssl_check(selected_domain or domain)
            result['ssl_valid'] = ssl_result['ssl_valid']
            result['ssl_issuer'] = ssl_result['ssl_issuer']
            result['ssl_expiry'] = ssl_result['ssl_expiry']
            if ssl_result['ssl_error']:
                result['additional_checks']['ssl_error'] = ssl_result['ssl_error']

        result['additional_checks'].update(
            self.additional_security_checks(url, selected_domain or domain, rdap_data)
        )

        return result
