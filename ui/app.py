"""Tkinter application components."""
import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse
import sqlite3

import risk
from db import DatabaseManager
from scanner import additional_security_checks
from .theme import ThemeManager, _HAS_TTKB
from .widgets import TaggedTreeview


class WebsiteVerificationTool:
    """Main application class extracted from the monolithic script."""

    def __init__(
        self,
        root: tk.Misc,
        db_path: str = "website_verification.db",
        theme: str | None = None,
    ):
        self.root = root
        self.db_path = db_path
        self.db = DatabaseManager(db_path)
        self.theme_manager = ThemeManager(theme or "litera")
        self.theme_manager.apply(self.root)

        if _HAS_TTKB:
            themes = self.theme_manager.style.theme_names()
            current_theme = self.theme_manager.style.theme_use()
            self._theme_var = tk.StringVar(value=current_theme)
            selector = ttk.Combobox(
                root,
                values=themes,
                textvariable=self._theme_var,
                state="readonly",
            )
            selector.pack(fill="x")
            selector.bind(
                "<<ComboboxSelected>>",
                lambda _e: self.theme_manager.style.theme_use(self._theme_var.get()),
            )

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
        self.theme_manager.apply(self.websites_tree)

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

    def perform_mx_check(self, domain):
        """Return MX record information for *domain*.

        The return dictionary contains ``mx_record_count``, ``mx_records`` as a
        comma separated string, ``mx_check_status`` which is ``"success"`` or
        ``"error"`` and ``mx_error`` with any error message.  This mirrors the
        fields consumed by :func:`risk.calculate_risk_score`.
        """
        result = {
            "mx_record_count": 0,
            "mx_records": "",
            "mx_check_status": "error",
            "mx_error": "",
        }

        try:
            try:  # Lazy import so tests without dnspython can still run
                import dns.resolver  # type: ignore
            except Exception as exc:  # pragma: no cover - import failure path
                result["mx_error"] = f"dns_import_error: {exc}"
                return result

            answers = dns.resolver.resolve(domain, "MX")
            records = sorted(str(r.exchange).rstrip(".") for r in answers)
            result["mx_record_count"] = len(records)
            result["mx_records"] = ",".join(records)
            result["mx_check_status"] = "success"
        except dns.resolver.NoAnswer:
            # No MX records is still considered a successful lookup
            result["mx_check_status"] = "success"
            result["mx_error"] = "no_answer"
        except dns.resolver.NXDOMAIN:
            result["mx_error"] = "nxdomain"
        except Exception as exc:  # pragma: no cover - defensive
            result["mx_error"] = str(exc)

        return result

    def perform_ssl_check(self, domain):
        """Validate the SSL certificate for *domain*.

        Returns a dictionary with ``ssl_valid`` (bool), ``ssl_issuer`` and
        ``ssl_expiry`` strings plus ``ssl_error`` (``""`` if none).  Additional
        diagnostic information such as ``ssl_version`` and ``ssl_cipher`` is
        included but not used directly by the risk calculation.
        """
        result = {
            "ssl_valid": False,
            "ssl_issuer": "",
            "ssl_expiry": "",
            "ssl_error": "",
            "ssl_version": None,
            "ssl_cipher": None,
        }

        try:
            import socket
            import ssl
            from datetime import datetime

            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                    result["ssl_issuer"] = issuer_parts.get("organizationName", "")
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            result["ssl_expiry"] = expiry.isoformat()
                        except Exception:  # pragma: no cover - parsing failures
                            result["ssl_expiry"] = not_after
                    result["ssl_valid"] = True
                    result["ssl_version"] = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        result["ssl_cipher"] = cipher[0]
        except Exception as exc:  # pragma: no cover - network/SSL errors
            result["ssl_error"] = str(exc)

        return result

    def normalize_content_for_hashing(self, content):
        """Return *content* with volatile portions stripped.

        Removing timestamps and script contents helps provide a stable hash when
        the scanned site injects dynamic values on each request.
        """
        import re

        patterns = [
            r"<script.*?>.*?</script>",  # strip script tags
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?",  # ISO timestamps
            r"Date:[^\n]+",  # HTTP style date headers
            r"[0-9]{10,}",  # long integers (e.g., epoch timestamps)
        ]

        normalized = content
        for pattern in patterns:
            normalized = re.sub(pattern, "", normalized, flags=re.IGNORECASE | re.DOTALL)

        return normalized

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
        # Derive a risk score from the collected scan data and persist the
        # complete result to the database. Database errors are ignored so that
        # scans can still succeed in environments without the expected schema.
        result['risk_score'] = risk.calculate_risk_score(result)

        try:
            self._ensure_db()
            self.db.save_scan_result(url, result)
        except Exception:
            pass

        return result
