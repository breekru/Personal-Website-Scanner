import types
import sys
import sqlite3
from pathlib import Path

# Ensure the project root is on the import path
sys.path.append(str(Path(__file__).resolve().parent.parent))
# Stub external dependencies before importing main module
sys.modules['requests'] = types.ModuleType("requests")

_dns = types.ModuleType("dns")
_dns_resolver = types.ModuleType("dns.resolver")
_dns_exception = types.ModuleType("dns.exception")
_dns_exception.DNSException = Exception
_dns.resolver = _dns_resolver
_dns.exception = _dns_exception
sys.modules['dns'] = _dns
sys.modules['dns.resolver'] = _dns_resolver
sys.modules['dns.exception'] = _dns_exception

_urllib3 = types.ModuleType("urllib3")
_urllib3_exceptions = types.ModuleType("urllib3.exceptions")
_urllib3_exceptions.InsecureRequestWarning = type("InsecureRequestWarning", (Warning,), {})
_urllib3.exceptions = _urllib3_exceptions
sys.modules['urllib3'] = _urllib3
sys.modules['urllib3.exceptions'] = _urllib3_exceptions

from risk import calculate_risk_score, DEFAULT_WEIGHTS
from mainV3 import WebsiteVerificationTool


class DummyTree:
    """Simple stand-in for tkinter Treeview used for testing."""
    def __init__(self):
        self.items = {}

    def get_children(self):
        return list(self.items.keys())

    def delete(self, item):
        if item in self.items:
            del self.items[item]

    def insert(self, parent, index, iid, text, values, tags):
        self.items[iid] = {"values": values, "tags": tags}

    def tag_configure(self, tag, **kwargs):
        # Method stub to satisfy calls in load_websites
        pass


def test_rdap_lookup_failed_increases_risk_score():
    """Ensure RDAP lookup failures affect the risk score."""
    scan_result = {
        'ssl_valid': True,
        'status_code': 200,
        'registrar': 'RDAP lookup failed'
    }
    assert calculate_risk_score(scan_result) == DEFAULT_WEIGHTS['registrar_unknown']


def test_custom_weights_adjust_score_and_capped():
    """Custom configuration should change weighting and remain within 0-100."""
    scan_result = {
        'ssl_valid': False,
        'status_code': 500,
        'registrar': 'Unknown',
        'mx_check_status': 'error',
        'mx_record_count': 0,
        'additional_checks': {'domain_age_days': 10}
    }
    default_score = calculate_risk_score(scan_result)
    custom_config = {
        'ssl_invalid': 60,
        'http_status_bad': 40,
        'registrar_unknown': 20,
        'mx_error': 20,
        'young_domain_penalty': 20,
    }
    custom_score = calculate_risk_score(scan_result, custom_config)
    assert custom_score > default_score
    assert 0 <= custom_score <= 100


def test_domain_age_threshold_can_be_tuned():
    """Adjusting the young domain threshold should affect scoring."""
    scan_result = {
        'ssl_valid': True,
        'status_code': 200,
        'registrar': 'Example',
        'mx_check_status': 'not_checked',
        'additional_checks': {'domain_age_days': 400}
    }
    default_score = calculate_risk_score(scan_result)
    custom_score = calculate_risk_score(scan_result, {
        'young_domain_days': 500,
        'young_domain_penalty': 20,
    })
    assert default_score == 0
    assert custom_score == 20


def test_manual_high_risk_updates_scan_results(tmp_path):
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            name TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_checked TIMESTAMP,
            status TEXT DEFAULT 'pending',
            manual_status TEXT,
            notes TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE scan_results (
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
            mx_record_count INTEGER DEFAULT 0,
            mx_records TEXT,
            mx_check_status TEXT DEFAULT 'not_checked',
            additional_checks TEXT,
            FOREIGN KEY (website_id) REFERENCES websites (id)
        )
    ''')
    conn.commit()

    cursor.execute("INSERT INTO websites (url) VALUES (?)", ("https://example.com",))
    website_id = cursor.lastrowid
    cursor.execute("INSERT INTO scan_results (website_id, risk_score, scan_date) VALUES (?,?,?)",
                   (website_id, 10, "2023-01-01"))
    cursor.execute("INSERT INTO scan_results (website_id, risk_score, scan_date) VALUES (?,?,?)",
                   (website_id, 20, "2023-01-02"))
    conn.commit()
    conn.close()

    tool = WebsiteVerificationTool.__new__(WebsiteVerificationTool)
    tool.db_path = str(db_path)

    tool.toggle_manual_status(website_id, 'high_risk')

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT risk_score FROM scan_results WHERE website_id=? ORDER BY scan_date DESC LIMIT 1",
                   (website_id,))
    assert cursor.fetchone()[0] == 100
    cursor.execute("SELECT manual_status FROM websites WHERE id=?", (website_id,))
    assert cursor.fetchone()[0] == 'high_risk'
    conn.close()


def test_load_websites_reports_100_for_manual_high_risk_without_scan(tmp_path):
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            name TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_checked TIMESTAMP,
            status TEXT DEFAULT 'pending',
            manual_status TEXT,
            notes TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE scan_results (
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
            mx_record_count INTEGER DEFAULT 0,
            mx_records TEXT,
            mx_check_status TEXT DEFAULT 'not_checked',
            additional_checks TEXT,
            FOREIGN KEY (website_id) REFERENCES websites (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website_id INTEGER,
            comment_date TEXT,
            name TEXT,
            comment TEXT,
            FOREIGN KEY (website_id) REFERENCES websites (id)
        )
    ''')
    conn.commit()
    cursor.execute("INSERT INTO websites (url, manual_status) VALUES (?, ?)",
                   ("https://example.com", "high_risk"))
    conn.commit()
    conn.close()

    tool = WebsiteVerificationTool.__new__(WebsiteVerificationTool)
    tool.db_path = str(db_path)
    tool.websites_tree = DummyTree()
    tool.last_sort_column = None
    tool.last_sort_reverse = False

    tool.load_websites()

    values = tool.websites_tree.items['1']['values']
    assert values[8] == '100/100'
