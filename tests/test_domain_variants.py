import types
import sys

# Provide minimal stubs for external dependencies required by mainV3
requests_module = types.ModuleType("requests")

class DummyResponse:
    status_code = 200
    headers = {'content-type': 'text/html'}
    text = '<html><title>Example</title></html>'
    content = text.encode('utf-8')

def dummy_get(*args, **kwargs):
    return DummyResponse()

class SSLError(Exception):
    pass

requests_module.get = dummy_get
requests_module.exceptions = types.SimpleNamespace(SSLError=SSLError)
sys.modules['requests'] = requests_module

# Stub dns modules
dns_module = types.ModuleType("dns")
dns_resolver = types.ModuleType("dns.resolver")
dns_exception = types.ModuleType("dns.exception")
dns_exception.DNSException = Exception
dns_module.resolver = dns_resolver
dns_module.exception = dns_exception
sys.modules['dns'] = dns_module
sys.modules['dns.resolver'] = dns_resolver
sys.modules['dns.exception'] = dns_exception

# Stub urllib3 exceptions for InsecureRequestWarning
urllib3_module = types.ModuleType("urllib3")
urllib3_exceptions = types.ModuleType("urllib3.exceptions")
urllib3_exceptions.InsecureRequestWarning = type("InsecureRequestWarning", (Warning,), {})
urllib3_module.exceptions = urllib3_exceptions
sys.modules['urllib3'] = urllib3_module
sys.modules['urllib3.exceptions'] = urllib3_exceptions

from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from mainV3 import WebsiteVerificationTool


def test_www_domain_uses_non_www_variant(monkeypatch):
    """URLs with www should fall back to the base domain for RDAP/MX lookups."""
    tool = WebsiteVerificationTool.__new__(WebsiteVerificationTool)

    # RDAP: only succeeds for example.com
    def fake_fetch_rdap(domain):
        return {'dummy': 'data'} if domain == 'example.com' else None

    monkeypatch.setattr('mainV3.fetch_rdap', fake_fetch_rdap)
    monkeypatch.setattr('mainV3.parse_registrar_from_rdap', lambda data: 'Example Registrar' if data else None)

    # MX check: success only for example.com
    def fake_mx_check(self, domain):
        if domain == 'example.com':
            return {
                'mx_record_count': 1,
                'mx_records': 'mail.example.com',
                'mx_check_status': 'success',
                'mx_error': None,
            }
        return {
            'mx_record_count': 0,
            'mx_records': '',
            'mx_check_status': 'error',
            'mx_error': 'fail',
        }

    monkeypatch.setattr(WebsiteVerificationTool, 'perform_mx_check', fake_mx_check)

    # Stub SSL and other methods
    monkeypatch.setattr(WebsiteVerificationTool, 'perform_ssl_check', lambda self, d: {
        'ssl_valid': True,
        'ssl_issuer': 'Issuer',
        'ssl_expiry': '2025',
        'ssl_error': None,
        'ssl_version': None,
        'ssl_cipher': None,
    })
    monkeypatch.setattr(WebsiteVerificationTool, 'additional_security_checks', lambda self, url, domain, rdap_data: {})
    monkeypatch.setattr(WebsiteVerificationTool, 'normalize_content_for_hashing', lambda self, content: content)

    result = WebsiteVerificationTool.perform_website_checks(tool, 'https://www.example.com')
    assert result['registrar'] == 'Example Registrar'
    assert result['mx_record_count'] == 1
