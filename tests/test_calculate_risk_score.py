import types
import sys


def test_rdap_lookup_failed_increases_risk_score(monkeypatch):
    """Ensure RDAP lookup failures affect the risk score."""
    # Provide minimal stubs for external dependencies required by mainV3
    sys.modules['requests'] = types.ModuleType("requests")

    dns_module = types.ModuleType("dns")
    dns_resolver = types.ModuleType("dns.resolver")
    dns_exception = types.ModuleType("dns.exception")
    dns_exception.DNSException = Exception
    dns_module.resolver = dns_resolver
    dns_module.exception = dns_exception
    sys.modules['dns'] = dns_module
    sys.modules['dns.resolver'] = dns_resolver
    sys.modules['dns.exception'] = dns_exception

    urllib3_module = types.ModuleType("urllib3")
    urllib3_exceptions = types.ModuleType("urllib3.exceptions")
    urllib3_exceptions.InsecureRequestWarning = type("InsecureRequestWarning", (Warning,), {})
    urllib3_module.exceptions = urllib3_exceptions
    sys.modules['urllib3'] = urllib3_module
    sys.modules['urllib3.exceptions'] = urllib3_exceptions

    from mainV3 import WebsiteVerificationTool

    tool = WebsiteVerificationTool.__new__(WebsiteVerificationTool)
    scan_result = {
        'ssl_valid': True,
        'status_code': 200,
        'registrar': 'RDAP lookup failed'
    }
    assert tool.calculate_risk_score(scan_result) == 15
