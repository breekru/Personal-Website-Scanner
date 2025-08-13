import types
import sys
from datetime import datetime, timezone, timedelta


def test_domain_age_uses_creation_event(monkeypatch):
    """Domain age should be calculated when RDAP uses the 'creation' event."""
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

    rdap = {
        'events': [
            {
                'eventAction': 'creation',
                'eventDate': '2000-01-01T00:00:00Z'
            }
        ]
    }

    checks = tool.additional_security_checks('https://example.com', 'example.com', rdap)
    expected_age = (datetime.now(timezone.utc) - datetime(2000, 1, 1, tzinfo=timezone.utc)).days
    assert checks['domain_age_days'] == expected_age


def test_domain_age_clamps_negative(monkeypatch):
    """Future creation dates should result in zero age."""
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

    future_date = (datetime.now(timezone.utc) + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    rdap = {
        'events': [
            {
                'eventAction': 'creation',
                'eventDate': future_date
            }
        ]
    }

    checks = tool.additional_security_checks('https://example.com', 'example.com', rdap)
    assert checks['domain_age_days'] == 0


def test_domain_age_handles_missing_creation(monkeypatch):
    """Missing creation date should set age to None with error flag."""
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

    rdap = {
        'events': [
            {
                'eventAction': 'expiration',
                'eventDate': '2000-01-01T00:00:00Z'
            }
        ]
    }

    checks = tool.additional_security_checks('https://example.com', 'example.com', rdap)
    assert checks['domain_age_days'] is None
    assert 'domain_age_error' in checks
