import types
import sys


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

from pathlib import Path

# Ensure project root is on the Python path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from mainV3 import parse_registrar_from_rdap


def test_parse_registrar_uses_fn():
    """Registrar should be read from the vCard fn field when available."""
    rdap = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Example Registrar"]],
                ],
            }
        ]
    }

    assert parse_registrar_from_rdap(rdap) == "Example Registrar"


def test_parse_registrar_falls_back_to_org():
    """If fn is missing, the org field should be used."""
    rdap = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["org", {}, "text", "Example Org"]],
                ],
            }
        ]
    }

    assert parse_registrar_from_rdap(rdap) == "Example Org"


def test_parse_registrar_falls_back_to_handle():
    """If neither fn nor org is present, the entity handle is used."""
    rdap = {
        "entities": [
            {
                "roles": ["registrar"],
                "handle": "HANDLE123",
                "vcardArray": ["vcard", []],
            }
        ]
    }

    assert parse_registrar_from_rdap(rdap) == "HANDLE123"

