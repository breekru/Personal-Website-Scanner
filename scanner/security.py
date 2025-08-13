from datetime import datetime, timezone
import requests

from .rdap import fetch_rdap


def additional_security_checks(url: str, domain: str, rdap_data=None):
    """Perform additional legitimacy checks for a domain."""
    checks: dict[str, object] = {}

    try:
        suspicious_patterns = ['paypal', 'amazon', 'microsoft', 'google', 'apple']
        domain_lower = domain.lower()
        for pattern in suspicious_patterns:
            if pattern in domain_lower and not domain_lower.endswith(f'{pattern}.com'):
                checks['suspicious_domain'] = f"Contains '{pattern}' but not official domain"

        rdap = rdap_data or fetch_rdap(domain)
        creation_date = None
        if rdap:
            for event in rdap.get('events', []):
                if event.get('eventAction') in ("registration", "creation"):
                    date_str = event.get('eventDate')
                    if date_str:
                        creation_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    break
        if creation_date:
            age_days = (datetime.now(timezone.utc) - creation_date).days
            if age_days < 0:
                age_days = 0
            checks['domain_age_days'] = age_days
            if age_days < 30:
                checks['new_domain_warning'] = "Domain is less than 30 days old"
        else:
            checks['domain_age_days'] = None
            checks['domain_age_error'] = "Creation date not found"
    except Exception as exc:  # pragma: no cover - defensive
        checks['domain_age_error'] = str(exc)

    try:
        if not url.startswith('https://'):
            http_response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
            if http_response.status_code in [301, 302] and 'https' in http_response.headers.get('Location', ''):
                checks['https_redirect'] = True
            else:
                checks['https_redirect'] = False
    except Exception:  # pragma: no cover - network errors ignored
        checks['https_redirect'] = 'unknown'

    return checks
