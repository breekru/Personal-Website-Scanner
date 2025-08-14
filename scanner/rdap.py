import requests


def fetch_rdap(domain: str):
    """Fetch RDAP information for a domain."""
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def parse_registrar_from_rdap(rdap_data):
    """Extract registrar name from RDAP data.

    Attempts to read the registrar's full name (fn) from the entity's
    vCard data. If absent, falls back to the organization (org) field, and
    finally to the entity's handle.
    """
    if not rdap_data:
        return None

    for entity in rdap_data.get('entities', []):
        if 'registrar' in entity.get('roles', []):
            vcard = entity.get('vcardArray', [])
            registrar_name = None

            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == 'fn':
                        registrar_name = item[3]
                        break
                if not registrar_name:
                    for item in vcard[1]:
                        if item[0] == 'org':
                            registrar_name = item[3]
                            break

            if not registrar_name:
                registrar_name = entity.get('handle')

            if registrar_name:
                return registrar_name

    return None
