"""Utilities for computing website risk scores.

Risk factors and their default weights:

* **ssl_invalid (30)** – SSL certificate is invalid or missing.
* **http_status_bad (20)** – HTTP status code is 400 or greater.
* **registrar_unknown (15)** – Registrar information could not be determined.
* **mx_error (10)** – MX record lookup failed.
* **mx_no_records (5)** – Domain has no MX records.
* **mx_present (5)** – Domain has MX records (potential email attack vector).
* **young_domain_penalty (10)** – Domain age is below ``young_domain_days``.
* **suspicious_domain (40)** – Domain flagged as suspicious.
* **new_domain_warning (25)** – Domain recently created warning.
* **no_https_redirect (10)** – HTTP does not redirect to HTTPS.
* **content_change (20)** – Non‑MX related content changes detected.
* **mx_change (25)** – MX record changes detected.
* **young_domain_days (365)** – Threshold in days for considering a domain young.
* **max_score (100)** – Upper bound for any calculated score.
"""

from typing import Dict, Any

DEFAULT_WEIGHTS: Dict[str, Any] = {
    "ssl_invalid": 30,
    "http_status_bad": 20,
    "registrar_unknown": 15,
    "mx_error": 10,
    "mx_no_records": 5,
    "mx_present": 5,
    "young_domain_penalty": 10,
    "suspicious_domain": 40,
    "new_domain_warning": 25,
    "no_https_redirect": 10,
    "content_change": 20,
    "mx_change": 25,
    "young_domain_days": 365,
    "max_score": 100,
}


def calculate_risk_score(scan_result: Dict[str, Any], config: Dict[str, Any] | None = None) -> int:
    """Return a risk score based on a scan result.

    Parameters
    ----------
    scan_result:
        Dictionary containing scan information for a single domain.
    config:
        Optional dictionary overriding values in :data:`DEFAULT_WEIGHTS`.

    Returns
    -------
    int
        Risk score capped between 0 and ``max_score``.
    """
    cfg = DEFAULT_WEIGHTS.copy()
    if config:
        cfg.update(config)

    score = 0

    if not scan_result.get("ssl_valid", True):
        score += cfg["ssl_invalid"]

    if scan_result.get("status_code", 0) >= 400:
        score += cfg["http_status_bad"]

    registrar = scan_result.get("registrar")
    if registrar in ["Unknown", "Whois lookup failed", "RDAP lookup failed"]:
        score += cfg["registrar_unknown"]

    mx_check_status = scan_result.get("mx_check_status", "not_checked")
    mx_record_count = scan_result.get("mx_record_count", 0)
    if mx_check_status == "error":
        score += cfg["mx_error"]
    elif mx_check_status == "success" and mx_record_count == 0:
        score += cfg["mx_no_records"]
    elif mx_check_status == "success" and mx_record_count > 0:
        score += cfg["mx_present"]

    additional = scan_result.get("additional_checks", {})
    domain_age_days = additional.get("domain_age_days")
    if domain_age_days is not None and domain_age_days < cfg["young_domain_days"]:
        score += cfg["young_domain_penalty"]

    if "suspicious_domain" in additional:
        score += cfg["suspicious_domain"]

    if "new_domain_warning" in additional:
        score += cfg["new_domain_warning"]

    if additional.get("https_redirect") is False:
        score += cfg["no_https_redirect"]

    if scan_result.get("changes_detected"):
        if "mx_change_details" in additional:
            score += cfg["mx_change"]
        else:
            score += cfg["content_change"]

    return max(0, min(cfg.get("max_score", 100), score))
