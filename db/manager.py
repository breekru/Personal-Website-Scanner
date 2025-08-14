import sqlite3
import json


class DatabaseManager:
    """Encapsulate persistence logic for the scanner."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def toggle_manual_status(self, website_id: int, status: str):
        """Toggle a manual status flag for a website.

        Mirrors the behaviour from the original application where a
        website can be marked as ``high_risk`` or ``safe`` manually. When
        toggling to ``high_risk`` the latest scan result's ``risk_score``
        is forced to ``100``.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT manual_status FROM websites WHERE id = ?",
            (website_id,),
        )
        row = cursor.fetchone()
        current_status = row[0] if row else None

        if current_status == status:
            cursor.execute(
                "UPDATE websites SET manual_status = NULL WHERE id = ?",
                (website_id,),
            )
            new_status = None
        else:
            cursor.execute(
                "UPDATE websites SET manual_status = ? WHERE id = ?",
                (status, website_id),
            )
            new_status = status

            if status == "high_risk":
                cursor.execute(
                    """
                    UPDATE scan_results
                    SET risk_score = 100
                    WHERE id = (
                        SELECT id FROM scan_results
                        WHERE website_id = ?
                        ORDER BY scan_date DESC
                        LIMIT 1
                    )
                    """,
                    (website_id,),
                )

        conn.commit()
        conn.close()
        return new_status

    def save_scan_result(self, url: str, scan_result: dict):
        """Persist a scan *scan_result* for *url*.

        A corresponding entry in the ``websites`` table will be created if it
        does not already exist. The ``scan_results`` row stores the computed
        ``risk_score`` alongside the raw scan details. Any database errors are
        silently ignored so that scans can proceed even if the schema is
        incomplete (e.g. during tests).
        """

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM websites WHERE url = ?", (url,))
            row = cursor.fetchone()
            if row:
                website_id = row[0]
            else:
                cursor.execute("INSERT INTO websites (url) VALUES (?)", (url,))
                website_id = cursor.lastrowid

            try:
                cursor.execute(
                    "UPDATE websites SET last_checked = CURRENT_TIMESTAMP WHERE id = ?",
                    (website_id,),
                )
            except sqlite3.Error:
                pass

            try:
                cursor.execute(
                    """
                    INSERT INTO scan_results (
                        website_id, registrar, page_title, status_code,
                        ssl_valid, ssl_issuer, ssl_expiry, source_code_hash,
                        changes_detected, risk_score, mx_record_count,
                        mx_records, mx_check_status, additional_checks
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        website_id,
                        scan_result.get("registrar"),
                        scan_result.get("page_title"),
                        scan_result.get("status_code"),
                        scan_result.get("ssl_valid"),
                        scan_result.get("ssl_issuer"),
                        scan_result.get("ssl_expiry"),
                        scan_result.get("source_code_hash"),
                        int(scan_result.get("changes_detected", False)),
                        scan_result.get("risk_score", 0),
                        scan_result.get("mx_record_count"),
                        scan_result.get("mx_records"),
                        scan_result.get("mx_check_status"),
                        json.dumps(scan_result.get("additional_checks", {})),
                    ),
                )
            except sqlite3.Error:
                cursor.execute(
                    "INSERT INTO scan_results (website_id, risk_score) VALUES (?, ?)",
                    (website_id, scan_result.get("risk_score", 0)),
                )

            conn.commit()
            conn.close()
        except sqlite3.Error:
            # Silently ignore database failures; scanning should not crash due
            # to missing tables or other schema issues.
            pass
