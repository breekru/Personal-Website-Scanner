import sqlite3


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
