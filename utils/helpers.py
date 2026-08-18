"""
utils/helpers.py — Shared helper functions: audit logging and security alert creation.
"""
import sqlite3
from datetime import datetime


def audit_log_action(user_id, username, action, ip_address, description):
    """Insert a record into audit_logs."""
    conn   = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO audit_logs
                (user_id, username, action, timestamp, ip_address, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            username,
            action,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip_address,
            description,
        ))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def create_security_alert(username, alert_type, severity, message,
                          prediction, threat_score):
    """
    Insert a new security alert into security_alerts.
    10-minute duplicate guard to avoid flooding.
    """
    conn   = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Duplicate guard
        cursor.execute("""
            SELECT COUNT(*) FROM security_alerts
            WHERE  username=?
              AND  alert_type=?
              AND  prediction=?
              AND  created_at >= datetime('now', '-10 minutes')
        """, (username, alert_type, prediction))
        if cursor.fetchone()[0] > 0:
            return

        cursor.execute("""
            INSERT INTO security_alerts
                (username, alert_type, prediction, alert_time, severity,
                 message, threat_score, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'New')
        """, (
            username, alert_type, prediction,
            now_str, severity, message, threat_score, now_str,
        ))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()
