import os
import sqlite3

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database.db")


def _table_has_column(conn, table_name, column_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row[1] == column_name for row in rows)


def _add_column_if_missing(conn, table_name, column_name, definition):
    if not _table_has_column(conn, table_name, column_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def create_database(db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    _add_column_if_missing(conn, "users", "failed_attempts", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "users", "account_locked", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "users", "user_code", "INTEGER")
    _add_column_if_missing(conn, "users", "trusted_device", "INTEGER")
    _add_column_if_missing(conn, "users", "ai_enabled", "INTEGER DEFAULT 1")
    _add_column_if_missing(conn, "users", "role", "TEXT DEFAULT 'user'")
    _add_column_if_missing(conn, "users", "created_at", "TEXT")
    _add_column_if_missing(conn, "users", "last_login_at", "TEXT")
    _add_column_if_missing(conn, "users", "last_login_ip", "TEXT")
    _add_column_if_missing(conn, "users", "updated_at", "TEXT")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        login_date TEXT,
        login_time TEXT,
        ip_address TEXT,
        browser TEXT,
        device TEXT,
        prediction TEXT,
        risk TEXT,
        reasons TEXT
    )
    """)

    _add_column_if_missing(conn, "login_logs", "threat_score", "REAL DEFAULT 0")
    _add_column_if_missing(conn, "login_logs", "confidence", "REAL DEFAULT 0")
    _add_column_if_missing(conn, "login_logs", "ai_enabled", "INTEGER DEFAULT 1")
    _add_column_if_missing(conn, "login_logs", "status", "TEXT DEFAULT 'normal'")
    _add_column_if_missing(conn, "login_logs", "created_at", "TEXT")
    _add_column_if_missing(conn, "login_logs", "user_id", "INTEGER")
    _add_column_if_missing(conn, "login_logs", "is_known_ip", "INTEGER")
    _add_column_if_missing(conn, "login_logs", "is_known_device", "INTEGER")
    _add_column_if_missing(conn, "login_logs", "time_anomaly_score", "REAL")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        timestamp TEXT,
        ip_address TEXT,
        device TEXT,
        risk TEXT,
        reason TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        alert_type TEXT,
        prediction TEXT,
        alert_time TEXT
    )
    """)

    _add_column_if_missing(conn, "security_alerts", "severity", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "message", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "threat_score", "REAL DEFAULT 0")
    _add_column_if_missing(conn, "security_alerts", "created_at", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "status", "TEXT DEFAULT 'New'")
    _add_column_if_missing(conn, "security_alerts", "resolved_at", "TEXT")
    # Phase 10 alert correlation: fingerprint is deterministic and prevents the
    # same application event from producing multiple analyst alerts.
    _add_column_if_missing(conn, "security_alerts", "application_id", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "user_id", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "event_id", "INTEGER")
    _add_column_if_missing(conn, "security_alerts", "ip_address", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "device_id", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "alert_fingerprint", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "risk_level", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "model_probability", "REAL")
    _add_column_if_missing(conn, "security_alerts", "confidence", "REAL")
    _add_column_if_missing(conn, "security_alerts", "behavioural_evidence", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "reasons", "TEXT")
    _add_column_if_missing(conn, "security_alerts", "incident_id", "TEXT")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        description TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS applications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id TEXT NOT NULL UNIQUE,
        application_name TEXT NOT NULL,
        description TEXT,
        api_key_hash TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_event_at TEXT,
        total_events INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id TEXT,
        user_id TEXT,
        timestamp TEXT,
        ip_address TEXT,
        device_id TEXT,
        browser TEXT,
        os TEXT,
        login_success INTEGER DEFAULT 1,
        failed_attempts INTEGER DEFAULT 0,
        received_at TEXT,
        risk_score REAL DEFAULT 0,
        risk_level TEXT,
        prediction TEXT,
        model_probability REAL DEFAULT 0,
        behavioural_score REAL DEFAULT 0,
        alert_created INTEGER DEFAULT 0,
        reasons TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    _add_column_if_missing(conn, "applications", "owner", "TEXT DEFAULT 'admin'")
    _add_column_if_missing(conn, "applications", "last_event_at", "TEXT")
    _add_column_if_missing(conn, "applications", "total_events", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "applications", "high_risk_events", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "applications", "medium_risk_events", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "applications", "low_risk_events", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "auth_events", "application_id", "TEXT")
    _add_column_if_missing(conn, "auth_events", "username", "TEXT")
    _add_column_if_missing(conn, "auth_events", "event_type", "TEXT DEFAULT 'login'")
    _add_column_if_missing(conn, "auth_events", "user_agent", "TEXT")
    _add_column_if_missing(conn, "auth_events", "success", "INTEGER DEFAULT 1")
    _add_column_if_missing(conn, "auth_events", "risk_score", "REAL DEFAULT 0")
    _add_column_if_missing(conn, "auth_events", "risk_level", "TEXT")
    _add_column_if_missing(conn, "auth_events", "prediction", "TEXT")
    _add_column_if_missing(conn, "auth_events", "model_probability", "REAL DEFAULT 0")
    _add_column_if_missing(conn, "auth_events", "behavioural_score", "REAL DEFAULT 0")
    _add_column_if_missing(conn, "auth_events", "confidence", "REAL DEFAULT 0")
    _add_column_if_missing(conn, "auth_events", "behavioural_evidence", "TEXT")
    _add_column_if_missing(conn, "auth_events", "alert_created", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "auth_events", "reasons", "TEXT")
    _add_column_if_missing(conn, "auth_events", "status", "TEXT DEFAULT 'received'")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_user ON login_logs(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_risk ON login_logs(risk)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_application ON auth_events(application_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_user ON auth_events(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_username ON auth_events(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON auth_events(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_risk_level ON auth_events(risk_level)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_event_type ON auth_events(event_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_app_user_ip_time ON auth_events(application_id, username, ip_address, timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_status ON auth_events(status)")

    # Phase 9: Incident management tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL UNIQUE,
        application_id TEXT,
        user_id TEXT,
        username TEXT,
        severity TEXT DEFAULT 'LOW',
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'OPEN',
        assigned_to TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        resolved_at TEXT,
        resolution_notes TEXT,
        FOREIGN KEY(application_id) REFERENCES applications(application_id)
    )
    """)

    _add_column_if_missing(conn, "incidents", "incident_id", "TEXT NOT NULL UNIQUE")
    _add_column_if_missing(conn, "incidents", "application_id", "TEXT")
    _add_column_if_missing(conn, "incidents", "user_id", "TEXT")
    _add_column_if_missing(conn, "incidents", "username", "TEXT")
    _add_column_if_missing(conn, "incidents", "severity", "TEXT DEFAULT 'LOW'")
    _add_column_if_missing(conn, "incidents", "title", "TEXT")
    _add_column_if_missing(conn, "incidents", "description", "TEXT")
    _add_column_if_missing(conn, "incidents", "status", "TEXT DEFAULT 'OPEN'")
    _add_column_if_missing(conn, "incidents", "assigned_to", "TEXT")
    _add_column_if_missing(conn, "incidents", "created_at", "TEXT")
    _add_column_if_missing(conn, "incidents", "updated_at", "TEXT")
    _add_column_if_missing(conn, "incidents", "resolved_at", "TEXT")
    _add_column_if_missing(conn, "incidents", "resolution_notes", "TEXT")
    _add_column_if_missing(conn, "incidents", "first_seen", "TEXT")
    _add_column_if_missing(conn, "incidents", "last_seen", "TEXT")
    _add_column_if_missing(conn, "incidents", "source_ip", "TEXT")
    _add_column_if_missing(conn, "incidents", "device_id", "TEXT")
    _add_column_if_missing(conn, "incidents", "acknowledged_at", "TEXT")
    _add_column_if_missing(conn, "incidents", "assigned_at", "TEXT")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incident_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        event_id INTEGER,
        application_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id),
        FOREIGN KEY(event_id) REFERENCES auth_events(id)
    )
    """)

    _add_column_if_missing(conn, "incident_events", "incident_id", "TEXT NOT NULL")
    _add_column_if_missing(conn, "incident_events", "event_id", "INTEGER")
    _add_column_if_missing(conn, "incident_events", "application_id", "TEXT")
    _add_column_if_missing(conn, "incident_events", "created_at", "TEXT")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_application ON incidents(application_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_security_alerts_fingerprint ON security_alerts(alert_fingerprint) WHERE alert_fingerprint IS NOT NULL")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_application ON security_alerts(application_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_incident ON security_alerts(incident_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_created ON security_alerts(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_assigned ON incidents(assigned_to)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incident_notes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        analyst TEXT NOT NULL,
        note TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incident_assignments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        assigned_to TEXT,
        assigned_by TEXT NOT NULL,
        assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_assignments_incident ON incident_assignments(incident_id, assigned_at)")

    # Password-reset tokens are intentionally stored only as SHA-256 digests.
    # Existing users and authentication history are never modified by this migration.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_active ON password_reset_tokens(user_id, used_at, expires_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry ON password_reset_tokens(expires_at)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_otps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        otp_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        used_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_otps_user_active ON password_reset_otps(user_id, used_at, expires_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_otps_expiry ON password_reset_otps(expires_at)")

    conn.commit()
    conn.close()

    print("Database and tables created successfully.")


if __name__ == "__main__":
    create_database()
