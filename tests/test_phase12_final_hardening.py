"""Final hardening tests: real ingestion, traceability, isolation and SOC controls."""
import hashlib
import json
import os
import sqlite3
import tempfile
import uuid

import app as flask_app_module
from app import API_RATE_LIMIT_BUCKETS, app
from database.database import create_database
from services import auth_event_service
from services import incident_service
from services.incident_service import add_incident_note, assign_incident, get_incident_by_id, update_incident_status


# ---------------------------------------------------------------------------
# Per-test DB isolation helpers
# ---------------------------------------------------------------------------

def _make_isolated_db():
    """Create a fresh temp database and redirect all module-level DB_PATH vars."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    create_database(path)
    flask_app_module.DB_PATH = path
    auth_event_service.DB_PATH = path
    incident_service.DB_PATH = path
    return path


def _new_application(suffix, status="active"):
    app_id = f"phase12-{suffix}-{uuid.uuid4().hex[:8]}"
    key = f"development-{uuid.uuid4().hex}"
    db = flask_app_module.DB_PATH
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO applications (application_id, application_name, api_key_hash, status) VALUES (?, ?, ?, ?)",
        (app_id, app_id, hashlib.sha256(key.encode()).hexdigest(), status),
    )
    conn.commit()
    conn.close()
    return app_id, key


def _event(application_id, user_id, timestamp, ip, device, failed_attempts=0):
    return {
        "application_id": application_id,
        "user_id": user_id,
        "timestamp": timestamp,
        "ip_address": ip,
        "device_id": device,
        "browser": "Chrome",
        "os": "Windows",
        "login_success": True,
        "failed_attempts": failed_attempts,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_real_ingestion_stores_model_outputs_and_preserves_application_isolation():
    db = _make_isolated_db()
    app.config.update(TESTING=True, API_RATE_LIMIT_PER_MINUTE=1000)
    API_RATE_LIMIT_BUCKETS.clear()
    app_a, key_a = _new_application("a")
    app_b, key_b = _new_application("b")
    client = app.test_client()

    normal = client.post(
        "/api/v1/auth-events",
        json=_event(app_a, "normal-user", "2026-08-17T10:00:00", "192.0.2.10", "known-device"),
        headers={"X-API-Key": key_a},
    )
    assert normal.status_code == 201
    normal_data = normal.get_json()
    assert isinstance(normal_data["model_probability"], float)
    assert isinstance(normal_data["threat_score"], float)
    assert isinstance(normal_data["reasons"], list)

    suspicious = client.post(
        "/api/v1/auth-events",
        json=_event(app_a, "suspicious-user", "2026-08-17T23:30:00", "198.51.100.23", "new-device", 5),
        headers={"X-API-Key": key_a},
    )
    assert suspicious.status_code == 201
    suspicious_data = suspicious.get_json()
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    stored = conn.execute(
        "SELECT * FROM auth_events WHERE id=?", (suspicious_data["event_id"],)
    ).fetchone()
    assert stored and stored["application_id"] == app_a
    assert stored["model_probability"] is not None and stored["risk_score"] is not None
    assert json.loads(stored["reasons"])
    # Re-ingesting the identical external signature keeps the event audit trail
    # but must not create a second matching alert fingerprint.
    repeated = client.post(
        "/api/v1/auth-events",
        json=_event(app_a, "suspicious-user", "2026-08-17T23:30:00", "198.51.100.23", "new-device", 5),
        headers={"X-API-Key": key_a},
    )
    assert repeated.status_code == 201
    fingerprints = conn.execute(
        "SELECT alert_fingerprint FROM security_alerts WHERE application_id=? AND event_id IN (?, ?)",
        (app_a, suspicious_data["event_id"], repeated.get_json()["event_id"]),
    ).fetchall()
    assert len({row["alert_fingerprint"] for row in fingerprints if row["alert_fingerprint"]}) <= 1
    conn.close()

    mismatch = client.post(
        "/api/v1/auth-events",
        json=_event(app_b, "other-user", "2026-08-17T10:01:00", "192.0.2.20", "other-device"),
        headers={"X-API-Key": key_a},
    )
    assert mismatch.status_code == 403
    assert key_a not in mismatch.get_data(as_text=True)
    assert key_b not in normal.get_data(as_text=True)


def test_revoked_application_and_invalid_event_are_rejected():
    _make_isolated_db()
    app.config.update(TESTING=True, API_RATE_LIMIT_PER_MINUTE=1000)
    API_RATE_LIMIT_BUCKETS.clear()
    app_id, key = _new_application("revoked", "revoked")
    client = app.test_client()

    rejected = client.post(
        "/api/v1/auth-events",
        json=_event(app_id, "user", "2026-08-17T10:00:00", "192.0.2.44", "device"),
        headers={"X-API-Key": key},
    )
    assert rejected.status_code == 403

    active_id, active_key = _new_application("invalid")
    invalid = client.post(
        "/api/v1/auth-events",
        json=_event(active_id, "user", "not-a-timestamp", "not-ip", "device"),
        headers={"X-API-Key": active_key},
    )
    assert invalid.status_code == 400


def test_incident_lifecycle_notes_and_audit_are_append_only():
    db = _make_isolated_db()
    app.config.update(TESTING=True)
    incident_id = f"INC-P12-{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO incidents (incident_id, application_id, username, severity, title, status) VALUES (?, ?, ?, 'HIGH', ?, 'NEW')",
        (incident_id, "phase12-workflow", "admin", "Phase 12 workflow"),
    )
    conn.commit()
    conn.close()
    assert assign_incident(incident_id, "admin", "admin")
    assert add_incident_note(incident_id, "admin", "Initial investigation note")
    for state in ("TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED"):
        assert update_incident_status(incident_id, state, actor="admin", comment="phase 12 test")
    assert not update_incident_status(incident_id, "NEW", actor="admin")
    incident = get_incident_by_id(incident_id)
    assert incident["status"] == "RESOLVED"
    assert len(incident["notes"]) == 1 and incident["notes"][0]["note"] == "Initial investigation note"
    assert any(item["type"] == "audit" for item in incident["timeline"])


def test_soc_api_is_not_available_without_an_admin_session():
    _make_isolated_db()
    app.config.update(TESTING=True)
    client = app.test_client()
    assert client.get("/api/v1/soc/events").status_code == 403
    assert client.post("/api/v1/soc/incidents/missing/status", json={"status": "TRIAGED"}).status_code == 403


def test_role_based_authorization_controls():
    db = _make_isolated_db()
    app.config.update(TESTING=True)
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO users (username, email, password, role) VALUES ('normaluser', 'norm@ex.com', 'hash', 'user')"
    )
    conn.execute(
        "INSERT INTO users (username, email, password, role) VALUES ('analystuser', 'ana@ex.com', 'hash', 'analyst')"
    )
    conn.execute(
        "INSERT INTO users (username, email, password, role) VALUES ('customadmin', 'adm@ex.com', 'hash', 'admin')"
    )
    conn.commit()
    conn.close()

    client = app.test_client()

    # 1. Normal user (role='user') must be blocked from admin/SOC endpoints
    with client.session_transaction() as sess:
        sess["username"] = "normaluser"
        sess["role"] = "user"
    assert client.get("/admin").status_code == 302
    assert client.get("/admin/applications").status_code == 302
    assert client.get("/admin/incidents").status_code == 302
    assert client.get("/api/v1/soc/events").status_code == 403

    # 2. Analyst user (role='analyst') can access SOC endpoints, but blocked from admin apps
    with client.session_transaction() as sess:
        sess["username"] = "analystuser"
        sess["role"] = "analyst"
    assert client.get("/admin/incidents").status_code == 200
    assert client.get("/admin/soc-dashboard").status_code == 200
    assert client.get("/admin/applications").status_code == 302
    assert client.get("/api/v1/soc/events").status_code == 403

    # 3. Custom Admin user (role='admin') can access admin and SOC endpoints
    with client.session_transaction() as sess:
        sess["username"] = "customadmin"
        sess["role"] = "admin"
    assert client.get("/admin").status_code == 200
    assert client.get("/admin/applications").status_code == 200
    assert client.get("/api/v1/soc/events").status_code == 200


def test_database_has_case_insensitive_email_index():
    db = _make_isolated_db()
    conn = sqlite3.connect(db)
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_users_email_lower'"
    ).fetchone()
    conn.close()
    assert row is not None and row[0] == "idx_users_email_lower"

