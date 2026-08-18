import hashlib
import sqlite3

import pytest

import app as flask_app_module
from app import API_RATE_LIMIT_BUCKETS, app
from database.database import create_database
from services import auth_event_service
from services import incident_service


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    create_database(path)
    return path


@pytest.fixture()
def client(db_path):
    API_RATE_LIMIT_BUCKETS.clear()
    app.config.update(TESTING=True, API_RATE_LIMIT_PER_MINUTE=1000)
    # Redirect all modules that have their own DB_PATH to the isolated temp DB
    flask_app_module.DB_PATH = db_path
    auth_event_service.DB_PATH = db_path
    incident_service.DB_PATH = db_path
    with app.test_client() as c:
        yield c
    API_RATE_LIMIT_BUCKETS.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _login_as_admin(client):
    with client.session_transaction() as sess:
        sess["username"] = "admin"


def _create_application(application_id, application_name="Demo App", api_key="demo-key-123", status="active"):
    """Insert or fully update an application record in the current temp DB."""
    db = flask_app_module.DB_PATH
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM applications WHERE application_id=?", (application_id,))
    if cursor.fetchone() is None:
        cursor.execute(
            """
            INSERT INTO applications (application_id, application_name, description, owner, api_key_hash, status, created_at, total_events, high_risk_events, medium_risk_events, low_risk_events)
            VALUES (?, ?, ?, 'admin', ?, ?, datetime('now'), 0, 0, 0, 0)
            """,
            (application_id, application_name, "Demo app", _hash(api_key), status),
        )
    else:
        cursor.execute(
            "UPDATE applications SET api_key_hash=?, status=? WHERE application_id=?",
            (_hash(api_key), status, application_id),
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_application_registration_and_summary(client):
    _login_as_admin(client)
    _create_application("phase8-registry", "Registry App", "seed-key")

    response = client.get("/admin/applications")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Monitored Applications" in html
    assert "Registry App" in html or "phase8-registry" in html

    assert "Monitored Applications" in html
    assert "Registry App" in html or "phase8-registry" in html
    assert "Total Applications" in html or "Active Applications" in html


def test_registered_app_api_key_must_match_application_id(client):
    _create_application("app-one", "App One", "key-for-app-one")
    _create_application("app-two", "App Two", "key-for-app-two")

    payload = {
        "application_id": "app-one",
        "user_id": "U-1001",
        "timestamp": "2026-08-17T10:00:00",
        "ip_address": "192.168.10.44",
        "device_id": "device-001",
        "browser": "Chrome",
        "os": "Windows",
        "login_success": True,
        "failed_attempts": 0,
    }

    response = client.post(
        "/api/v1/auth-events",
        json=payload,
        headers={"X-API-Key": "key-for-app-two"},
    )

    assert response.status_code in {401, 403}
    data = response.get_json()
    assert "error" in data
    assert "application" in data["error"].lower()


def test_app_status_toggle_and_revoke_are_reflected(client):
    _login_as_admin(client)
    _create_application("phase8-toggle", "Toggle App", "toggle-key", status="active")

    response = client.post("/admin/applications/phase8-toggle/toggle", follow_redirects=True)
    assert response.status_code == 200
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    row = conn.execute("SELECT status FROM applications WHERE application_id=?", ("phase8-toggle",)).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "inactive"

    response = client.post("/admin/applications/phase8-toggle/revoke", follow_redirects=True)
    assert response.status_code == 200
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    row = conn.execute("SELECT status FROM applications WHERE application_id=?", ("phase8-toggle",)).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "revoked"


def test_api_requests_are_rate_limited_per_application(client):
    app_id = "phase8-rate-fresh"
    api_key = "rate-key-phase8-fresh-unique"
    _create_application(app_id, "Rate App", api_key)
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 1
    API_RATE_LIMIT_BUCKETS.clear()

    first = client.post(
        "/api/v1/auth-events",
        json={
            "application_id": app_id,
            "user_id": "U-2001",
            "timestamp": "2026-08-17T11:00:00",
            "ip_address": "192.168.10.55",
            "device_id": "device-rate-1",
            "browser": "Firefox",
            "os": "Linux",
            "login_success": True,
            "failed_attempts": 0,
        },
        headers={"X-API-Key": api_key},
    )
    second = client.post(
        "/api/v1/auth-events",
        json={
            "application_id": app_id,
            "user_id": "U-2002",
            "timestamp": "2026-08-17T11:01:00",
            "ip_address": "192.168.10.56",
            "device_id": "device-rate-2",
            "browser": "Firefox",
            "os": "Linux",
            "login_success": True,
            "failed_attempts": 0,
        },
        headers={"X-API-Key": api_key},
    )

    assert first.status_code == 201
    assert second.status_code == 429
    assert first.get_json()["application_id"] == app_id


def test_application_detail_page_shows_recent_activity(client):
    _login_as_admin(client)
    _create_application("phase8-detail", "Detail App", "detail-key")
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    conn.execute(
        """
        INSERT INTO auth_events (
            application_id, user_id, username, timestamp, ip_address, device_id, browser, os,
            event_type, login_success, failed_attempts, received_at, risk_level, prediction,
            model_probability, behavioural_score, confidence, behavioural_evidence, alert_created, reasons
        )
        VALUES (?, 'user-01', 'alice', '2026-08-17T12:00:00', '10.0.0.2', 'phone-1', 'Chrome', 'Android', 'login', 1, 0, datetime('now'), 'LOW', 'Normal Login', 0.1, 0.1, 0.1, '[]', 0, '[]')
        """,
        ("phase8-detail",),
    )
    conn.commit()
    conn.close()

    response = client.get("/admin/applications/phase8-detail")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "alice" in html or "Detail App" in html
    assert "Recent Authentication Events" in html
    assert "Top Risky Users" in html or "Top Risky IPs" in html


def test_application_rotation_updates_api_key_hash(client):
    _login_as_admin(client)
    _create_application("phase8-rotate", "Rotate App", "old-key")
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    before = conn.execute(
        "SELECT api_key_hash FROM applications WHERE application_id=?",
        ("phase8-rotate",),
    ).fetchone()[0]
    conn.close()

    response = client.post("/admin/applications/phase8-rotate/rotate", follow_redirects=True)
    assert response.status_code == 200
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    after = conn.execute(
        "SELECT api_key_hash FROM applications WHERE application_id=?",
        ("phase8-rotate",),
    ).fetchone()[0]
    conn.close()
    assert before != after


def test_application_status_is_enforced_by_api_gateway(client):
    _create_application("phase8-disabled", "Disabled App", "disabled-key", status="inactive")
    response = client.post(
        "/api/v1/auth-events",
        json={
            "application_id": "phase8-disabled",
            "user_id": "U-4001",
            "timestamp": "2026-08-17T13:00:00",
            "ip_address": "203.0.113.10",
            "device_id": "device-disabled",
            "browser": "Edge",
            "os": "Windows",
            "login_success": True,
            "failed_attempts": 0,
        },
        headers={"X-API-Key": "disabled-key"},
    )
    assert response.status_code == 403
    assert "disabled" in response.get_json()["error"].lower()


def test_registered_application_is_required_for_event_submission(client):
    response = client.post(
        "/api/v1/auth-events",
        json={
            "application_id": "missing-app",
            "user_id": "U-5001",
            "timestamp": "2026-08-17T14:00:00",
            "ip_address": "198.51.100.1",
            "device_id": "device-missing",
            "browser": "Safari",
            "os": "iOS",
            "login_success": True,
            "failed_attempts": 0,
        },
        headers={"X-API-Key": "missing-key"},
    )
    assert response.status_code == 403
    assert "registered" in response.get_json()["error"].lower()


def test_application_can_be_created_via_admin_form_and_exposed_in_summary(client):
    _login_as_admin(client)
    response = client.post(
        "/admin/applications",
        data={
            "application_id": "phase8-form-app",
            "application_name": "Form App",
            "description": "Registered through the form",
            "owner": "admin",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    row = conn.execute(
        "SELECT application_id, application_name, owner FROM applications WHERE application_id=?",
        ("phase8-form-app",),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "phase8-form-app"
    assert row[1] == "Form App"
    assert row[2] == "admin"


def test_application_detail_shows_core_risk_stats(client):
    _login_as_admin(client)
    _create_application("phase8-risk", "Risk App", "risk-key")
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    conn.execute(
        "INSERT INTO auth_events (application_id, user_id, username, timestamp, ip_address, device_id, browser, os, event_type, login_success, failed_attempts, received_at, risk_level, prediction, model_probability, behavioural_score, confidence, behavioural_evidence, alert_created, reasons) VALUES (?, 'u1', 'bob', '2026-08-17T01:00:00', '10.0.0.4', 'd1', 'Chrome', 'Windows', 'login', 1, 0, datetime('now'), 'HIGH', 'Suspicious Login', 0.9, 0.7, 0.8, '[]', 1, '[\"high risk\"]')",
        ("phase8-risk",),
    )
    conn.execute(
        "INSERT INTO auth_events (application_id, user_id, username, timestamp, ip_address, device_id, browser, os, event_type, login_success, failed_attempts, received_at, risk_level, prediction, model_probability, behavioural_score, confidence, behavioural_evidence, alert_created, reasons) VALUES (?, 'u2', 'charlie', '2026-08-17T02:00:00', '10.0.0.5', 'd2', 'Chrome', 'Windows', 'login', 1, 0, datetime('now'), 'MEDIUM', 'Unusual Login', 0.6, 0.6, 0.7, '[]', 1, '[\"medium risk\"]')",
        ("phase8-risk",),
    )
    conn.commit()
    conn.close()

    response = client.get("/admin/applications/phase8-risk")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "bob" in html or "charlie" in html or "Risk App" in html
    assert "High Risk" in html or "Medium Risk" in html


def test_admin_application_routes_require_authenticated_admin(client):
    response = client.get("/admin/applications")
    assert response.status_code == 302
    response = client.get("/admin/applications/phase8-registry")
    assert response.status_code == 302
    response = client.post("/admin/applications/phase8-registry/rotate")
    assert response.status_code == 302
    response = client.get("/admin")
    assert response.status_code == 302


def test_api_key_hash_is_not_plaintext_and_matches_application(client):
    _create_application("phase8-hash", "Hash App", "hash-key")
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    row = conn.execute(
        "SELECT api_key_hash FROM applications WHERE application_id=?",
        ("phase8-hash",),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] != "hash-key"
    assert row[0] == _hash("hash-key")

    payload = {
        "application_id": "phase8-hash",
        "user_id": "U-6001",
        "timestamp": "2026-08-17T15:00:00",
        "ip_address": "192.0.2.10",
        "device_id": "device-hash",
        "browser": "Chrome",
        "os": "Linux",
        "login_success": True,
        "failed_attempts": 0,
    }
    response = client.post(
        "/api/v1/auth-events",
        json=payload,
        headers={"X-API-Key": "hash-key"},
    )
    assert response.status_code == 201
    assert response.get_json()["application_id"] == "phase8-hash"
