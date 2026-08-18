import hashlib
import json
import os
import sqlite3
import tempfile

import pytest

import app as flask_app_module
from app import app, API_RATE_LIMIT_BUCKETS
from database.database import create_database
from services import auth_event_service
from services import incident_service
from services.auth_event_service import process_auth_event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    create_database(path)
    return path


@pytest.fixture()
def api_app(db_path):
    app.config.update(TESTING=True, API_RATE_LIMIT_PER_MINUTE=1000)
    # Redirect every module that holds its own DB_PATH to the temp database
    flask_app_module.DB_PATH = db_path
    auth_event_service.DB_PATH = db_path
    incident_service.DB_PATH = db_path
    # Clear rate-limit state between tests
    API_RATE_LIMIT_BUCKETS.clear()
    with app.app_context():
        yield app
    API_RATE_LIMIT_BUCKETS.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_api_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _create_app_record(application_id="student-portal", name="Student Portal", api_key="demo-key-123"):
    """Insert a fresh application record into the current (temp) DB_PATH."""
    db = flask_app_module.DB_PATH
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    # Always upsert so stale state from the real DB never bleeds in
    cursor.execute("SELECT id FROM applications WHERE application_id=?", (application_id,))
    if cursor.fetchone():
        cursor.execute(
            "UPDATE applications SET api_key_hash=?, status='active' WHERE application_id=?",
            (_hash_api_key(api_key), application_id),
        )
    else:
        cursor.execute(
            """
            INSERT INTO applications (application_id, application_name, description, api_key_hash, status, created_at)
            VALUES (?, ?, ?, ?, 'active', datetime('now'))
            """,
            (application_id, name, "Demo app", _hash_api_key(api_key)),
        )
    conn.commit()
    conn.close()
    return application_id, api_key


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_valid_api_key_event_ingestion(api_app):
    application_id, api_key = _create_app_record()
    client = api_app.test_client()
    payload = {
        "application_id": application_id,
        "user_id": "U1001",
        "timestamp": "2026-08-17T10:30:00",
        "ip_address": "192.168.1.20",
        "device_id": "device-abc123",
        "browser": "Chrome",
        "os": "Windows",
        "login_success": True,
        "failed_attempts": 0,
    }
    response = client.post(
        "/api/v1/auth-events",
        json=payload,
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    data = response.get_json()
    assert "event_id" in data
    assert data["application_id"] == application_id
    assert data["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
    assert "threat_score" in data


def test_invalid_api_key_rejected(api_app):
    _create_app_record()
    client = api_app.test_client()
    response = client.post(
        "/api/v1/auth-events",
        json={
            "application_id": "student-portal",
            "user_id": "U1002",
            "timestamp": "2026-08-17T10:35:00",
            "ip_address": "192.168.1.21",
            "device_id": "device-xyz",
            "browser": "Safari",
            "os": "macOS",
            "login_success": True,
            "failed_attempts": 0,
        },
        headers={"X-API-Key": "wrong-key"},
    )
    assert response.status_code == 401


def test_missing_required_fields_rejected(api_app):
    _create_app_record()
    client = api_app.test_client()
    response = client.post(
        "/api/v1/auth-events",
        json={"application_id": "student-portal", "user_id": "U1003"},
        headers={"X-API-Key": "demo-key-123"},
    )
    assert response.status_code == 400


def test_api_key_not_stored_plaintext(api_app):
    application_id, api_key = _create_app_record(application_id="portal-plain", api_key="secret-api-key")
    conn = sqlite3.connect(flask_app_module.DB_PATH)
    row = conn.execute(
        "SELECT api_key_hash FROM applications WHERE application_id=?",
        (application_id,),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] != api_key
    assert row[0] == _hash_api_key(api_key)


def test_rate_limit_exceeded(api_app):
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 1
    API_RATE_LIMIT_BUCKETS.clear()
    _create_app_record(application_id="portal-rate", api_key="rate-key")
    client = api_app.test_client()
    payload = {
        "application_id": "portal-rate",
        "user_id": "U2001",
        "timestamp": "2026-08-17T10:40:00",
        "ip_address": "192.168.1.40",
        "device_id": "device-rate",
        "browser": "Chrome",
        "os": "Linux",
        "login_success": True,
        "failed_attempts": 0,
    }
    first = client.post("/api/v1/auth-events", json=payload, headers={"X-API-Key": "rate-key"})
    second = client.post("/api/v1/auth-events", json=payload, headers={"X-API-Key": "rate-key"})
    assert first.status_code == 201
    assert second.status_code == 429


def test_process_auth_event_returns_real_pipeline_result(api_app):
    _create_app_record()
    result = process_auth_event(
        {
            "application_id": "student-portal",
            "user_id": "U1001",
            "timestamp": "2026-08-17T10:45:00",
            "ip_address": "10.0.0.15",
            "device_id": "device-demo",
            "browser": "Chrome",
            "os": "Windows",
            "login_success": True,
            "failed_attempts": 0,
        },
        api_key="demo-key-123",
        allow_missing_application=False,
    )
    assert "risk_level" in result
    assert "threat_score" in result
    assert "prediction" in result
    assert "reasons" in result
