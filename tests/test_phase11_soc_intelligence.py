"""Phase 11 contract tests for real-time SOC intelligence additions."""
from app import app
from services.alert_service import build_alert_fingerprint
from services.incident_service import LIFECYCLE_TRANSITIONS


def test_deduplication_keeps_security_boundaries():
    base = build_alert_fingerprint("app-a", "user-a", "192.0.2.1", "device-a", "HIGH", "2026-08-17T10:01:00")
    assert base != build_alert_fingerprint("app-a", "user-a", "192.0.2.2", "device-a", "HIGH", "2026-08-17T10:01:00")
    assert base != build_alert_fingerprint("app-a", "user-b", "192.0.2.1", "device-a", "HIGH", "2026-08-17T10:01:00")
    assert base != build_alert_fingerprint("app-b", "user-a", "192.0.2.1", "device-a", "HIGH", "2026-08-17T10:01:00")
    assert base != build_alert_fingerprint("app-a", "user-a", "192.0.2.1", "device-a", "MEDIUM", "2026-08-17T10:01:00")


def test_triage_and_false_positive_lifecycle_is_explicit():
    assert "TRIAGED" in LIFECYCLE_TRANSITIONS["NEW"]
    assert "FALSE_POSITIVE" in LIFECYCLE_TRANSITIONS["NEW"]
    assert "FALSE_POSITIVE" in LIFECYCLE_TRANSITIONS["INVESTIGATING"]
    assert "NEW" not in LIFECYCLE_TRANSITIONS["RESOLVED"]


def test_soc_endpoints_require_admin_session():
    client = app.test_client()
    for path in ("/api/v1/soc/events", "/api/v1/soc/alerts", "/api/v1/soc/incidents", "/api/v1/applications"):
        assert client.get(path).status_code == 403
