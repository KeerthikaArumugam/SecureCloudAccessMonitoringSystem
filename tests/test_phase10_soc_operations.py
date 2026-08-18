"""Phase 10 SOC operations unit coverage for deterministic, non-synthetic logic."""
from services.alert_service import build_alert_fingerprint, derive_alert_severity
from services.incident_service import LIFECYCLE_TRANSITIONS


def test_alert_severity_is_deterministic_and_explainable():
    assert derive_alert_severity(.95, 95, ["New IP address"], 0, 1) == "CRITICAL"
    assert derive_alert_severity(.72, 30, [], 0, 0) == "HIGH"
    assert derive_alert_severity(.20, 20, ["New device"], 0, 0) == "MEDIUM"
    assert derive_alert_severity(.10, 10, [], 0, 0) == "LOW"


def test_alert_fingerprint_deduplicates_same_correlation_bucket():
    one = build_alert_fingerprint("app", "user", "192.0.2.1", "device", "HIGH", "2026-08-17T10:01:01")
    two = build_alert_fingerprint("app", "user", "192.0.2.1", "device", "HIGH", "2026-08-17T10:04:59")
    assert one == two


def test_incident_lifecycle_rejects_invalid_shortcuts():
    assert "ACKNOWLEDGED" in LIFECYCLE_TRANSITIONS["NEW"]
    assert "RESOLVED" not in LIFECYCLE_TRANSITIONS["NEW"]
    assert not LIFECYCLE_TRANSITIONS["CLOSED"]
