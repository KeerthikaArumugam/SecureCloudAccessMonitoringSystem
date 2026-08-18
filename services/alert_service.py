"""Deterministic, explainable alert intelligence for SOC authentication events."""
from __future__ import annotations

from hashlib import sha256
from datetime import datetime
from typing import Any, Mapping


def build_alert_key(username: str, timestamp: str, ip_address: str, device: str) -> str:
    return sha256("|".join(map(lambda v: str(v or "").strip(), (username, timestamp, ip_address, device))).encode("utf-8")).hexdigest()


def build_alert_fingerprint(application_id: str, user_id: str, ip_address: str, device_id: str, risk: str, timestamp: str) -> str:
    """Five-minute bucket makes retries idempotent without hiding later activity."""
    try:
        bucket_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).replace(second=0, microsecond=0)
        bucket = bucket_dt.replace(minute=(bucket_dt.minute // 5) * 5).isoformat()
    except (TypeError, ValueError):
        bucket = str(timestamp or "")[:16]
    return sha256("|".join(map(str, (application_id, user_id, ip_address, device_id, risk, bucket))).encode("utf-8")).hexdigest()


def derive_alert_severity(model_probability: float, threat_score: float, evidence: Any, failed_attempts: int = 0,
                          repeated_events: int = 0) -> str:
    """Critical needs strong model/risk evidence plus an anomaly; high needs either."""
    evidence_text = " ".join(evidence if isinstance(evidence, list) else [str(evidence or "")]).lower()
    anomaly_terms = ("new ip", "new device", "rapid", "failed", "off-hours", "time anomaly")
    anomalies = sum(term in evidence_text for term in anomaly_terms)
    probability, score = float(model_probability or 0), float(threat_score or 0)
    failures, repeats = int(failed_attempts or 0), int(repeated_events or 0)
    if (probability >= .90 or score >= 90) and (anomalies or failures >= 5 or repeats >= 3):
        return "CRITICAL"
    if probability >= .70 or score >= 70 or failures >= 5 or (anomalies >= 2 and repeats >= 2):
        return "HIGH"
    if probability >= .40 or score >= 40 or anomalies or failures >= 3 or repeats >= 2:
        return "MEDIUM"
    return "LOW"


def is_duplicate_alert(alert: Mapping[str, Any], existing_alerts) -> bool:
    key = str(alert.get("alert_fingerprint") or alert.get("alert_key") or "")
    return bool(key) and any(str(item.get("alert_fingerprint") or item.get("alert_key") or "") == key for item in existing_alerts)
