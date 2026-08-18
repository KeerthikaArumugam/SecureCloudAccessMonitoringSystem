import hashlib
import json
import os
import sqlite3
import time
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from urllib.parse import urlparse

from prediction.predict import predict_login
from services.feature_service import extract_login_features
from services.incident_service import create_or_update_incident
from services.alert_service import build_alert_fingerprint, derive_alert_severity
from utils.helpers import audit_log_action, create_security_alert

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database.db")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _safe_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256((raw_key or "").encode("utf-8")).hexdigest()


def _get_application_by_api_key(api_key: str) -> Optional[sqlite3.Row]:
    if not api_key:
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM applications WHERE api_key_hash=? AND status='active'",
        (_hash_api_key(api_key),),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _get_or_create_application(application_id: str, application_name: str, description: str = "") -> sqlite3.Row:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM applications WHERE application_id=?",
        (application_id,),
    )
    row = cursor.fetchone()
    if row is None:
        cursor.execute(
            """
            INSERT INTO applications (application_id, application_name, description, api_key_hash, status, created_at)
            VALUES (?, ?, ?, ?, 'active', datetime('now'))
            """,
            (application_id, application_name, description, _hash_api_key("placeholder")),
        )
        conn.commit()
        cursor.execute(
            "SELECT * FROM applications WHERE application_id=?",
            (application_id,),
        )
        row = cursor.fetchone()
    conn.close()
    return row


def _normalize_event(raw_event: Dict[str, Any], app_id: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(raw_event, dict):
        raise ValueError("Event payload must be an object.")

    payload_size = len(json.dumps(raw_event, separators=(",", ":"), default=str).encode("utf-8"))
    if payload_size > 65536:
        raise ValueError("Payload exceeds maximum allowed size.")

    application_id = str(raw_event.get("application_id") or "").strip()
    username = str(raw_event.get("username") or raw_event.get("user_id") or "").strip()
    user_id = str(raw_event.get("user_id") or username).strip()
    timestamp = str(raw_event.get("timestamp") or "").strip()
    ip_address = str(raw_event.get("ip_address") or "").strip()
    device_id = str(raw_event.get("device_id") or raw_event.get("device") or "").strip()
    browser = str(raw_event.get("browser") or "").strip()
    os_name = str(raw_event.get("os") or "").strip()
    user_agent = str(raw_event.get("user_agent") or "").strip()
    event_type = str(raw_event.get("event_type") or "login").strip().lower()
    login_success = _safe_bool(raw_event.get("success", raw_event.get("login_success", True)))
    failed_attempts = _safe_int(raw_event.get("failed_attempts", 0), 0)
    if not application_id:
        raise ValueError("application_id is required.")
    if not username:
        raise ValueError("username is required.")
    if not timestamp:
        raise ValueError("timestamp is required.")
    if not ip_address:
        raise ValueError("ip_address is required.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", application_id):
        raise ValueError("application_id is invalid.")
    if len(user_id) > 128 or len(username) > 128:
        raise ValueError("user_id or username exceeds supported length.")
    if event_type not in {"login", "logout", "signup", "token_refresh", "mfa", "password_reset"}:
        raise ValueError("event_type is invalid.")
    if len(ip_address) > 45:
        raise ValueError("ip_address is invalid.")
    try:
        __import__("ipaddress").ip_address(ip_address)
    except ValueError as exc:
        raise ValueError("ip_address is invalid.") from exc
    if not browser and user_agent:
        browser = "Unknown"
    if not os_name and user_agent:
        os_name = "Unknown"
    if len(device_id) > 128 or len(browser) > 64 or len(os_name) > 64 or len(user_agent) > 256:
        raise ValueError("device_id, browser, os, or user_agent exceeds supported length.")
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be in ISO 8601 format.") from exc
    if failed_attempts < 0:
        raise ValueError("failed_attempts cannot be negative.")
    if failed_attempts > 10000:
        raise ValueError("failed_attempts exceeds supported range.")

    if app_id:
        application_id = app_id
    return {
        "application_id": application_id,
        "user_id": user_id,
        "username": username,
        "timestamp": timestamp,
        "ip_address": ip_address,
        "device_id": device_id or "unknown-device",
        "browser": browser or "Unknown",
        "os": os_name or "Unknown",
        "user_agent": user_agent or "Unknown",
        "event_type": event_type,
        "login_success": login_success,
        "failed_attempts": failed_attempts,
    }


def process_auth_event(raw_event: Dict[str, Any], api_key: Optional[str] = None, allow_missing_application: bool = False) -> Dict[str, Any]:
    try:
        app_record = None
        if api_key:
            app_record = _get_application_by_api_key(api_key)
            if app_record is None:
                raise PermissionError("Invalid or revoked API key.")
        normalized = _normalize_event(raw_event, app_id=raw_event.get("application_id") if not app_record else app_record["application_id"])
        application_id = normalized["application_id"]
        if not allow_missing_application:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM applications WHERE application_id=?", (application_id,))
            if cursor.fetchone() is None:
                conn.close()
                raise LookupError("Application is not registered.")
            conn.close()

        event_timestamp = normalized["timestamp"]
        effective_dt = datetime.fromisoformat(event_timestamp.replace("Z", "+00:00"))
        login_event = {
            "application_id": application_id,
            "user_id": normalized["user_id"],
            "username": normalized["username"],
            "timestamp": event_timestamp,
            "ip_address": normalized["ip_address"],
            "device_id": normalized["device_id"],
            "browser": normalized["browser"],
            "os": normalized["os"],
            "user_agent": normalized["user_agent"],
            "event_type": normalized["event_type"],
            "login_success": normalized["login_success"],
            "failed_attempts": normalized["failed_attempts"],
            "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO auth_events (
                application_id, user_id, username, timestamp, ip_address, device_id, browser, os,
                user_agent, event_type, login_success, failed_attempts, received_at, risk_level,
                prediction, model_probability, behavioural_score, confidence, behavioural_evidence,
                alert_created, reasons, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'LOW', 'Normal Login', 0.0, 0.0, 0.0, '[]', 0, '[]', datetime('now'))
            """,
            (
                application_id,
                normalized["user_id"],
                normalized["username"],
                event_timestamp,
                normalized["ip_address"],
                normalized["device_id"],
                normalized["browser"],
                normalized["os"],
                normalized["user_agent"],
                normalized["event_type"],
                1 if normalized["login_success"] else 0,
                normalized["failed_attempts"],
                login_event["received_at"],
            ),
        )
        event_id = cursor.lastrowid
        conn.commit()

        user_code = int(hashlib.sha256(str(normalized["user_id"]).encode("utf-8")).hexdigest(), 16) % 10000
        browser = normalized["browser"] or "Unknown"
        device = normalized["device_id"] or "Unknown"
        hour = effective_dt.hour
        day = effective_dt.day
        month = effective_dt.month
        weekday = effective_dt.weekday()
        activity = 1 if normalized["login_success"] else 2
        behavioural_features = extract_login_features(
            username=normalized["username"],
            user_id=0,
            user_code=user_code,
            pc_id=0,
            ip_address=normalized["ip_address"],
            device=device,
            browser=browser,
            hour=hour,
            day=day,
            month=month,
            weekday=weekday,
        )

        prediction = predict_login(
            user=user_code,
            pc=0,
            activity=activity,
            hour=hour,
            day=day,
            month=month,
            weekday=weekday,
            behavioural_features=behavioural_features,
        )

        risk_level = prediction.get("risk", "LOW")
        threat_score = float(prediction.get("threat_score", 0.0))
        model_probability = float(prediction.get("model_probability", prediction.get("probability", 0.0)))
        behavioural_score = float(prediction.get("behavioural_score", 0.0))
        confidence = float(prediction.get("confidence", 0.0))
        reasons = prediction.get("reasons", [])
        behavioural_evidence = prediction.get("behavioural_evidence", [])

        # Severity is derived from the real model output and persisted behavioural
        # evidence; no presentation-layer or randomly generated scoring is used.
        repeated_events = conn.execute(
            "SELECT COUNT(*) FROM auth_events WHERE application_id=? AND username=? AND ip_address=? "
            "AND datetime(timestamp) >= datetime(?, '-10 minutes')",
            (application_id, normalized["username"], normalized["ip_address"], event_timestamp),
        ).fetchone()[0]
        alert_severity = derive_alert_severity(model_probability, threat_score, behavioural_evidence,
                                                normalized["failed_attempts"], repeated_events)
        alert_created = False
        if risk_level in {"MEDIUM", "HIGH"}:
            fingerprint = build_alert_fingerprint(application_id, normalized["user_id"], normalized["ip_address"],
                                                  normalized["device_id"], risk_level, event_timestamp)
            try:
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                conn.execute("""
                    INSERT INTO security_alerts (user_id, username, alert_type, prediction, alert_time, severity,
                      message, threat_score, created_at, status, application_id, event_id, ip_address, device_id, alert_fingerprint,
                      risk_level, model_probability, confidence, behavioural_evidence, reasons)
                    VALUES (?, ?, 'auth_event', ?, ?, ?, ?, ?, ?, 'New', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (normalized["user_id"], normalized["username"], prediction.get("prediction", "Suspicious Login"),
                      now_str, alert_severity, f"Authentication event from {application_id} flagged as {risk_level} risk",
                      threat_score, now_str, application_id, event_id, normalized["ip_address"], normalized["device_id"], fingerprint,
                      risk_level, model_probability, confidence, json.dumps(behavioural_evidence), json.dumps(reasons)))
                alert_created = True
            except sqlite3.IntegrityError:
                # Same source event in the same correlation bucket: intentionally idempotent.
                alert_created = False

        # Release the ingestion transaction before correlation opens its own
        # connection; SQLite permits one writer at a time.
        conn.commit()

        # Phase 9: Create or update incident for MEDIUM/HIGH events
        incident_id = None
        if risk_level in {"MEDIUM", "HIGH"}:
            incident_id = create_or_update_incident(
                application_id=application_id,
                event_id=event_id,
                username=normalized["username"],
                ip_address=normalized["ip_address"],
                risk_level=risk_level,
                event_timestamp=normalized["timestamp"],
                threat_score=threat_score,
                prediction=prediction.get("prediction", "Suspicious Login"),
                reasons=reasons,
                confidence=confidence,
            )
        if incident_id:
            conn.execute("UPDATE security_alerts SET incident_id=? WHERE event_id=?", (incident_id, event_id))

        cursor.execute(
            """
            UPDATE auth_events
            SET risk_score=?, risk_level=?, prediction=?, model_probability=?, behavioural_score=?, confidence=?, behavioural_evidence=?, alert_created=?, reasons=?
            WHERE id = ?
            """,
            (
                threat_score,
                risk_level,
                prediction.get("prediction", "Normal Login"),
                model_probability,
                behavioural_score,
                confidence,
                json.dumps(behavioural_evidence),
                1 if alert_created else 0,
                json.dumps(reasons),
                event_id,
            ),
        )

        cursor.execute(
            """
            UPDATE applications
            SET last_event_at=?, total_events = total_events + 1,
                high_risk_events = high_risk_events + ?,
                medium_risk_events = medium_risk_events + ?,
                low_risk_events = low_risk_events + ?
            WHERE application_id=?
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                1 if risk_level == "HIGH" else 0,
                1 if risk_level == "MEDIUM" else 0,
                1 if risk_level == "LOW" else 0,
                application_id,
            ),
        )
        conn.commit()

        audit_log_action(
            user_id=0,
            username=normalized["username"],
            action="auth_event_ingested",
            ip_address=normalized["ip_address"],
            description=f"Authentication event accepted for application {application_id}; risk={risk_level}; score={threat_score}",
        )
        conn.close()

        response = {
            "success": True,
            "event_id": event_id,
            "application_id": application_id,
            "risk": risk_level,
            "risk_level": risk_level,
            "threat_score": round(threat_score, 1),
            "confidence": round(confidence, 1),
            "prediction": prediction.get("prediction", "Normal Login"),
            "model_probability": round(model_probability, 4),
            "behavioural_score": round(behavioural_score, 1),
            "alert_created": alert_created,
            "incident_id": incident_id,
            "reasons": reasons,
        }
        return response
    except Exception as exc:  # pragma: no cover - final API layer handles details
        raise exc
