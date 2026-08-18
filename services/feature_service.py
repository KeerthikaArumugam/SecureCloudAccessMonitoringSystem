"""
services/feature_service.py — Phase 6 behavioural feature engineering

This module computes only historical behaviour available before the current login
attempt. It intentionally avoids using future events or a target label to define
risk features.
"""
import json
import math
import sqlite3
from typing import Any, List


def _safe_json_list(value: Any) -> List[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError, json.JSONDecodeError):
        return []


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _parse_login_time(value: Any) -> tuple[int, int, int] | None:
    if not value:
        return None
    try:
        if isinstance(value, str):
            ts = value.strip()
            if " " in ts:
                ts = ts.split(" ")[-1]
            parts = ts.split(":")
            if len(parts) >= 3:
                return int(parts[0]), int(parts[1]), int(parts[2])
            if len(parts) >= 2:
                return int(parts[0]), int(parts[1]), 0
    except (TypeError, ValueError):
        return None
    return None


def extract_login_features(username, user_id, user_code, pc_id,
                           ip_address, device, browser,
                           hour, day, month, weekday):
    """Return behavioural features derived only from historical login activity."""
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, login_date, login_time, ip_address, browser, device, risk, prediction, status
        FROM login_logs
        WHERE username=? AND login_time IS NOT NULL
        ORDER BY id DESC
        LIMIT 180
        """,
        (username,),
    )
    history = cursor.fetchall()

    cursor.execute(
        "SELECT user_ips, user_devices, last_login_at, total_logins FROM users WHERE id=?",
        (user_id,),
    )
    user_row = cursor.fetchone()
    conn.close()

    known_ips = []
    known_devices = []
    known_browsers = []
    total_logins = 0

    if user_row:
        known_ips = _safe_json_list(user_row["user_ips"])
        known_devices = _safe_json_list(user_row["user_devices"])
        total_logins = int(user_row["total_logins"] or 0)

    history_ips = [row["ip_address"] for row in history if row["ip_address"]]
    history_devices = [row["device"] for row in history if row["device"]]
    history_browsers = [row["browser"] for row in history if row["browser"]]
    recent_failures = sum(1 for row in history if str(row["status"]).lower() in {"failed", "suspicious"})
    recent_successes = sum(1 for row in history if str(row["status"]).lower() == "normal")
    recent_high_risk_count = sum(1 for row in history if str(row["risk"]).upper() in {"MEDIUM", "HIGH"})

    is_new_ip = bool(ip_address and ip_address not in known_ips and ip_address not in history_ips)
    is_new_device = bool(device and device not in known_devices and device not in history_devices)
    is_new_browser = bool(browser and browser not in known_browsers and browser not in history_browsers)
    first_seen_device = int(device and device not in history_devices)
    first_seen_ip = int(ip_address and ip_address not in history_ips)
    first_seen_browser = int(browser and browser not in history_browsers)

    past_hours = []
    previous_login_times = []
    for row in history:
        parsed = _parse_login_time(row["login_time"])
        if parsed is not None:
            past_hours.append(parsed[0])
            previous_login_times.append(parsed[0])

    time_anomaly_score = 0.0
    user_typical_hour = float(sum(past_hours) / len(past_hours)) if past_hours else float(hour)
    if past_hours:
        variance = sum((h - user_typical_hour) ** 2 for h in past_hours) / len(past_hours)
        std_hour = math.sqrt(variance) if variance > 0 else 1.0
        z_score = abs(hour - user_typical_hour) / max(std_hour, 1.0)
        time_anomaly_score = round(min(z_score / 3.0, 1.0), 3)

    off_hours_flag = int((hour < 6) or (hour > 22))
    weekend_flag = int(weekday >= 5)
    rapid_login_flag = 0
    hours_since_last_login = 0.0
    if history:
        last_t = _parse_login_time(history[0]["login_time"])
        if last_t is not None:
            hours_since_last_login = max(0.0, abs(hour - last_t[0]))
            rapid_login_flag = int(hours_since_last_login <= 1)

    login_count_last_24h = 0
    login_count_last_7d = 0
    if history:
        for row in history:
            login_date = row["login_date"]
            login_time = row["login_time"]
            if login_date and login_time:
                # simple historical count using event ordering only; no future data is used
                login_count_last_24h += 1
                login_count_last_7d += 1

    ip_frequency = float(sum(1 for row in history if row["ip_address"] == ip_address) / max(1, len(history)))
    device_frequency = float(sum(1 for row in history if row["device"] == device) / max(1, len(history)))
    device_trust_score = 1.0 if device and device in known_devices else 0.35 if device else 0.0
    user_login_frequency = float(len(history) / max(1, total_logins or len(history)))

    failed_recently = recent_failures
    failure_signal = min(failed_recently / 5.0, 1.0)
    new_device_and_new_ip = int(is_new_device and is_new_ip)
    recent_failed_login_flag = int(failed_recently >= 2)
    new_ip_after_failed_attempts = int(is_new_ip and failed_recently >= 1)
    user_hour_anomaly = float(time_anomaly_score)
    unusual_user_activity = int(time_anomaly_score > 0.5 or off_hours_flag)

    behavioural_anomaly_score = round(
        0.22 * float(is_new_ip) +
        0.18 * float(is_new_device) +
        0.10 * float(is_new_browser) +
        0.16 * time_anomaly_score +
        0.12 * failure_signal +
        0.10 * float(rapid_login_flag) +
        0.08 * float(off_hours_flag) +
        0.04 * float(weekend_flag) +
        0.10 * min(1.0, login_count_last_24h / 5.0),
        3,
    )

    behaviour_score = round(min(max(behavioural_anomaly_score, 0.0), 1.0), 3)

    reasons: List[str] = []
    if is_new_ip:
        reasons.append(f"New IP address detected: {ip_address}")
    if is_new_device:
        reasons.append(f"New device detected: {device}")
    if is_new_browser:
        reasons.append(f"New browser detected: {browser}")
    if time_anomaly_score > 0.4:
        reasons.append("Login time differs from the user's normal pattern")
    if off_hours_flag:
        reasons.append("Login occurred outside the normal business-hours window")
    if rapid_login_flag:
        reasons.append("Recent rapid login activity detected")
    if failed_recently >= 2:
        reasons.append(f"{failed_recently} recent failed or suspicious logins were observed")

    return {
        "is_new_ip": is_new_ip,
        "is_new_device": is_new_device,
        "is_new_browser": is_new_browser,
        "first_seen_device": first_seen_device,
        "first_seen_ip": first_seen_ip,
        "first_seen_browser": first_seen_browser,
        "failed_attempts_recent": failed_recently,
        "successful_attempts_recent": recent_successes,
        "login_count_last_24h": login_count_last_24h,
        "login_count_last_7d": login_count_last_7d,
        "time_since_previous_login": hours_since_last_login,
        "user_typical_hour": user_typical_hour,
        "user_hour_anomaly": user_hour_anomaly,
        "device_change_frequency": 1.0 if is_new_device else 0.0,
        "ip_change_frequency": 1.0 if is_new_ip else 0.0,
        "ip_frequency": ip_frequency,
        "device_frequency": device_frequency,
        "device_trust_score": device_trust_score,
        "user_login_frequency": user_login_frequency,
        "hours_since_last_login": hours_since_last_login,
        "rapid_login_flag": rapid_login_flag,
        "off_hours_flag": off_hours_flag,
        "new_device_and_new_ip": new_device_and_new_ip,
        "new_ip_after_failed_attempts": new_ip_after_failed_attempts,
        "unusual_user_activity": unusual_user_activity,
        "recent_high_risk_count": recent_high_risk_count,
        "historical_user_risk": min(1.0, recent_high_risk_count / 5.0),
        "time_anomaly_score": time_anomaly_score,
        "behaviour_score": behaviour_score,
        "behavioural_anomaly_score": behaviour_score,
        "failure_signal": failure_signal,
        "failed_recently": failed_recently,
        "behavioural_evidence": reasons,
        "reasons": reasons,
    }
