"""Real probability-based login threat scoring.

This module intentionally does not fabricate scores. It loads the trained model and
reports only the model probability for the suspicious class, together with
measurable behavioural features that are available at login time.
"""
import json
import os
from typing import Any

import joblib
import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_PATH = os.path.join(ROOT_DIR, "models", "random_forest_model.pkl")
_META_PATH = os.path.join(ROOT_DIR, "models", "model_metadata.json")

MODEL_VERSION = "unknown"
MODEL_FEATURES = ["user", "pc", "activity", "day", "month"]
THRESHOLD_MEDIUM = 40.0
THRESHOLD_HIGH = 70.0

try:
    model = joblib.load(_MODEL_PATH)
except Exception:
    model = None

try:
    with open(_META_PATH, "r", encoding="utf-8") as f:
        _META = json.load(f)
    MODEL_VERSION = str(_META.get("version", MODEL_VERSION))
    if isinstance(_META.get("features"), list) and _META["features"]:
        MODEL_FEATURES = list(_META["features"])
    thresholds = _META.get("thresholds", {})
    if isinstance(thresholds, dict):
        if "medium" in thresholds:
            THRESHOLD_MEDIUM = float(thresholds["medium"])
        if "high" in thresholds:
            THRESHOLD_HIGH = float(thresholds["high"])
except Exception:
    _META = {}


def _time_score(hour: int, weekday: int) -> float:
    """Return a behavioural anomaly score from the runtime time context."""
    working_hours = 1 if 8 <= hour <= 18 else 0
    weekend = 1 if weekday >= 5 else 0
    anomaly = 0.0
    if not working_hours and hour < 6:
        anomaly = 90.0
    elif not working_hours and hour > 22:
        anomaly = 85.0
    elif weekend and not working_hours:
        anomaly = 75.0
    elif not working_hours:
        anomaly = 55.0
    elif weekend:
        anomaly = 30.0
    return anomaly


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _risk_from_probability(probability: float) -> str:
    score = min(max(probability * 100.0, 0.0), 100.0)
    if score >= THRESHOLD_HIGH:
        return "HIGH"
    if score >= THRESHOLD_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _build_feature_scores(new_ip_score, new_device_score, time_hist_score, failure_signal,
                         is_new_ip, is_new_device, hour, weekday) -> dict:
    """Return a structured dict of per-dimension risk assessments."""

    def level(score):
        if score >= 65:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    net_score = round(new_ip_score, 1)
    time_score = round(_time_score(hour, weekday) * 0.7 + time_hist_score * 100.0 * 0.3, 1)
    dev_score = round(new_device_score, 1)
    beh_score = round(min(max((time_hist_score * 100.0) * 0.5 + failure_signal * 100.0 * 0.5, 0.0), 100.0), 1)

    return {
        "network": {
            "score": net_score,
            "level": level(net_score),
            "reason": "Login from a new IP address." if is_new_ip else "Login from a known IP address.",
        },
        "time": {
            "score": time_score,
            "level": level(time_score),
            "reason": "Login time differs from normal behaviour." if time_score >= 40 else "Login time is consistent with normal behaviour.",
        },
        "device": {
            "score": dev_score,
            "level": level(dev_score),
            "reason": "Login from a new device." if is_new_device else "Login from a known device.",
        },
        "behaviour": {
            "score": beh_score,
            "level": level(beh_score),
            "reason": "Behaviour deviates from past activity." if beh_score >= 40 else "Behaviour is aligned with historical patterns.",
        },
    }


def predict_login(user: int, pc: int, activity: int,
                  hour: int, day: int, month: int, weekday: int,
                  behavioural_features: dict | None = None) -> dict:
    """Return a real probability-based login risk prediction."""
    bf = behavioural_features or {}

    if model is None:
        return {
            "prediction": "Normal Login",
            "risk": "LOW",
            "model_probability": 0.0,
            "calibrated_probability": 0.0,
            "probability": 0.0,
            "threat_score": 0.0,
            "behavioural_score": 0.0,
            "confidence": 0.0,
            "model_component": 0.0,
            "reasons": ["Model artifact is unavailable."],
            "model_version": MODEL_VERSION,
            "feature_scores": {},
            "behavioural_evidence": [],
        }

    feature_frame = pd.DataFrame([{
        "user": user,
        "pc": pc,
        "activity": activity,
        "day": day,
        "month": month,
    }])

    valid_columns = [c for c in MODEL_FEATURES if c in feature_frame.columns]
    if valid_columns:
        feature_frame = feature_frame[valid_columns]

    proba = model.predict_proba(feature_frame)[0]
    suspicious_probability = float(proba[1]) if len(proba) > 1 else float(proba[0])
    predicted_label = 1 if suspicious_probability >= 0.5 else 0
    confidence = float(suspicious_probability if predicted_label == 1 else 1.0 - suspicious_probability) * 100.0

    is_new_ip = bool(bf.get("is_new_ip", False))
    is_new_device = bool(bf.get("is_new_device", False))
    is_new_browser = bool(bf.get("is_new_browser", False))
    time_hist_score = _safe_float(bf.get("time_anomaly_score", 0.0))
    failure_signal = _safe_float(bf.get("failure_signal", 0.0))
    failure_raw = int(bf.get("failed_recently", 0) or 0)
    behavioural_anomaly_score = _safe_float(bf.get("behavioural_anomaly_score", 0.0))
    off_hours_flag = int(bf.get("off_hours_flag", 0) or 0)
    rapid_login_flag = int(bf.get("rapid_login_flag", 0) or 0)
    behavioural_score = _safe_float(bf.get("behaviour_score", behavioural_anomaly_score))

    new_ip_score = 100.0 if is_new_ip else 0.0
    new_device_score = 100.0 if is_new_device else 0.0

    behavioural_bonus = 0.0
    behavioural_bonus += 18.0 if is_new_ip else 0.0
    behavioural_bonus += 14.0 if is_new_device else 0.0
    behavioural_bonus += 6.0 if is_new_browser else 0.0
    behavioural_bonus += time_hist_score * 25.0
    behavioural_bonus += failure_signal * 22.0
    behavioural_bonus += behavioural_anomaly_score * 15.0
    behavioural_bonus += 10.0 if off_hours_flag else 0.0
    behavioural_bonus += 8.0 if rapid_login_flag else 0.0
    behavioural_bonus = min(behavioural_bonus, 35.0)

    threat_score = round(min(max((suspicious_probability * 100.0) + behavioural_bonus, 0.0), 100.0), 1)
    risk = _risk_from_probability(suspicious_probability)
    if threat_score >= THRESHOLD_HIGH:
        risk = "HIGH"
    elif threat_score >= THRESHOLD_MEDIUM:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    prediction = "Suspicious Login" if risk in {"HIGH", "MEDIUM"} else "Normal Login"

    runtime_time_score = _time_score(hour, weekday)
    behavioural_evidence = []
    if is_new_ip:
        behavioural_evidence.append("New IP")
    if is_new_device:
        behavioural_evidence.append("New device")
    if is_new_browser:
        behavioural_evidence.append("New browser")
    if runtime_time_score >= 60 or time_hist_score > 0.6:
        behavioural_evidence.append("Unusual login time")
    if failure_raw >= 1:
        behavioural_evidence.append("Recent failed attempts")
    if rapid_login_flag:
        behavioural_evidence.append("Rapid login activity")
    if not behavioural_evidence:
        behavioural_evidence = ["Known device and IP", "Login time matches history"]

    reasons = []
    if hour < 6:
        reasons.append("Login occurred before 6 AM")
    elif hour > 22:
        reasons.append("Login occurred after 10 PM")
    elif 8 <= hour <= 18 and weekday < 5:
        reasons.append("Login occurred during expected business hours")
    if weekday >= 5:
        reasons.append("Weekend login activity detected")
    if is_new_ip:
        reasons.append("New or unusual IP address detected")
    if is_new_device:
        reasons.append("New device detected")
    if is_new_browser:
        reasons.append("New browser detected")
    if runtime_time_score >= 60:
        reasons.append("Time-of-day deviates from historical behaviour")
    if time_hist_score > 0.6:
        reasons.append("Login time differs from the user's usual pattern")
    if off_hours_flag:
        reasons.append("Login occurred outside the usual business-hours window")
    if rapid_login_flag:
        reasons.append("Rapid login activity was detected")
    if failure_raw >= 3:
        reasons.append(f"{failure_raw} recent failed or suspicious attempts were observed")
    elif failure_raw >= 1:
        reasons.append(f"Recent failed login attempts were observed ({failure_raw})")
    if not reasons:
        reasons.append("No strong risk indicators were detected from the login context")

    feature_scores = _build_feature_scores(
        new_ip_score=new_ip_score,
        new_device_score=new_device_score,
        time_hist_score=time_hist_score,
        failure_signal=failure_signal,
        is_new_ip=is_new_ip,
        is_new_device=is_new_device,
        hour=hour,
        weekday=weekday,
    )

    evidence_strength = min(1.0, (
        (1.0 if is_new_ip else 0.0) * 0.30 +
        (1.0 if is_new_device else 0.0) * 0.25 +
        (1.0 if is_new_browser else 0.0) * 0.10 +
        min(1.0, time_hist_score) * 0.20 +
        min(1.0, failure_signal) * 0.15
    ))
    calibrated_probability = min(1.0, max(0.0, suspicious_probability * 0.75 + evidence_strength * 0.25))
    confidence = round(min(max((calibrated_probability * 100.0), 0.0), 100.0), 1)

    return {
        "prediction": prediction,
        "risk": risk,
        "model_probability": round(suspicious_probability, 6),
        "calibrated_probability": round(calibrated_probability, 6),
        "probability": round(calibrated_probability, 6),
        "threat_score": round(threat_score, 1),
        "behavioural_score": round(behavioural_score * 100.0, 1),
        "confidence": confidence,
        "model_component": round(suspicious_probability * 100.0, 1),
        "reasons": reasons,
        "model_version": MODEL_VERSION,
        "feature_scores": feature_scores,
        "behavioural_evidence": behavioural_evidence,
    }


__all__ = ["predict_login", "MODEL_VERSION", "THRESHOLD_MEDIUM", "THRESHOLD_HIGH", "MODEL_FEATURES"]

