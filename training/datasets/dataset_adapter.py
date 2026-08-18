"""Normalization layer for external authentication/security datasets.

This project does not ship a real world cyber dataset by default. The adapter is
provided so a genuine labelled security-authentication dataset may be imported into
this project without changing the application contract.
"""
from __future__ import annotations

import pandas as pd


def normalize_security_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize an external authentication dataset into the project's schema.

    The normalized schema intentionally matches the terminology used by the app:
    user, timestamp, ip_address, device, browser, activity, authentication_result,
    target.
    """
    if df is None:
        raise ValueError("A dataset DataFrame is required.")

    normalized = df.copy()
    normalized.columns = [str(c).strip() for c in normalized.columns]

    column_map = {
        "username": "user",
        "user": "user",
        "user_id": "user",
        "timestamp": "timestamp",
        "login_time": "timestamp",
        "datetime": "timestamp",
        "ip": "ip_address",
        "ip_address": "ip_address",
        "src_ip": "ip_address",
        "device": "device",
        "user_agent": "browser",
        "browser": "browser",
        "activity": "activity",
        "event_type": "activity",
        "authentication_result": "authentication_result",
        "result": "authentication_result",
        "outcome": "authentication_result",
        "label": "target",
        "target": "target",
        "is_suspicious": "target",
        "suspicious": "target",
        "malicious": "target",
    }

    renamed = normalized.rename(columns=column_map)

    for col in ["user", "timestamp", "ip_address", "device", "browser", "activity", "authentication_result"]:
        if col not in renamed.columns:
            renamed[col] = None

    if "target" not in renamed.columns:
        if "authentication_result" in renamed.columns:
            renamed["target"] = renamed["authentication_result"].map({
                "success": 0,
                "normal": 0,
                "benign": 0,
                "failure": 1,
                "failed": 1,
                "suspicious": 1,
                "malicious": 1,
                "attack": 1,
            }).fillna(0)
        else:
            renamed["target"] = 0

    renamed["target"] = renamed["target"].astype(int)
    renamed["user"] = renamed["user"].fillna("unknown").astype(str)
    renamed["ip_address"] = renamed["ip_address"].fillna("unknown").astype(str)
    renamed["device"] = renamed["device"].fillna("unknown").astype(str)
    renamed["browser"] = renamed["browser"].fillna("unknown").astype(str)
    renamed["activity"] = renamed["activity"].fillna("login").astype(str)
    renamed["authentication_result"] = renamed["authentication_result"].fillna("unknown").astype(str)

    if "timestamp" in renamed.columns:
        renamed["timestamp"] = pd.to_datetime(renamed["timestamp"], errors="coerce")
    else:
        renamed["timestamp"] = pd.NaT

    normalized_schema = [
        "user",
        "timestamp",
        "ip_address",
        "device",
        "browser",
        "activity",
        "authentication_result",
        "target",
    ]
    for col in normalized_schema:
        if col not in renamed.columns:
            renamed[col] = None
    return renamed[normalized_schema]
