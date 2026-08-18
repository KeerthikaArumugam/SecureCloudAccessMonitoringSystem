import json
import os
import sqlite3
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from prediction.predict import predict_login
from services.alert_service import build_alert_key, is_duplicate_alert
from training.datasets.dataset_adapter import normalize_security_dataset


class TestDatasetAdapter:
    def test_normalize_security_dataset(self):
        raw = pd.DataFrame([
            {
                "user": "alice",
                "timestamp": "2026-01-01 09:00:00",
                "ip_address": "10.0.0.1",
                "device": "Laptop",
                "browser": "Chrome",
                "activity": "login",
                "authentication_result": "success",
                "target": 0,
            }
        ])
        out = normalize_security_dataset(raw)
        assert set(["user", "timestamp", "ip_address", "device", "browser", "activity", "authentication_result", "target"]).issubset(out.columns)
        assert out.iloc[0]["target"] == 0

    def test_dataset_audit_report_exists(self):
        path = os.path.join("training", "datasets", "README.md")
        assert os.path.exists(path), "Dataset audit report missing"
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read().lower()
        assert "dataset audit" in text or "audit" in text
        assert "synthetic" in text or "real" in text


class TestPhase5PredictionContract:
    def test_prediction_output_schema(self):
        result = predict_login(
            user=5,
            pc=105,
            activity=3,
            hour=10,
            day=15,
            month=8,
            weekday=1,
            behavioural_features={
                "is_new_ip": False,
                "is_new_device": False,
                "time_anomaly_score": 0.1,
                "failure_signal": 0.0,
                "failed_recently": 0,
                "behavioural_evidence": ["Known IP", "Known device"],
            },
        )
        for key in ["prediction", "probability", "risk", "threat_score", "confidence", "behavioural_evidence", "reasons"]:
            assert key in result, f"Missing key: {key}"
        assert 0.0 <= result["probability"] <= 1.0
        assert 0 <= result["threat_score"] <= 100

    def test_no_hardcoded_scores_or_confidence(self):
        values = []
        for case in [
            dict(user=5, pc=105, activity=3, hour=10, day=15, month=8, weekday=1,
                 behavioural_features={"is_new_ip": False, "is_new_device": False,
                                       "time_anomaly_score": 0.0, "failure_signal": 0.0,
                                       "failed_recently": 0}),
            dict(user=5, pc=105, activity=3, hour=2, day=15, month=8, weekday=6,
                 behavioural_features={"is_new_ip": True, "is_new_device": True,
                                       "time_anomaly_score": 0.9, "failure_signal": 0.8,
                                       "failed_recently": 4}),
        ]:
            out = predict_login(**case)
            values.append((out["threat_score"], out["confidence"]))
        assert len({round(x[0], 1) for x in values}) > 1
        assert len({round(x[1], 1) for x in values}) > 1


class TestDatasetAndMetadata:
    def test_model_metadata_has_dataset_and_split_fields(self):
        with open("models/model_metadata.json", "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        for key in ["dataset_source", "target_definition", "split_strategy", "calibration_method"]:
            assert key in meta, f"Missing metadata key: {key}"

    def test_no_target_proxy_columns_in_training_matrix(self):
        df = pd.read_csv("dataset/final_training_dataset.csv")
        assert "hour" not in df.columns
        assert "weekday" not in df.columns


class TestAlertDeduplication:
    def test_duplicate_alerts_are_prevented(self):
        key1 = build_alert_key("alice", "2026-01-01 10:20:00", "10.0.0.1", "Laptop")
        key2 = build_alert_key("alice", "2026-01-01 10:20:00", "10.0.0.1", "Laptop")
        assert key1 == key2
        assert is_duplicate_alert({"alert_key": key1}, [{"alert_key": key1}]) is True
        assert is_duplicate_alert({"alert_key": key1}, [{"alert_key": "different"}]) is False
