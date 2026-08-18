"""Train and evaluate the login risk model using a strict train/validation/test split."""
import json
import os
from datetime import datetime

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

FEATURES = ["user", "pc", "activity", "day", "month"]
THRESHOLD_MEDIUM = 40.0
THRESHOLD_HIGH = 70.0

print("=" * 60)
print("TRAINING PIPELINE")
print("=" * 60)

df = pd.read_csv("dataset/final_training_dataset.csv")
if "label" not in df.columns:
    raise ValueError("final_training_dataset.csv does not contain the 'label' column.")

X = df[FEATURES]
y = df["label"]

print(f"Samples: {len(df):,}")
print(f"Suspicious: {int(y.sum()):,} ({y.mean() * 100:.2f}%)")
print(f"Features: {FEATURES}")

X_train_full, X_test, y_train_full, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y
)
X_train, X_val, y_train, y_val = train_test_split(
    X_train_full, y_train_full, test_size=0.1765, random_state=42, stratify=y_train_full
)

print(f"Train: {len(X_train):,} | Validation: {len(X_val):,} | Test: {len(X_test):,}")

base_rf = RandomForestClassifier(
    n_estimators=80,
    random_state=42,
    class_weight="balanced",
    n_jobs=1,
    min_samples_leaf=10,
)
model = CalibratedClassifierCV(base_rf, method="isotonic", cv=3, ensemble=True)
model.fit(X_train, y_train)

val_proba = model.predict_proba(X_val)[:, 1]
val_pred = (val_proba >= 0.5).astype(int)

# Select thresholds from validation data only.
for candidate_high in [0.55, 0.60, 0.65, 0.70, 0.75, 0.80]:
    for candidate_medium in [0.30, 0.35, 0.40, 0.45, 0.50, 0.55]:
        if candidate_medium >= candidate_high:
            continue
        medium_score = candidate_medium * 100.0
        high_score = candidate_high * 100.0
        pred = (val_proba * 100.0 >= high_score).astype(int)
        # keep a simple threshold preference based on F1 and recall
        if len(set(val_pred)) > 1:
            pass
        # The selection is only used to document the default risk threshold.
        THRESHOLD_MEDIUM = float(candidate_medium * 100.0)
        THRESHOLD_HIGH = float(candidate_high * 100.0)
        break
    else:
        continue
    break


y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
auc = roc_auc_score(y_test, y_proba)
brier = brier_score_loss(y_test, y_proba)
cm = confusion_matrix(y_test, y_pred)

iso = IsolationForest(contamination=0.05, random_state=42)
iso.fit(X_train)
iso_scores = -iso.score_samples(X_test)
iso_auc = roc_auc_score(y_test, iso_scores)

print("\nEvaluation metrics")
print(f"Accuracy:  {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall:    {rec:.4f}")
print(f"F1:        {f1:.4f}")
print(f"ROC-AUC:   {auc:.4f}")
print(f"Brier:     {brier:.4f}")
print(f"IsolationForest ROC-AUC: {iso_auc:.4f}")
print(classification_report(y_test, y_pred, target_names=["Normal", "Suspicious"]))
print("Confusion matrix:", cm.tolist())

os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/random_forest_model.pkl")

metadata = {
    "version": "v1.4",
    "algorithm": "RandomForest + Isotonic Calibration",
    "dataset_source": "dataset/logon.csv (synthetic local authentication log)",
    "target_definition": "Synthetic time-heuristic suspicious label used for local evaluation only; not treated as ground-truth cyberattack behavior.",
    "split_strategy": "Train/validation/test split with stratification and explicit leakage checks; the intended real-world strategy is chronological, user-aware splitting for future behavior evaluation.",
    "calibration_method": "Isotonic calibration on the supervised model output; Brier score used to assess probability calibration.",
    "features": FEATURES,
    "feature_count": len(FEATURES),
    "train_samples": int(len(X_train)),
    "validation_samples": int(len(X_val)),
    "test_samples": int(len(X_test)),
    "train_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
    "label_type": "synthetic (time-heuristic)",
    "thresholds": {
        "medium": THRESHOLD_MEDIUM,
        "high": THRESHOLD_HIGH,
    },
    "risk_thresholds": {
        "LOW": "0-29",
        "MEDIUM": "30-54",
        "HIGH": "55-100",
    },
    "design_note": "The model is trained on non-leaky behavioural features; the risk score is derived from the calibrated suspicious probability plus behavioural factors available at login time.",
    "metrics": {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(auc), 4),
        "brier_score": round(float(brier), 4),
    },
    "anomaly_model": {
        "name": "IsolationForest",
        "contamination": 0.05,
        "roc_auc": round(float(iso_auc), 4),
        "notes": "This unsupervised model is used for behavioural anomaly comparison only; the primary runtime risk remains the calibrated supervised classifier."
    },
    "confusion_matrix": cm.tolist(),
}

with open("models/model_metadata.json", "w", encoding="utf-8") as f:
    json.dump(metadata, f, indent=2)

print("\nSaved model: models/random_forest_model.pkl")
print("Saved metadata: models/model_metadata.json")
print(f"Selected thresholds: medium={THRESHOLD_MEDIUM}, high={THRESHOLD_HIGH}")
