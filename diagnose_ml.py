"""
diagnose_ml.py — Root cause analysis for 100% confidence issue.
Run this BEFORE making any changes.
"""
import joblib
import pandas as pd
import numpy as np

model = joblib.load("models/random_forest_model.pkl")

print("=" * 70)
print("DIAGNOSIS: Why is threat_score/confidence = 100%?")
print("=" * 70)

# ── 1. Check what features the model was trained on ──────────────────────────
print("\n[1] Model feature names (training):")
try:
    print(" ", list(model.feature_names_in_))
except AttributeError:
    print("  (sklearn < 1.0 — no feature_names_in_)")

# ── 2. Probe probability distribution over many inputs ──────────────────────
print("\n[2] Probability samples across different hour values:")
print(f"  {'hour':>6}  {'weekday':>8}  {'working_hrs':>12}  {'weekend':>8}  "
      f"{'P(normal)':>10}  {'P(suspicious)':>14}  {'max_proba':>10}")
print("  " + "-" * 75)

results = []
for hour in [2, 6, 9, 12, 14, 17, 20, 23]:
    for weekday in [0, 5, 6]:  # Mon, Sat, Sun
        working_hours = 1 if 8 <= hour <= 18 else 0
        weekend       = 1 if weekday >= 5 else 0
        row = pd.DataFrame({
            "user": [5], "pc": [105], "activity": [3],
            "hour": [hour], "day": [15], "month": [8],
            "weekday": [weekday], "working_hours": [working_hours], "weekend": [weekend]
        })
        proba = model.predict_proba(row)[0]
        results.append((hour, weekday, proba[0], proba[1]))
        print(f"  {hour:>6}  {weekday:>8}  {working_hours:>12}  {weekend:>8}  "
              f"{proba[0]:>10.4f}  {proba[1]:>14.4f}  {max(proba):>10.4f}")

sus_probas = [r[3] for r in results]
print(f"\n  Suspicious probability range: {min(sus_probas):.4f} — {max(sus_probas):.4f}")
unique_vals = set(round(p, 4) for p in sus_probas)
print(f"  Unique suspicious prob values: {len(unique_vals)}")
print(f"  Values: {sorted(unique_vals)}")

# ── 3. Check label distribution in training data ─────────────────────────────
print("\n[3] Training data label distribution:")
try:
    df = pd.read_csv("dataset/final_training_dataset.csv")
    counts = df["label"].value_counts()
    total  = len(df)
    print(f"  Normal (0):     {counts.get(0,0):>8,}  ({counts.get(0,0)/total*100:.1f}%)")
    print(f"  Suspicious (1): {counts.get(1,0):>8,}  ({counts.get(1,0)/total*100:.1f}%)")

    # Check if labels are derivable directly from features
    print("\n[4] LEAKAGE CHECK — Can labels be derived from features?")
    label_from_hour   = ((df["hour"] < 6) | (df["hour"] > 22))
    label_from_combo  = (df["weekend"] == 1) & (df["working_hours"] == 0)
    rule_label        = (label_from_hour | label_from_combo).astype(int)
    match_pct         = (rule_label == df["label"]).mean() * 100
    print(f"  Rule-reconstructed label match: {match_pct:.2f}%")
    if match_pct > 99:
        print("  *** CRITICAL: Labels are 100% derivable from input features!")
        print("  *** This is SEVERE data leakage — 'working_hours' and 'weekend'")
        print("  *** are computed from 'hour' and 'weekday', which are ALSO in X.")
        print("  *** The model learned to perfectly predict the rule, not real threat.")
except Exception as e:
    print(f"  ERROR: {e}")

# ── 5. Feature importance ────────────────────────────────────────────────────
print("\n[5] Feature Importance:")
try:
    fi = pd.Series(model.feature_importances_, index=model.feature_names_in_)
    fi = fi.sort_values(ascending=False)
    for fname, imp in fi.items():
        print(f"  {fname:>15s}: {imp:.4f}")
except Exception:
    pass

print("\n" + "=" * 70)
print("ROOT CAUSE SUMMARY")
print("=" * 70)
print("""
The 100% confidence problem is caused by DATA LEAKAGE:

The label was created using this rule:
  label=1  IF  (hour < 6 OR hour > 22)
           OR  (weekend == 1 AND working_hours == 0)

Then BOTH 'working_hours' AND 'weekend' (derived from hour/weekday)
were kept as INPUT FEATURES alongside 'hour' and 'weekday'.

The model effectively receives the answer in the input:
  - 'hour' → label can be inferred directly
  - 'working_hours' = f(hour) → redundant with 'hour'
  - 'weekend' = f(weekday) → redundant with 'weekday'

The Random Forest learned a perfect decision rule: if working_hours==0
and weekend==1, then suspicious. This gives near-perfect accuracy
and extreme probabilities (0.0 or 1.0) on the test set.

FIX: Remove redundant derived features from training input.
     Keep: user, pc, activity, hour, day, month, weekday
     Drop: working_hours, weekend  (these are label proxies)
""")
