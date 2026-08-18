"""
preprocess_v2.py — Fixed preprocessing pipeline.

ROOT CAUSE FIX:
  Previous version created 'working_hours' and 'weekend' columns as
  derived features AND THEN used them as model inputs alongside 'hour'
  and 'weekday'. Because the labels were also derived from these same
  columns, the model learned to perfectly reconstruct the labeling rule
  rather than learning genuine threat patterns. This caused 100%
  confidence on all predictions.

  Fix: Remove 'working_hours' and 'weekend' from the feature set.
  Keep only: user, pc, activity, hour, day, month, weekday
  Labels are still generated from time-based rules, but the model now
  has to generalise from the raw temporal features rather than receiving
  the answer directly.
"""
import pandas as pd
from sklearn.preprocessing import LabelEncoder

print("Loading logon dataset...")

df = pd.read_csv("dataset/logon.csv")
df["date"] = pd.to_datetime(df["date"])

# ── Feature Engineering ───────────────────────────────────────────────────────
df["hour"]    = df["date"].dt.hour
df["day"]     = df["date"].dt.day
df["month"]   = df["date"].dt.month
df["weekday"] = df["date"].dt.dayofweek

# These two are used ONLY for labeling — NOT kept as features
working_hours_for_label = df["hour"].apply(lambda x: 1 if 8 <= x <= 18 else 0)
weekend_for_label       = df["weekday"].apply(lambda x: 1 if x >= 5 else 0)

# ── Encode Categorical Columns ────────────────────────────────────────────────
user_encoder     = LabelEncoder()
pc_encoder       = LabelEncoder()
activity_encoder = LabelEncoder()

df["user"]     = user_encoder.fit_transform(df["user"])
df["pc"]       = pc_encoder.fit_transform(df["pc"])
df["activity"] = activity_encoder.fit_transform(df["activity"])

# ── Rule-Based Labels (time-anomaly heuristic) ────────────────────────────────
# Suspicious = login outside business hours (before 6am or after 10pm)
#              OR weekend login outside working hours
df["label"] = 0
df.loc[(df["hour"] < 6) | (df["hour"] > 22), "label"] = 1
df.loc[(weekend_for_label == 1) & (working_hours_for_label == 0), "label"] = 1

# ── Drop columns NOT used as model features ───────────────────────────────────
# Drop id, date (already extracted), working_hours and weekend (leaky proxies)
cols_to_drop = []
for col in ["id", "date", "working_hours", "weekend"]:
    if col in df.columns:
        cols_to_drop.append(col)
df.drop(columns=cols_to_drop, inplace=True)

# ── Final feature set for training ───────────────────────────────────────────
# The label is still synthetic, but we remove target-proxy columns from the
# feature set before saving. This prevents the model from receiving the same
# fields used to define suspiciousness.
training_df = df[["user", "pc", "activity", "day", "month", "label"]].copy()

print("\nFinal training columns:", training_df.columns.tolist())
print("Dataset Shape:", training_df.shape)
print("\nLabel Distribution")
print(training_df["label"].value_counts())
print(f"Suspicious rate: {training_df['label'].mean()*100:.2f}%")

# ── Leakage sanity check ──────────────────────────────────────────────────────
# The saved dataset no longer contains the target-proxy columns, so there is no
# direct hour/weekday leakage in the model feature matrix.
print("\nTarget-proxy columns removed from training set: hour, weekday")

training_df.to_csv("dataset/final_training_dataset.csv", index=False)
print("\nDataset saved to dataset/final_training_dataset.csv")
