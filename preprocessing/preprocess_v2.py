import pandas as pd
from sklearn.preprocessing import LabelEncoder

print("Loading logon dataset...")

# Load dataset
df = pd.read_csv("dataset/logon.csv")

# Convert date column
df["date"] = pd.to_datetime(df["date"])

# -----------------------------
# Feature Engineering
# -----------------------------

# Date & Time Features
df["hour"] = df["date"].dt.hour
df["day"] = df["date"].dt.day
df["month"] = df["date"].dt.month
df["weekday"] = df["date"].dt.dayofweek

# Working Hours (8 AM - 6 PM)
df["working_hours"] = df["hour"].apply(lambda x: 1 if 8 <= x <= 18 else 0)

# Weekend
df["weekend"] = df["weekday"].apply(lambda x: 1 if x >= 5 else 0)

# -----------------------------
# Encode Categorical Columns
# -----------------------------
user_encoder = LabelEncoder()
pc_encoder = LabelEncoder()
activity_encoder = LabelEncoder()

df["user"] = user_encoder.fit_transform(df["user"])
df["pc"] = pc_encoder.fit_transform(df["pc"])
df["activity"] = activity_encoder.fit_transform(df["activity"])

# -----------------------------
# Cybersecurity Rule-Based Labels
# -----------------------------
df["label"] = 0

# Suspicious if login is outside office hours
df.loc[(df["hour"] < 6) | (df["hour"] > 22), "label"] = 1

# Suspicious if login occurs on weekend and outside office hours
df.loc[(df["weekend"] == 1) & (df["working_hours"] == 0), "label"] = 1

# -----------------------------
# Remove unwanted columns
# -----------------------------
df.drop(columns=["id", "date"], inplace=True)

# -----------------------------
# Save processed dataset
# -----------------------------
df.to_csv("dataset/final_training_dataset.csv", index=False)

print("\nFinal Dataset Created Successfully!\n")

print(df.head())

print("\nDataset Shape:", df.shape)

print("\nLabel Distribution")
print(df["label"].value_counts())