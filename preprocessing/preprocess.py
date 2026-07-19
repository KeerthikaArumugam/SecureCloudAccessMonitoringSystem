import pandas as pd
from sklearn.preprocessing import LabelEncoder

# -----------------------------
# Load Dataset
# -----------------------------
print("Loading dataset...")

df = pd.read_csv("dataset/logon.csv")

print("Dataset Loaded Successfully!")
print(df.head())


# -----------------------------
# Convert Date Column
# -----------------------------
print("\nConverting date column...")

df["date"] = pd.to_datetime(df["date"])


# -----------------------------
# Extract Useful Features
# -----------------------------
print("Extracting features...")

df["hour"] = df["date"].dt.hour
df["day"] = df["date"].dt.day
df["month"] = df["date"].dt.month
df["weekday"] = df["date"].dt.dayofweek


# -----------------------------
# Encode User
# -----------------------------
print("Encoding user column...")

user_encoder = LabelEncoder()

df["user"] = user_encoder.fit_transform(df["user"])


# -----------------------------
# Encode PC
# -----------------------------
print("Encoding PC column...")

pc_encoder = LabelEncoder()

df["pc"] = pc_encoder.fit_transform(df["pc"])


# -----------------------------
# Encode Activity
# -----------------------------
print("Encoding activity column...")

activity_encoder = LabelEncoder()

df["activity"] = activity_encoder.fit_transform(df["activity"])


# -----------------------------
# Create Labels
# -----------------------------
print("Creating labels...")

df["label"] = 0

df.loc[(df["hour"] < 6) | (df["hour"] > 22), "label"] = 1


# -----------------------------
# Remove Unnecessary Columns
# -----------------------------
print("Dropping unwanted columns...")

df.drop(columns=["id", "date"], inplace=True)


# -----------------------------
# Save Dataset
# -----------------------------
print("Saving processed dataset...")

df.to_csv("dataset/processed_logon.csv", index=False)

print("\nPreprocessing Completed Successfully!")

print(df.head())