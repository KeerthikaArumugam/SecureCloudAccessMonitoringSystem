import pandas as pd

# Load device dataset
df = pd.read_csv("dataset/device.csv")

print("Shape:")
print(df.shape)

print("\nColumns:")
print(df.columns)

print("\nFirst 5 Rows:")
print(df.head())

print("\nData Types:")
print(df.dtypes)

print("\nMissing Values:")
print(df.isnull().sum())

print("\nUnique Activities:")
print(df["activity"].value_counts())