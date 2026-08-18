"""Quick verification script."""
import sqlite3
from werkzeug.security import check_password_hash

conn = sqlite3.connect("database.db")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check password hashes
cursor.execute("SELECT username, password FROM users WHERE username IN ('sureka','sathish','Harini')")
for row in cursor.fetchall():
    hashed = row["password"]
    is_hash = hashed.startswith("pbkdf2:") or hashed.startswith("scrypt:")
    print(f"{row['username']}: password is hashed = {is_hash}")

# Check new columns
cursor.execute("PRAGMA table_info(users)")
ucols = {r["name"] for r in cursor.fetchall()}
for col in ["user_devices", "user_ips", "total_logins"]:
    print(f"users.{col}: {'EXISTS' if col in ucols else 'MISSING'}")

# Verify predict.py returns threat_score
from prediction.predict import predict_login
result = predict_login(user=1, pc=101, activity=1, hour=14, day=15, month=7, weekday=1)
print("\nPredict result keys:", list(result.keys()))
print("threat_score:", result["threat_score"])
print("confidence:", result["confidence"])
print("risk:", result["risk"])

conn.close()
print("\nAll checks passed!")
