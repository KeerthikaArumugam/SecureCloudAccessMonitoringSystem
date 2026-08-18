import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print("TABLES:", tables)

for t in tables:
    tname = t[0]
    cursor.execute(f"PRAGMA table_info({tname})")
    cols = cursor.fetchall()
    print(f"\n--- {tname} ---")
    for c in cols:
        print(c)
    cursor.execute(f"SELECT COUNT(*) FROM {tname}")
    print("Row count:", cursor.fetchone()[0])

# Sample data from users
print("\n--- SAMPLE USERS ---")
cursor.execute("SELECT id, username, email, failed_attempts, account_locked, ai_enabled, user_code, trusted_device FROM users LIMIT 5")
for row in cursor.fetchall():
    print(row)

# Sample login logs
print("\n--- SAMPLE LOGIN LOGS ---")
cursor.execute("SELECT * FROM login_logs LIMIT 3")
for row in cursor.fetchall():
    print(row)

conn.close()
