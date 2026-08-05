import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
UPDATE users
SET failed_attempts = 0,
    account_locked = 0
WHERE username = 'sathish'
""")

conn.commit()
conn.close()

print("User unlocked successfully!")