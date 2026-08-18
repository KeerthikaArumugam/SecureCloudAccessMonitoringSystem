"""migrate_db.py — Run once to add new columns."""
import sqlite3
from werkzeug.security import generate_password_hash

conn   = sqlite3.connect("database.db")
cursor = conn.cursor()

def add_col(table, col, defn):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        print(f"  + {table}.{col} added")
    except Exception as e:
        print(f"  ~ {table}.{col}: {e}")

# users
add_col("users", "user_devices", "TEXT DEFAULT '[]'")
add_col("users", "user_ips",     "TEXT DEFAULT '[]'")
add_col("users", "total_logins", "INTEGER DEFAULT 0")

conn.commit()

# Fix plaintext passwords
fixes = [
    ("sureka",   "Sureka@1234"),
    ("sathish",  "Sathish@4321"),
    ("Harini",   "Harini@4321"),
]
for uname, plain in fixes:
    cursor.execute("SELECT password FROM users WHERE username=?", (uname,))
    row = cursor.fetchone()
    if row:
        pwd = row[0]
        if not pwd.startswith("scrypt:") and not pwd.startswith("pbkdf2:"):
            hashed = generate_password_hash(plain)
            cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed, uname))
            print(f"  ✓ {uname} password hashed")
        else:
            print(f"  ~ {uname} already hashed")

conn.commit()
conn.close()
print("Migration complete.")
