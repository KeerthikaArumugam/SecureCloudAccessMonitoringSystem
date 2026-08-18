"""
fix_passwords.py — Phase 2a
Hash plaintext passwords for sureka, sathish, Harini.
Run once: venv\Scripts\python.exe fix_passwords.py
"""
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

USERS_TO_FIX = [
    ("sureka",  "Sureka@1234"),
    ("sathish", "Sathish@4321"),
    ("Harini",  "Harini@4321"),
]

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

for username, plaintext in USERS_TO_FIX:
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if row is None:
        print(f"[SKIP]  User '{username}' not found in DB.")
        continue

    pwd = row[0]

    # If already hashed (werkzeug hashes start with pbkdf2:sha256 or scrypt)
    if pwd and (pwd.startswith("pbkdf2:") or pwd.startswith("scrypt:")):
        print(f"[OK]    '{username}' already has a hashed password — skipping.")
        continue

    hashed = generate_password_hash(plaintext)
    cursor.execute(
        "UPDATE users SET password=? WHERE username=?",
        (hashed, username)
    )
    print(f"[FIXED] '{username}' password hashed successfully.")

conn.commit()
conn.close()
print("\nDone.")
