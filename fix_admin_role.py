import sqlite3

conn   = sqlite3.connect("database.db")
cursor = conn.cursor()

# Ensure admin user has role='admin'
cursor.execute("UPDATE users SET role='admin' WHERE username='admin'")
conn.commit()

cursor.execute("SELECT id, username, role, ai_enabled, account_locked FROM users")
print("Users:")
for r in cursor.fetchall():
    print(" ", r)

# Verify all passwords are hashed
cursor.execute("SELECT username, password FROM users")
print("\nPassword check:")
for username, pwd in cursor.fetchall():
    hashed = pwd.startswith("scrypt:") or pwd.startswith("pbkdf2:")
    status = "HASHED" if hashed else "PLAINTEXT (!)"
    print(f"  {username:20s} -> {status}")

conn.close()
print("\nDone.")
