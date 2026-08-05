import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

username = "admin"
email = "admin@gmail.com"
password = generate_password_hash("admin123")

try:
    cursor.execute("""
    INSERT INTO users (username, email, password)
    VALUES (?, ?, ?)
    """, (username, email, password))

    conn.commit()
    print("Admin account created successfully!")

except sqlite3.IntegrityError:
    print("Admin account already exists.")

conn.close()