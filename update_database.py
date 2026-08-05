import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Add failed_attempts column
try:
    cursor.execute("""
        ALTER TABLE users
        ADD COLUMN failed_attempts INTEGER DEFAULT 0
    """)
    print("✓ failed_attempts column added")
except Exception as e:
    print("failed_attempts:", e)

# Add account_locked column
try:
    cursor.execute("""
        ALTER TABLE users
        ADD COLUMN account_locked INTEGER DEFAULT 0
    """)
    print("✓ account_locked column added")
except Exception as e:
    print("account_locked:", e)

conn.commit()
conn.close()

print("Database updated successfully!")