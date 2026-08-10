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
    # Add user_code column
try:
    cursor.execute("""
        ALTER TABLE users
        ADD COLUMN user_code INTEGER
    """)
    print("✓ user_code column added")
except Exception as e:
    print("user_code:", e)

# Add trusted_device column
try:
    cursor.execute("""
        ALTER TABLE users
        ADD COLUMN trusted_device INTEGER
    """)
    print("✓ trusted_device column added")
except Exception as e:
    print("trusted_device:", e)
    # Assign user_code and trusted_device

cursor.execute("""
UPDATE users
SET user_code = 1,
    trusted_device = 101
WHERE username = 'sureka'
""")

cursor.execute("""
UPDATE users
SET user_code = 2,
    trusted_device = 102
WHERE username = 'sathish'
""")

cursor.execute("""
UPDATE users
SET user_code = 3,
    trusted_device = 103
WHERE username = 'Harini'
""")

cursor.execute("""
UPDATE users
SET user_code = 4,
    trusted_device = 104
WHERE username = 'Ramya'
""")

cursor.execute("""
UPDATE users
SET user_code = 5,
    trusted_device = 105
WHERE username = 'Arun'
""")

cursor.execute("""
UPDATE users
SET user_code = 6,
    trusted_device = 106
WHERE username = 'admin'
""")

conn.commit()
conn.close()

print("Database updated successfully!")