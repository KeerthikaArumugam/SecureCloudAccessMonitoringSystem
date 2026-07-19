import sqlite3

def create_database():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    # Login Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_date TEXT,
        login_time TEXT,
        ip_address TEXT,
        browser TEXT,
        device TEXT,
        prediction TEXT,
        risk TEXT,
        reasons TEXT
    )
    """)

    # Security Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        alert_type TEXT,
        prediction TEXT,
        alert_time TEXT
    )
    """)

    conn.commit()
    conn.close()

    print("Database and tables created successfully.")

if __name__ == "__main__":
    create_database()