"""migrate_phase4.py — Phase 4 schema additions (safe, idempotent)."""
import sqlite3

conn   = sqlite3.connect("database.db")
cursor = conn.cursor()

def add_col(table, col, defn):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        print(f"  + {table}.{col}")
    except Exception as e:
        print(f"  ~ {table}.{col}: {e}")

# Add model_version to login_logs
add_col("login_logs", "model_version",   "TEXT DEFAULT 'v1.1'")
# Add feature_scores JSON to login_logs
add_col("login_logs", "feature_scores",  "TEXT DEFAULT '{}'")
# Add model_component (raw RF probability * 100) separate from composite score
add_col("login_logs", "model_component", "REAL DEFAULT 0")

conn.commit()
conn.close()
print("Phase 4 migration complete.")
