"""
One-time migration: adds upload_id column to alerts table if missing.
Run once: py migrate_db.py
"""
import sqlite3, os

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'soc_platform.db')

conn = sqlite3.connect(db_path)
cur  = conn.cursor()

# Check existing columns
cur.execute("PRAGMA table_info(alerts)")
cols = [r[1] for r in cur.fetchall()]
print("Current alerts columns:", cols)

if 'upload_id' not in cols:
    cur.execute("ALTER TABLE alerts ADD COLUMN upload_id INTEGER REFERENCES log_uploads(id)")
    conn.commit()
    print("Added upload_id column to alerts.")
else:
    print("upload_id already exists — no migration needed.")

conn.close()
print("Done.")
