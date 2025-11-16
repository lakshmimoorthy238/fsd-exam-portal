# create_db.py
import sqlite3
import os
from werkzeug.security import generate_password_hash
from datetime import datetime

DB_PATH = 'exam_prep.db'
SCHEMA_FILE = 'schema.sql'

# Default admin credentials (change after first run)
ADMIN_EMAIL = 'admin@admin.local'
ADMIN_PASSWORD = 'Admin@123'  # change this right after initialization
ADMIN_FULLNAME = 'Quiz Master'

def execute_script(db_path, script_text):
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(script_text)
        conn.commit()
    finally:
        conn.close()

def read_schema(schema_file):
    with open(schema_file, 'r', encoding='utf-8') as f:
        return f.read()

def ensure_admin(db_path, email, password, full_name):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            print(f"[info] Admin user '{email}' already exists.")
            return
        pw_hash = generate_password_hash(password)
        cur.execute("""
            INSERT INTO users (email, password_hash, full_name, role, created_on)
            VALUES (?, ?, ?, 'admin', ?)
        """, (email, pw_hash, full_name, datetime.utcnow().isoformat()))
        conn.commit()
        print(f"[success] Admin user '{email}' created. Please change the password after first login.")
    finally:
        conn.close()

def quick_verify(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        tables = ['users','subjects','chapters','quizzes','questions','scores']
        print("\n[verify] Table row counts:")
        for t in tables:
            try:
                cur.execute(f"SELECT COUNT(*) AS cnt FROM {t}")
                r = cur.fetchone()
                print(f"  - {t}: {r['cnt']}")
            except sqlite3.OperationalError:
                print(f"  - {t}: (table missing)")
        # show admin user if present
        cur.execute("SELECT id, email, role, full_name FROM users WHERE role='admin' LIMIT 1")
        adm = cur.fetchone()
        if adm:
            print(f"\n[verify] Admin present: id={adm['id']}, email={adm['email']}, name={adm['full_name']}")
        else:
            print("\n[verify] No admin found.")
    finally:
        conn.close()

def main():
    if not os.path.exists(SCHEMA_FILE):
        print(f"[error] Schema file '{SCHEMA_FILE}' not found. Create schema.sql first.")
        return
    schema_sql = read_schema(SCHEMA_FILE)
    print(f"[info] Creating/Updating DB at {DB_PATH} ...")
    execute_script(DB_PATH, schema_sql)
    print("[info] Schema applied.")
    ensure_admin(DB_PATH, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_FULLNAME)
    quick_verify(DB_PATH)
    print("\n[done] DB initialization complete.")

if __name__ == '__main__':
    main()
