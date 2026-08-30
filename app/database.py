import sqlite3
from datetime import datetime

DATABASE_NAME = "history.db"


def get_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def create_table():
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT,
            issues_count INTEGER,
            risk_score INTEGER,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(code, issues_count, risk_score):
    conn = get_connection()

    conn.execute("""
        INSERT INTO scan_history
        (code, issues_count, risk_score, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        code,
        issues_count,
        risk_score,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_history():
    conn = get_connection()

    rows = conn.execute("""
        SELECT * FROM scan_history
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return [dict(row) for row in rows]