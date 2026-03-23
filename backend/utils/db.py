import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "webguard.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            domain TEXT,
            timestamp TEXT,
            risk_score REAL,
            risk_level TEXT,
            data TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_scan(scan_id: str, domain: str, data: dict):
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO scans (id, domain, timestamp, risk_score, risk_level, data)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        domain,
        data.get("timestamp", ""),
        data.get("risk_score", 0),
        data.get("risk_level", ""),
        json.dumps(data)
    ))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, domain, timestamp, risk_score, risk_level FROM scans ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan_by_id(scan_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
