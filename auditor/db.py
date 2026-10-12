import sqlite3
import json
import time
import os
from typing import List, Dict, Any, Optional

# On Vercel or serverless environments, root filesystem is read-only; use /tmp or env
DB_PATH = os.environ.get("AUDIT_DB_PATH", "/tmp/audits.db" if os.environ.get("VERCEL") else "audits.db")


def init_db():
    """Initialize SQLite tables for storing audit history."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_history (
                id TEXT PRIMARY KEY,
                root_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                created_at REAL NOT NULL,
                health_score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                pages_crawled INTEGER NOT NULL,
                total_links_checked INTEGER NOT NULL,
                broken_links_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                warning_count INTEGER NOT NULL,
                notice_count INTEGER NOT NULL,
                passed_count INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_root_url ON audit_history(root_url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON audit_history(created_at DESC)")
        conn.commit()


def save_audit(report_data: Dict[str, Any]) -> str:
    """Saves a completed audit report into SQLite database."""
    init_db()
    audit_id = report_data.get("id") or str(int(time.time() * 1000))
    report_data["id"] = audit_id

    root_url = report_data.get("root_url", "")
    timestamp = report_data.get("timestamp", "")
    created_at = time.time()
    health_score = int(report_data.get("health_score", 0))
    grade = report_data.get("grade", "-")
    pages_crawled = int(report_data.get("pages_crawled", 0))
    total_links = int(report_data.get("total_links_checked", 0))
    broken_links = int(report_data.get("broken_links_count", 0))

    sev_counts = report_data.get("severity_counts", {})
    critical_c = int(sev_counts.get("critical", 0))
    warning_c = int(sev_counts.get("warning", 0))
    notice_c = int(sev_counts.get("notice", 0))
    passed_c = int(sev_counts.get("passed", 0))

    report_json_str = json.dumps(report_data)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO audit_history (
                id, root_url, timestamp, created_at, health_score, grade,
                pages_crawled, total_links_checked, broken_links_count,
                critical_count, warning_count, notice_count, passed_count,
                report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id, root_url, timestamp, created_at, health_score, grade,
            pages_crawled, total_links, broken_links,
            critical_c, warning_c, notice_c, passed_c,
            report_json_str
        ))
        conn.commit()

    return audit_id


def list_audits(limit: int = 20) -> List[Dict[str, Any]]:
    """Lists recent audits from the database without full JSON blob for fast rendering."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, root_url, timestamp, created_at, health_score, grade,
                   pages_crawled, total_links_checked, broken_links_count,
                   critical_count, warning_count, notice_count, passed_count
            FROM audit_history
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def get_audit_by_id(audit_id: str) -> Optional[Dict[str, Any]]:
    """Loads a full audit report from database by its ID."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT report_json FROM audit_history WHERE id = ?", (audit_id,))
        row = cursor.fetchone()
        if row and row[0]:
            return json.loads(row[0])
        return None


def delete_audit_by_id(audit_id: str) -> bool:
    """Deletes an audit record."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_history WHERE id = ?", (audit_id,))
        conn.commit()
        return cursor.rowcount > 0
