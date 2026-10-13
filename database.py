"""SQLite scan history with sanitized addresses and parameterized queries."""

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from urllib.parse import urlunsplit

from phishing_detector import analyze_url, validate_url


@contextmanager
def connection(database_path):
    with closing(sqlite3.connect(database_path, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA secure_delete = ON")
        with db:
            yield db


def initialize_database(database_path):
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with connection(database_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
                risk_level TEXT NOT NULL CHECK(risk_level IN ('Low', 'Medium', 'High')),
                reasons TEXT NOT NULL
            )
        """)


def storage_url(value):
    _, parsed, hostname, _, _ = validate_url(value)
    host = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None and parsed.port != {"http": 80, "https": 443}[parsed.scheme.lower()]:
        host += f":{parsed.port}"
    # Paths can carry reset links or bearer tokens; persist the origin only.
    return urlunsplit((parsed.scheme.lower(), host, "", "", ""))


def save_scan(database_path, value):
    # Generate reasons here, rather than accepting caller-supplied text that could contain secrets.
    analysis = analyze_url(value)
    address = storage_url(value)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    with connection(database_path) as db:
        cursor = db.execute("""
            INSERT INTO scans (scanned_at, normalized_url, risk_score, risk_level, reasons)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, address, analysis["risk_score"], analysis["risk_level"], json.dumps(analysis["reasons"])))
        return {"id": cursor.lastrowid, "scanned_at": timestamp, "normalized_url": address}


def get_history(database_path, limit=20, offset=0):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Limit must be an integer from 1 to 100.")
    if type(offset) is not int or not 0 <= offset <= 1000000:
        raise ValueError("Offset must be an integer from 0 to 1000000.")
    with connection(database_path) as db:
        db.execute("BEGIN")
        rows = db.execute("""
            SELECT id, scanned_at, normalized_url, risk_score, risk_level, reasons
            FROM scans ORDER BY id DESC LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()
        stats = dict(db.execute("""
            SELECT COUNT(*) AS total, COALESCE(ROUND(AVG(risk_score), 1), 0) AS average_score,
                COALESCE(SUM(risk_level = 'Low'), 0) AS low,
                COALESCE(SUM(risk_level = 'Medium'), 0) AS medium,
                COALESCE(SUM(risk_level = 'High'), 0) AS high
            FROM scans
        """).fetchone())
    scans = [dict(row) for row in rows]
    for scan in scans:
        scan["reasons"] = json.loads(scan["reasons"])
    return {"scans": scans, "statistics": stats, "total": stats["total"], "limit": limit, "offset": offset}


def delete_history(database_path):
    with connection(database_path) as db:
        return db.execute("DELETE FROM scans").rowcount
