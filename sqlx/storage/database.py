"""
sqlx/storage/database.py
~~~~~~~~~~~~~~~~~~~~~~~~
Lightweight SQLite persistence layer using Python stdlib sqlite3.
Stores target metadata, session records, findings, and audit events
for fast cross-target querying without parsing every JSON file.
"""
from __future__ import annotations
import datetime
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_DB = Path("sqlx.db")

_DDL = """
CREATE TABLE IF NOT EXISTS targets (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    url           TEXT NOT NULL,
    workspace_dir TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    description   TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,
    target_id      TEXT NOT NULL,
    objective      TEXT,
    status         TEXT DEFAULT 'active',
    created_at     TEXT NOT NULL,
    updated_at     TEXT,
    findings_count INTEGER DEFAULT 0,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    target_id  TEXT NOT NULL,
    finding    TEXT NOT NULL,
    severity   TEXT DEFAULT 'info',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_name TEXT NOT NULL,
    target_id  TEXT,
    session_id TEXT,
    actor      TEXT DEFAULT 'system',
    data       TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_traffic (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    method      TEXT NOT NULL,
    url         TEXT NOT NULL,
    req_headers TEXT,
    req_body    TEXT,
    res_status  INTEGER,
    res_headers TEXT,
    res_body    TEXT,
    latency_ms  REAL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_events_name ON audit_events(event_name);
CREATE INDEX IF NOT EXISTS idx_events_target ON audit_events(target_id);
CREATE INDEX IF NOT EXISTS idx_proxy_traffic ON proxy_traffic(id DESC);
"""


def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


class Database:
    """Thin sqlite3 wrapper for SQLX persistent storage."""

    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._conn: Optional[sqlite3.Connection] = None

    # ── lifecycle ──────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if not self._conn:
            self.connect()
        return self._conn

    # ── generic helpers ────────────────────────────────────────────────────

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        return cur

    def fetchall(self, sql: str, params=()) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def fetchone(self, sql: str, params=()) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    # ── domain helpers ─────────────────────────────────────────────────────

    def upsert_target(self, data: dict) -> None:
        self.execute("""
            INSERT OR REPLACE INTO targets
                (id, name, url, workspace_dir, created_at, description)
            VALUES (:id, :name, :url, :workspace_dir, :created_at, :description)
        """, data)

    def get_target(self, target_id: str) -> Optional[dict]:
        return self.fetchone("SELECT * FROM targets WHERE id = ?", (target_id,))

    def list_targets(self) -> List[dict]:
        return self.fetchall("SELECT * FROM targets ORDER BY created_at DESC")

    def insert_finding(self, target_id: str, session_id: str,
                       finding: str, severity: str = "info") -> int:
        cur = self.execute("""
            INSERT INTO findings (session_id, target_id, finding, severity, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, target_id, finding, severity, _now()))
        return cur.lastrowid

    def get_findings(self, target_id: str = None,
                     session_id: str = None) -> List[dict]:
        if target_id and session_id:
            return self.fetchall(
                "SELECT * FROM findings WHERE target_id=? AND session_id=? ORDER BY id DESC",
                (target_id, session_id),
            )
        if target_id:
            return self.fetchall(
                "SELECT * FROM findings WHERE target_id=? ORDER BY id DESC",
                (target_id,),
            )
        return self.fetchall("SELECT * FROM findings ORDER BY id DESC")

    def log_event(self, event_name: str, data: dict = None,
                  target_id: str = None, session_id: str = None,
                  actor: str = "system") -> None:
        self.execute("""
            INSERT INTO audit_events
                (event_name, target_id, session_id, actor, data, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (event_name, target_id, session_id, actor,
               json.dumps(data or {}), _now()))

    def get_events(self, event_name: str = None,
                   target_id: str = None, limit: int = 100) -> List[dict]:
        if event_name and target_id:
            return self.fetchall(
                "SELECT * FROM audit_events WHERE event_name=? AND target_id=? "
                "ORDER BY id DESC LIMIT ?",
                (event_name, target_id, limit),
            )
        if event_name:
            return self.fetchall(
                "SELECT * FROM audit_events WHERE event_name=? ORDER BY id DESC LIMIT ?",
                (event_name, limit),
            )
        return self.fetchall(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
        )


# Module-level lazy singleton
_db: Optional[Database] = None


def get_db(db_path: str = None) -> Database:
    global _db
    if _db is None:
        _db = Database(db_path)
        _db.connect()
    return _db
