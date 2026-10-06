"""
sqlx/proxy/history.py
~~~~~~~~~~~~~~~~~~~~~
Thread-safe, multi-process SQLite-backed store of HTTP transactions.
Subscribes to ProxyResponseReceived to capture all proxy traffic dynamically.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from sqlx.storage.database import get_db


class ProxyHistory:
    """SQLite-backed store of HTTP transactions observed by the proxy."""

    def __init__(self) -> None:
        # Subscribe to proxy events
        self._subscribe()

    def _subscribe(self) -> None:
        """Register an auto-capture handler on the global EventBus."""
        try:
            from sqlx.events.bus import bus
            bus.subscribe("ProxyResponseReceived", self._on_response_received)
        except Exception:
            pass

    def _on_response_received(self, event_data: Any) -> None:
        """Callback invoked by the EventBus for every ProxyResponseReceived event."""
        if not isinstance(event_data, dict):
            return

        req_data = event_data.get("req_data", {})
        res_data = event_data.get("res_data", {})
        latency_ms: float = event_data.get("latency_ms", 0.0)
        self.add(req_data, res_data, latency_ms)

    def add(
        self,
        req_data: dict,
        res_data: dict,
        latency_ms: float = 0.0,
    ) -> dict:
        """Record a new HTTP transaction in the database."""
        timestamp = datetime.now(tz=timezone.utc).isoformat()

        req_body_raw = req_data.get("body", b"")
        res_body_raw = res_data.get("body", b"")

        def _to_str(value: Any) -> str:
            if isinstance(value, (bytes, bytearray)):
                return value.decode("utf-8", errors="replace")
            return str(value) if value is not None else ""

        record = {
            "method": req_data.get("method", "GET"),
            "url": req_data.get("url", ""),
            "status": res_data.get("status", 0),
            "latency_ms": float(latency_ms),
            "timestamp": timestamp,
            "request_headers": json.dumps(dict(req_data.get("headers", {}))),
            "response_headers": json.dumps(dict(res_data.get("headers", {}))),
            "request_body": _to_str(req_body_raw),
            "response_body": _to_str(res_body_raw),
        }

        db = get_db()
        cur = db.execute("""
            INSERT INTO proxy_traffic 
            (method, url, req_headers, req_body, res_status, res_headers, res_body, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["method"], record["url"], record["request_headers"],
            record["request_body"], record["status"], record["response_headers"],
            record["response_body"], record["latency_ms"], record["timestamp"]
        ))
        
        record["id"] = cur.lastrowid
        
        # Hydrate JSON fields before returning the dict
        record["request_headers"] = json.loads(record["request_headers"])
        record["response_headers"] = json.loads(record["response_headers"])
        
        return record

    def _row_to_dict(self, row: dict) -> dict:
        """Convert a SQLite row into the standard proxy history dict format."""
        if not row:
            return None
        return {
            "id": row["id"],
            "method": row["method"],
            "url": row["url"],
            "status": row["res_status"],
            "latency_ms": row["latency_ms"],
            "timestamp": row["created_at"],
            "request_headers": json.loads(row["req_headers"] or "{}"),
            "response_headers": json.loads(row["res_headers"] or "{}"),
            "request_body": row["req_body"],
            "response_body": row["res_body"]
        }

    def get_all(self) -> List[dict]:
        """Return all stored transactions (oldest first)."""
        db = get_db()
        rows = db.fetchall("SELECT * FROM proxy_traffic ORDER BY id ASC")
        return [self._row_to_dict(r) for r in rows]

    def get_by_id(self, request_id: int) -> Optional[dict]:
        """Retrieve a single transaction by its auto-assigned integer ID."""
        db = get_db()
        row = db.fetchone("SELECT * FROM proxy_traffic WHERE id = ?", (request_id,))
        return self._row_to_dict(row) if row else None

    def get_recent(self, limit: int = 10) -> List[dict]:
        """Return the most recent *limit* transactions (newest first)."""
        db = get_db()
        rows = db.fetchall("SELECT * FROM proxy_traffic ORDER BY id DESC LIMIT ?", (limit,))
        return [self._row_to_dict(r) for r in rows]

    def clear(self) -> None:
        """Remove all proxy traffic from the database."""
        db = get_db()
        db.execute("DELETE FROM proxy_traffic")

    def __len__(self) -> int:
        db = get_db()
        row = db.fetchone("SELECT COUNT(*) as c FROM proxy_traffic")
        return row["c"] if row else 0

    def __repr__(self) -> str:
        return f"<ProxyHistory records={len(self)} persist=sqlite>"
