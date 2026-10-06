"""
sqlx/sqlmap/monitor.py
~~~~~~~~~~~~~~~~~~~~~~
Live execution monitor for a running SQLMap process.
Polls the output queue in a background thread and fires callbacks
on key events (injection found, WAF detected, completion).
"""
from __future__ import annotations
import logging
import re
import threading
import time
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class ProgressEvent:
    def __init__(self, event_type: str, message: str, payload: dict = None):
        self.event_type = event_type   # 'info'|'warning'|'critical'|'done'|'error'
        self.message    = message
        self.payload    = payload or {}

    def __str__(self) -> str:
        return f"[{self.event_type.upper()}] {self.message}"


class SQLMapMonitor:
    """Monitors a running SQLMapRunner and fires callbacks on key events."""

    def __init__(self, runner, poll_interval: float = 0.5):
        self.runner        = runner
        self.poll_interval = poll_interval
        self._callbacks: List[Callable[[ProgressEvent], None]] = []
        self._events: List[ProgressEvent] = []
        self._stop  = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def on_event(self, callback: Callable[[ProgressEvent], None]) -> None:
        """Register a callback that fires on every ProgressEvent."""
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start monitoring in a background daemon thread."""
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def wait(self) -> List[ProgressEvent]:
        """Block until sqlmap finishes, then return all recorded events."""
        if self._thread:
            self._thread.join()
        return list(self._events)

    # ── internals ──────────────────────────────────────────────────────────

    def _emit(self, event: ProgressEvent) -> None:
        self._events.append(event)
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as exc:
                logger.warning("Monitor callback error: %s", exc)

    def _classify(self, line: str) -> Optional[ProgressEvent]:
        clean = _ANSI_RE.sub("", line).strip()
        if not clean:
            return None
        lower = clean.lower()

        if "[critical]" in clean:
            return ProgressEvent("critical", clean)
        if "[warning]" in clean:
            return ProgressEvent("warning", clean)
        if any(k in lower for k in ("vulnerable", "injection found", "injectable")):
            return ProgressEvent("critical", clean, {"type": "injection_found"})
        if any(k in lower for k in ("back-end dbms", "web application technology")):
            return ProgressEvent("info", clean, {"type": "fingerprint"})
        if "[error]" in clean:
            return ProgressEvent("error", clean)
        return None

    def _loop(self) -> None:
        from sqlx.sqlmap.cleaner import SQLMapOutputCleaner
        cleaner = SQLMapOutputCleaner()

        while not self._stop.is_set() and self.runner.is_running():
            try:
                lines = self.runner.get_output_lines(timeout=self.poll_interval)
            except Exception:
                lines = []
            for line in lines:
                event = self._classify(line)
                if event:
                    self._emit(event)
            time.sleep(0)

        # Drain + emit done event
        try:
            remaining = self.runner.get_output_lines(timeout=0.1)
            if remaining:
                summary = cleaner.summarize(remaining)
                self._emit(ProgressEvent("done", "SQLMap completed", payload=summary))
        except Exception:
            self._emit(ProgressEvent("done", "SQLMap completed"))
