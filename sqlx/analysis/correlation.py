"""
sqlx/analysis/correlation.py
─────────────────────────────
Correlates SQLMap payloads with the HTTP responses they triggered.

Classes
-------
PayloadCorrelator
    Tracks payload → response mappings, classifies them as blocked /
    successful, and subscribes to ``ProxyResponseReceived`` events on
    the global :data:`~sqlx.events.bus` for automatic recording.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from sqlx.events import bus


class PayloadCorrelator:
    """Track which payloads caused which responses.

    Thread-safe — all mutation is protected by an internal :class:`Lock`.

    Usage
    -----
    >>> corr = PayloadCorrelator()
    >>> corr.record("UNION SELECT", "http://t.co/page?id=1", 200, "admin")
    >>> corr.record("OR 1=1--",     "http://t.co/page?id=1", 403, "blocked")
    >>> print(corr.summary())
    """

    # HTTP status ranges treated as "blocked"
    _BLOCKED_RANGE = range(400, 600)  # 4xx and 5xx

    def __init__(self, auto_subscribe: bool = True) -> None:
        """Initialise the correlator.

        Parameters
        ----------
        auto_subscribe:
            When *True* (default) the instance automatically registers
            a handler on the ``ProxyResponseReceived`` event bus topic.
        """
        self._records: list[dict[str, Any]] = []
        self._lock = threading.Lock()

        if auto_subscribe:
            bus.subscribe("ProxyResponseReceived", self._on_proxy_response)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        payload_hint: str,
        request_url: str,
        response_status: int,
        response_body_snippet: str,
    ) -> None:
        """Record a single payload/response pair.

        Parameters
        ----------
        payload_hint:
            A short string identifying the payload or injection technique
            (e.g. ``"UNION SELECT NULL--"``).
        request_url:
            The full URL that was requested.
        response_status:
            HTTP status code of the response.
        response_body_snippet:
            A brief excerpt from the response body (first ~200 chars is fine).
        """
        entry: dict[str, Any] = {
            "payload_hint": payload_hint,
            "request_url": request_url,
            "response_status": response_status,
            "response_body_snippet": response_body_snippet,
            "blocked": response_status in self._BLOCKED_RANGE,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }
        with self._lock:
            self._records.append(entry)

    def get_blocked_payloads(self) -> list[dict[str, Any]]:
        """Return entries whose response status was 4xx or 5xx.

        Returns
        -------
        list[dict]
            A copy of each blocked record dict.
        """
        with self._lock:
            return [r.copy() for r in self._records if r["blocked"]]

    def get_successful_payloads(self) -> list[dict[str, Any]]:
        """Return entries whose response status was *not* 4xx/5xx.

        Returns
        -------
        list[dict]
            A copy of each successful record dict.
        """
        with self._lock:
            return [r.copy() for r in self._records if not r["blocked"]]

    def summary(self) -> str:
        """Return a human-readable summary of recorded payload outcomes.

        Returns
        -------
        str
            Multi-line text suitable for logging or display.
        """
        with self._lock:
            total = len(self._records)
            blocked = sum(1 for r in self._records if r["blocked"])
            successful = total - blocked

        lines: list[str] = [
            "=== PayloadCorrelator Summary ===",
            f"  Total recorded : {total}",
            f"  Successful     : {successful}",
            f"  Blocked (4xx/5xx): {blocked}",
        ]

        if blocked:
            lines.append("\nBlocked payloads:")
            for r in self.get_blocked_payloads():
                lines.append(
                    f"  [{r['response_status']}] {r['payload_hint']!r}"
                    f" → {r['request_url']}"
                )

        if successful:
            lines.append("\nSuccessful payloads:")
            for r in self.get_successful_payloads():
                lines.append(
                    f"  [{r['response_status']}] {r['payload_hint']!r}"
                    f" → {r['request_url']}"
                )

        return "\n".join(lines)

    def clear(self) -> None:
        """Remove all recorded entries."""
        with self._lock:
            self._records.clear()

    # ------------------------------------------------------------------
    # Event bus integration
    # ------------------------------------------------------------------

    def _on_proxy_response(self, event_data: Any) -> None:
        """Handle a ``ProxyResponseReceived`` event from the event bus.

        Expected *event_data* shape (dict or object with attributes)::

            {
                "payload_hint":           str,   # optional
                "url":                    str,
                "status":                 int,
                "body_snippet":           str,   # optional
            }

        Missing fields are replaced with safe defaults so that even a
        partial event does not raise.
        """
        if event_data is None:
            return

        # Support both dicts and attribute-based objects
        def _get(key: str, default: Any = "") -> Any:
            if isinstance(event_data, dict):
                return event_data.get(key, default)
            return getattr(event_data, key, default)

        payload_hint = str(_get("payload_hint", "<unknown>"))
        url = str(_get("url", _get("request_url", "<unknown>")))
        status = int(_get("status", _get("response_status", 0)))
        snippet = str(_get("body_snippet", _get("response_body_snippet", "")))

        self.record(payload_hint, url, status, snippet)
