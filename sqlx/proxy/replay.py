"""
sqlx/proxy/replay.py
────────────────────
Utility for replaying a previously captured HTTP request and collecting the
response.

:class:`RequestReplayer` accepts a *request dict* in the same format used
throughout the SQLX proxy subsystem::

    {
        "method":  "POST",
        "url":     "https://example.com/login",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body":    "username=admin&password=secret",   # str or bytes
    }

Replaying fires the request through :mod:`urllib.request` (no external
dependencies) and returns a *response dict*::

    {
        "status":     200,
        "headers":    {"content-type": "text/html; charset=utf-8", ...},
        "body_text":  "<html>...</html>",
        "latency_ms": 124.7,
    }

Two EventBus events are published for every replay:

* ``ProxyRequestCaptured``  – fired just before the request is sent.
* ``ProxyResponseReceived`` – fired after a response (or error) is received,
  in the same format expected by :class:`~sqlx.proxy.history.ProxyHistory`.
"""

from __future__ import annotations

import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional


class RequestReplayer:
    """Replay a captured HTTP request and publish the result on the EventBus.

    Parameters
    ----------
    timeout:
        Socket timeout in seconds for the replayed request (default 30 s).
    """

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def replay(self, request_dict: dict) -> dict:
        """Send a replayed HTTP request and return the response.

        The method:

        1. Publishes ``ProxyRequestCaptured`` with the normalised request data.
        2. Executes the request via :mod:`urllib.request`.
        3. Publishes ``ProxyResponseReceived`` with request + response data
           (compatible with :class:`~sqlx.proxy.history.ProxyHistory`).
        4. Returns the response dict.

        Parameters
        ----------
        request_dict:
            A dict describing the request to replay.  Recognised keys:

            * ``method``  (str) – HTTP verb; defaults to ``"GET"``.
            * ``url``     (str) – Full URL including scheme.
            * ``headers`` (dict) – Request headers; empty dict if absent.
            * ``body``    (str | bytes | None) – Request body; ``None`` / empty
              strings are treated as *no body*.

        Returns
        -------
        dict
            Response dict with keys ``status``, ``headers``, ``body_text``,
            ``latency_ms``.

        Raises
        ------
        ValueError
            If *request_dict* is missing a ``url`` key.
        """
        method: str = request_dict.get("method", "GET").upper()
        url: str = request_dict.get("url", "")
        if not url:
            raise ValueError("request_dict must contain a non-empty 'url' key")

        raw_headers: dict = dict(request_dict.get("headers", {}))
        raw_body: Any = request_dict.get("body", None)

        # Normalise body to bytes (or None for body-less requests)
        body_bytes: Optional[bytes] = self._normalise_body(raw_body)

        # Build normalised req_data for event publishing
        req_data: dict = {
            "method": method,
            "url": url,
            "headers": raw_headers,
            "body": body_bytes or b"",
        }

        # 1. Publish request captured event
        self._publish("ProxyRequestCaptured", req_data)

        # 2. Execute request
        response_dict = self._execute(method, url, raw_headers, body_bytes)

        # 3. Publish response received event (matches ProxyHistory listener)
        res_data: dict = {
            "status": response_dict["status"],
            "headers": response_dict["headers"],
            "body": response_dict["body_text"].encode("utf-8", errors="replace"),
        }
        self._publish(
            "ProxyResponseReceived",
            {
                "req_data": req_data,
                "res_data": res_data,
                "latency_ms": response_dict["latency_ms"],
            },
        )

        return response_dict

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _normalise_body(self, body: Any) -> Optional[bytes]:
        """Convert *body* to bytes, or return ``None`` for empty bodies.

        Parameters
        ----------
        body:
            Raw body value from the request dict.

        Returns
        -------
        Optional[bytes]
            Body as bytes, or ``None`` if there is no body.
        """
        if body is None:
            return None
        if isinstance(body, (bytes, bytearray)):
            return bytes(body) if body else None
        if isinstance(body, str):
            return body.encode("utf-8") if body else None
        # Fallback: coerce to string first
        encoded = str(body).encode("utf-8")
        return encoded if encoded else None

    def _execute(
        self,
        method: str,
        url: str,
        headers: dict,
        body_bytes: Optional[bytes],
    ) -> dict:
        """Perform the actual HTTP request using :mod:`urllib.request`.

        Parameters
        ----------
        method:
            HTTP verb.
        url:
            Destination URL.
        headers:
            Request headers to send.
        body_bytes:
            Request body as bytes, or ``None``.

        Returns
        -------
        dict
            Response dict with keys ``status``, ``headers``, ``body_text``,
            ``latency_ms``.
        """
        req = urllib.request.Request(
            url,
            data=body_bytes,
            method=method,
        )

        # Copy headers, skipping hop-by-hop headers that urllib handles
        _skip = frozenset({"host", "accept-encoding", "content-length",
                           "transfer-encoding", "connection"})
        for key, value in headers.items():
            if key.lower() not in _skip:
                req.add_header(key, value)

        t_start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                latency_ms = (time.monotonic() - t_start) * 1000.0
                raw_body = response.read()
                status = response.status
                resp_headers = dict(response.headers)
        except urllib.error.HTTPError as exc:
            latency_ms = (time.monotonic() - t_start) * 1000.0
            raw_body = exc.read()
            status = exc.code
            resp_headers = dict(exc.headers) if exc.headers else {}
        except urllib.error.URLError as exc:
            latency_ms = (time.monotonic() - t_start) * 1000.0
            raw_body = str(exc.reason).encode("utf-8")
            status = 0
            resp_headers = {}

        body_text: str = (
            raw_body.decode("utf-8", errors="replace")
            if isinstance(raw_body, (bytes, bytearray))
            else str(raw_body)
        )

        return {
            "status": status,
            "headers": resp_headers,
            "body_text": body_text,
            "latency_ms": round(latency_ms, 3),
        }

    @staticmethod
    def _publish(event_name: str, data: Any) -> None:
        """Publish *data* under *event_name* on the global EventBus.

        Silently ignores import/runtime errors so the replayer works even
        when the EventBus is unavailable (e.g. in unit tests).

        Parameters
        ----------
        event_name:
            The event topic to publish on.
        data:
            Payload to deliver to subscribers.
        """
        try:
            from sqlx.events.bus import bus
            bus.publish(event_name, data)
        except Exception:
            pass

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RequestReplayer timeout={self._timeout}s>"
