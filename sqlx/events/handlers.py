"""
sqlx/events/handlers.py
-----------------------
Default EventBus handlers for the SQLX project.

``AuditLogHandler``
    Subscribes to **all** known events and appends one JSON line per event
    to ``logs/events.jsonl`` (relative to the current working directory).

``register_default_handlers()``
    Convenience function that wires up all built-in handlers to the global
    ``bus`` singleton.  Call this once at application startup.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlx.events.bus import bus, EventBus
from sqlx.events.events import ALL_EVENTS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Audit log handler
# ---------------------------------------------------------------------------

_DEFAULT_LOG_PATH = Path("logs") / "events.jsonl"


class AuditLogHandler:
    """Appends a JSON line to ``logs/events.jsonl`` for every SQLX event.

    The handler subscribes to every event name defined in
    :data:`~sqlx.events.events.ALL_EVENTS`.  When any of those events fire,
    :meth:`handle` serialises the event to a single JSON line containing:

    - ``timestamp``   — ISO-8601 UTC timestamp of when the event was received.
    - ``event_name``  — The string topic key (e.g. ``"session.started"``).
    - ``data``        — The payload dict from the event dataclass.

    Args:
        log_path: Path to the JSONL file.  Defaults to ``logs/events.jsonl``
            resolved relative to the process's current working directory.
            Parent directories are created automatically.
        event_bus: The :class:`~sqlx.events.bus.EventBus` instance to
            subscribe to.  Defaults to the global singleton ``bus``.
    """

    def __init__(
        self,
        log_path: Path | str | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._log_path: Path = Path(log_path) if log_path else _DEFAULT_LOG_PATH
        self._bus: EventBus = event_bus or bus
        self._subscribed: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def subscribe(self) -> None:
        """Subscribe to all known event topics on the EventBus.

        Safe to call multiple times — will not duplicate subscriptions.
        """
        if self._subscribed:
            return

        for event_cls in ALL_EVENTS:
            self._bus.subscribe(event_cls.name, self._make_handler(event_cls.name))

        self._subscribed = True
        logger.debug(
            "AuditLogHandler subscribed to %d event types → %s",
            len(ALL_EVENTS),
            self._log_path,
        )

    def handle(self, event_name: str, data: Any) -> None:
        """Write a single JSON audit line for *event_name* with *data*.

        This method is also callable directly (e.g. in tests) without going
        through the EventBus subscription mechanism.

        Args:
            event_name: The string topic key of the event.
            data:       The raw payload passed by :meth:`EventBus.publish`.
                        Expected to be a dict, but gracefully handles other types.
        """
        try:
            # Normalise payload to a plain dict for JSON serialisation.
            if hasattr(data, "data"):
                # It's one of our event dataclass instances.
                payload = data.data
            elif isinstance(data, dict):
                payload = data
            else:
                payload = {"raw": str(data)}

            record = {
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "event_name": event_name,
                "data": payload,
            }

            self._ensure_log_dir()
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("AuditLogHandler failed to write event %r: %s", event_name, exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_log_dir(self) -> None:
        """Create parent directories for the log file if they don't exist."""
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def _make_handler(self, event_name: str):
        """Return a closure that captures *event_name* for the subscription."""
        def _handler(data: Any) -> None:
            self.handle(event_name, data)

        _handler.__name__ = f"_audit_handler_{event_name.replace('.', '_')}"
        return _handler


# ---------------------------------------------------------------------------
# Module-level singleton & registration helper
# ---------------------------------------------------------------------------

#: Module-level AuditLogHandler instance; created by register_default_handlers().
_audit_handler: AuditLogHandler | None = None


def register_default_handlers(
    log_path: Path | str | None = None,
    event_bus: EventBus | None = None,
) -> AuditLogHandler:
    """Wire up all built-in SQLX event handlers to the EventBus.

    This function is idempotent — calling it multiple times will not create
    duplicate log entries; subsequent calls return the existing handler.

    Args:
        log_path:  Override the JSONL audit log path.
        event_bus: Override the EventBus instance (useful in tests).

    Returns:
        The :class:`AuditLogHandler` that was registered.
    """
    global _audit_handler  # noqa: PLW0603

    if _audit_handler is None:
        _audit_handler = AuditLogHandler(log_path=log_path, event_bus=event_bus)
        _audit_handler.subscribe()
        logger.info("Default SQLX event handlers registered.")
    else:
        logger.debug("register_default_handlers() called again; reusing existing handler.")

    return _audit_handler
