"""
sqlx/session/manager.py
-----------------------
High-level session management for the SQLX project.

:class:`SessionManager` is the primary entry point for all session lifecycle
operations.  It delegates persistence to :class:`~sqlx.session.persistence.SessionPersistence`
and publishes domain events via the global :data:`~sqlx.events.bus.bus`.

Typical usage::

    from sqlx.session.manager import SessionManager

    mgr = SessionManager()
    session = mgr.start_session(
        target_id="t-abc123",
        objective="Discover SQL injection in login endpoint",
        workspace_dir="/path/to/workspace",
    )
    mgr.add_finding(session, {"severity": "high", "description": "Union-based SQLi"})
    mgr.add_observation(session, "Parameter 'username' is vulnerable.")
    mgr.save(session)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlx.events.bus import bus, EventBus
from sqlx.events.events import SessionStarted
from sqlx.session.persistence import SessionPersistence
from sqlx.session.state import SessionState

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages SQLX scan session lifecycle.

    Responsibilities:
    - Creating new sessions and persisting them immediately.
    - Mutating sessions in a controlled way (findings, observations).
    - Saving and loading sessions via :class:`~sqlx.session.persistence.SessionPersistence`.
    - Publishing :class:`~sqlx.events.events.SessionStarted` events on session creation.

    Args:
        persistence: A :class:`~sqlx.session.persistence.SessionPersistence`
            instance.  A fresh default instance is created if not provided.
        event_bus:   The :class:`~sqlx.events.bus.EventBus` to publish events
            on.  Defaults to the global singleton ``bus``.
    """

    def __init__(
        self,
        persistence: Optional[SessionPersistence] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        self._persistence: SessionPersistence = persistence or SessionPersistence()
        self._bus: EventBus = event_bus or bus

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def start_session(
        self,
        target_id: str,
        objective: str,
        workspace_dir: str | Path,
    ) -> SessionState:
        """Create, persist, and announce a new scan session.

        Steps:
        1. Instantiate a fresh :class:`~sqlx.session.state.SessionState`.
        2. Persist it to ``<workspace_dir>/sessions/<id>.json``.
        3. Publish a :class:`~sqlx.events.events.SessionStarted` event.

        Args:
            target_id:     Identifier of the target being scanned.
            objective:     Human-readable description of the session goal.
            workspace_dir: Root of the target workspace where sessions are stored.

        Returns:
            The newly created :class:`~sqlx.session.state.SessionState`.
        """
        state = SessionState(target_id=target_id, objective=objective)
        self._persistence.save(state, workspace_dir)

        # Publish event so listeners (e.g. AuditLogHandler) are notified.
        event = SessionStarted(data={
            "session_id": state.id,
            "target_id": state.target_id,
            "objective": state.objective,
            "created_at": state.created_at.isoformat(),
        })
        self._bus.publish(SessionStarted.name, event)

        logger.info(
            "Session started: id=%s target=%s objective=%r",
            state.id,
            state.target_id,
            state.objective,
        )
        return state

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_finding(
        self,
        session: SessionState,
        finding_dict: Dict[str, Any],
    ) -> None:
        """Append a finding to *session* (mutates in place).

        The session's :attr:`~sqlx.session.state.SessionState.last_updated`
        timestamp is refreshed automatically.

        Args:
            session:      The session to update.
            finding_dict: Free-form dict describing the vulnerability finding.
                          Recommended keys: ``finding_id``, ``severity``,
                          ``description``, ``parameter``.
        """
        session.add_finding(finding_dict)
        logger.debug(
            "Finding added to session %s: %s",
            session.id,
            finding_dict.get("finding_id", "<no id>"),
        )

    def add_observation(self, session: SessionState, text: str) -> None:
        """Append a free-form observation string to *session* (mutates in place).

        Args:
            session: The session to update.
            text:    Observation text (e.g. AI commentary, notable events).
        """
        session.add_observation(text)
        logger.debug("Observation added to session %s.", session.id)

    # ------------------------------------------------------------------
    # Persistence delegation
    # ------------------------------------------------------------------

    def save(self, session: SessionState, workspace_dir: str | Path) -> Path:
        """Persist the current state of *session* to disk.

        Args:
            session:       The session state to save.
            workspace_dir: Root of the target workspace.

        Returns:
            Path of the written JSON file.
        """
        path = self._persistence.save(session, workspace_dir)
        logger.debug("Session %s saved to %s.", session.id, path)
        return path

    def load(
        self,
        session_id: str,
        workspace_dir: str | Path,
    ) -> Optional[SessionState]:
        """Load a session by ID from *workspace_dir*.

        Args:
            session_id:    UUID string of the session.
            workspace_dir: Root of the target workspace.

        Returns:
            The loaded :class:`~sqlx.session.state.SessionState`, or ``None``
            if no file was found or the file was unreadable.
        """
        state = self._persistence.load(session_id, workspace_dir)
        if state is None:
            logger.warning(
                "Session %s not found in workspace %s.", session_id, workspace_dir
            )
        return state

    def list_sessions(self, workspace_dir: str | Path) -> List[SessionState]:
        """Return all sessions stored in *workspace_dir*, sorted by creation time.

        Args:
            workspace_dir: Root of the target workspace.

        Returns:
            List of :class:`~sqlx.session.state.SessionState` objects.
        """
        sessions = self._persistence.list_sessions(workspace_dir)
        logger.debug(
            "Listed %d session(s) from workspace %s.", len(sessions), workspace_dir
        )
        return sessions
