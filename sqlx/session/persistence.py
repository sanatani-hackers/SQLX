"""
sqlx/session/persistence.py
---------------------------
File-system persistence layer for :class:`~sqlx.session.state.SessionState`.

Sessions are stored as individual JSON files inside a ``sessions/`` sub-directory
of the target's workspace directory::

    <workspace_dir>/
    └── sessions/
        ├── <session-uuid>.json
        └── <session-uuid>.json

This keeps all session data co-located with the workspace it belongs to,
making workspaces self-contained and easy to archive or transfer.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from sqlx.session.state import SessionState

logger = logging.getLogger(__name__)

_SESSIONS_SUBDIR = "sessions"


class SessionPersistence:
    """Saves and loads :class:`~sqlx.session.state.SessionState` objects to disk.

    Each session is stored as a single JSON file named ``<session_id>.json``
    inside ``<workspace_dir>/sessions/``.

    This class is intentionally stateless — all methods accept the necessary
    paths as parameters so that the same instance can be reused across multiple
    workspaces.
    """

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sessions_dir(workspace_dir: str | Path) -> Path:
        """Return the ``sessions/`` directory path for *workspace_dir*.

        The directory is **not** created by this helper; creation is deferred
        to :meth:`save` so that read-only operations do not mutate the fs.
        """
        return Path(workspace_dir) / _SESSIONS_SUBDIR

    @staticmethod
    def _session_path(workspace_dir: str | Path, session_id: str) -> Path:
        """Return the JSON file path for a specific session."""
        return SessionPersistence._sessions_dir(workspace_dir) / f"{session_id}.json"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, state: SessionState, workspace_dir: str | Path) -> Path:
        """Persist *state* to ``<workspace_dir>/sessions/<id>.json``.

        The ``sessions/`` directory is created automatically if it does not
        already exist.

        Args:
            state:         The session state to serialise.
            workspace_dir: Root of the target workspace.

        Returns:
            The :class:`~pathlib.Path` of the written file.

        Raises:
            OSError: If the file cannot be written (permissions, disk full, etc.).
        """
        sessions_dir = self._sessions_dir(workspace_dir)
        sessions_dir.mkdir(parents=True, exist_ok=True)

        file_path = self._session_path(workspace_dir, state.id)

        # Pydantic v2 uses model_dump_json(); fall back to v1's json() if needed.
        try:
            json_str = state.model_dump_json(indent=2)
        except AttributeError:
            json_str = state.json(indent=2)  # Pydantic v1

        file_path.write_text(json_str, encoding="utf-8")
        logger.debug("Session %s saved → %s", state.id, file_path)
        return file_path

    def load(
        self,
        session_id: str,
        workspace_dir: str | Path,
    ) -> Optional[SessionState]:
        """Load and deserialise a session from disk.

        Args:
            session_id:    UUID string of the target session.
            workspace_dir: Root of the target workspace.

        Returns:
            A :class:`~sqlx.session.state.SessionState` if the file exists and
            parses successfully; ``None`` otherwise.
        """
        file_path = self._session_path(workspace_dir, session_id)

        if not file_path.exists():
            logger.debug("Session file not found: %s", file_path)
            return None

        try:
            raw = file_path.read_text(encoding="utf-8")
            data = json.loads(raw)

            # Support both Pydantic v1 (parse_obj) and v2 (model_validate).
            try:
                state = SessionState.model_validate(data)
            except AttributeError:
                state = SessionState.parse_obj(data)  # Pydantic v1

            logger.debug("Session %s loaded from %s", session_id, file_path)
            return state

        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.error(
                "Failed to load session %s from %s: %s",
                session_id,
                file_path,
                exc,
            )
            return None

    def list_sessions(self, workspace_dir: str | Path) -> List[SessionState]:
        """Return all persisted sessions in *workspace_dir*.

        Sessions that fail to deserialise are skipped with a warning rather
        than raising, so that one corrupt file does not block access to others.

        Args:
            workspace_dir: Root of the target workspace.

        Returns:
            List of :class:`~sqlx.session.state.SessionState` objects sorted
            by :attr:`~sqlx.session.state.SessionState.created_at` ascending.
        """
        sessions_dir = self._sessions_dir(workspace_dir)

        if not sessions_dir.exists():
            return []

        states: List[SessionState] = []
        for json_file in sorted(sessions_dir.glob("*.json")):
            session_id = json_file.stem
            state = self.load(session_id, workspace_dir)
            if state is not None:
                states.append(state)
            else:
                logger.warning("Skipping unreadable session file: %s", json_file)

        # Sort by creation time so callers get a chronological list.
        states.sort(key=lambda s: s.created_at)
        return states
