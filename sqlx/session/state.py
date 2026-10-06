"""
sqlx/session/state.py
---------------------
Pydantic model representing the persistent state of a SQLX scan session.

A :class:`SessionState` is the canonical in-memory and on-disk representation
of everything known about an ongoing or completed session, including the target
being scanned, the AI's objective, all collected findings, free-form
observations, historical SQLMap argument lists, and the current workspace
revision.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(tz=timezone.utc)


def _new_uuid() -> str:
    """Generate a fresh UUID4 string."""
    return str(uuid.uuid4())


class SessionState(BaseModel):
    """Persistent state for a single SQLX scan session.

    Attributes:
        id:                    Unique session identifier (UUID4 string).
        target_id:             Identifier of the scan target.
        objective:             Human-readable description of the scan goal.
        created_at:            UTC datetime when the session was created.
        last_updated:          UTC datetime of the most recent state change.
        findings:              List of finding dicts produced by the AI or SQLMap.
        observations:          Free-form textual observations accumulated during
                               the session (e.g. AI commentary, notable events).
        sqlmap_args_history:   Ordered list of argument lists passed to SQLMap.
                               Each entry is a ``list[str]`` corresponding to one
                               SQLMap invocation.
        workspace_revision:    Opaque string identifying the current workspace
                               revision (e.g. a git SHA or a sequential counter).
        status:                Session lifecycle status.
                               One of ``'active'``, ``'completed'``, ``'failed'``,
                               ``'paused'``.  Defaults to ``'active'``.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    id: str = Field(
        default_factory=_new_uuid,
        description="Unique session identifier (UUID4).",
    )
    target_id: str = Field(
        ...,
        description="Identifier of the scan target this session belongs to.",
    )
    objective: str = Field(
        ...,
        description="Human-readable description of what this session aims to achieve.",
    )

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    created_at: datetime = Field(
        default_factory=_utcnow,
        description="UTC datetime when the session was first created.",
    )
    last_updated: datetime = Field(
        default_factory=_utcnow,
        description="UTC datetime of the most recent state mutation.",
    )

    # ------------------------------------------------------------------
    # Accumulated data
    # ------------------------------------------------------------------
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Vulnerability findings produced during this session. "
            "Each entry is a free-form dict; recommended keys: "
            "'finding_id', 'severity', 'description', 'parameter'."
        ),
    )
    observations: List[str] = Field(
        default_factory=list,
        description=(
            "Free-form textual observations accumulated during the session "
            "(e.g. AI commentary, notable intermediate results)."
        ),
    )
    sqlmap_args_history: List[List[str]] = Field(
        default_factory=list,
        description=(
            "Ordered history of SQLMap argument lists.  Each sub-list "
            "corresponds to a single SQLMap invocation."
        ),
    )

    # ------------------------------------------------------------------
    # Workspace tracking
    # ------------------------------------------------------------------
    workspace_revision: str = Field(
        default="",
        description=(
            "Opaque identifier of the current workspace revision "
            "(e.g. git SHA or sequential counter string)."
        ),
    )
    status: str = Field(
        default="active",
        description=(
            "Session lifecycle status. "
            "Allowed values: 'active', 'completed', 'failed', 'paused'."
        ),
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def touch(self) -> None:
        """Update :attr:`last_updated` to the current UTC time."""
        self.last_updated = _utcnow()

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Append *finding* to :attr:`findings` and refresh :attr:`last_updated`.

        Args:
            finding: Dict describing the vulnerability finding.
        """
        self.findings.append(finding)
        self.touch()

    def add_observation(self, text: str) -> None:
        """Append *text* to :attr:`observations` and refresh :attr:`last_updated`.

        Args:
            text: Free-form observation string.
        """
        self.observations.append(text)
        self.touch()

    def record_sqlmap_args(self, args: List[str]) -> None:
        """Append *args* to :attr:`sqlmap_args_history` and refresh timestamp.

        Args:
            args: The argument list passed to a SQLMap invocation.
        """
        self.sqlmap_args_history.append(list(args))
        self.touch()

    # ------------------------------------------------------------------
    # Pydantic config
    # ------------------------------------------------------------------

    model_config = {
        # Allow datetime objects to round-trip through JSON without issues.
        "json_encoders": {datetime: lambda dt: dt.isoformat()},
    }
