"""
sqlx/events/events.py
---------------------
Typed event constants/dataclasses for the SQLX EventBus.

Each event is a simple dataclass with:
  - ``name``  — class-level string constant used as the EventBus topic key.
  - ``data``  — instance-level dict carrying arbitrary event payload.

Usage::

    from sqlx.events.events import SessionStarted
    from sqlx.events.bus import bus

    bus.publish(SessionStarted.name, SessionStarted(data={"session_id": sid}))
"""

from dataclasses import dataclass, field
from typing import Any, Dict


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

@dataclass
class _BaseEvent:
    """Common base for all SQLX events.  Sub-classes must define ``name``."""

    #: Arbitrary key/value payload for the event.
    data: Dict[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "name"):
            raise TypeError(f"Event class {cls.__name__!r} must define a 'name' class variable.")


# ---------------------------------------------------------------------------
# Concrete event types
# ---------------------------------------------------------------------------

@dataclass
class TargetCreated(_BaseEvent):
    """Fired when a new scan target is registered in the workspace.

    Expected ``data`` keys:
      - ``target_id``   (str)  -- internal target identifier
      - ``url``         (str)  -- target URL
      - ``workspace``   (str)  -- absolute path to the workspace directory
    """
    name: str = field(default="target.created", init=False, repr=False)


@dataclass
class SessionStarted(_BaseEvent):
    """Fired when a new session is started via ``SessionManager``.

    Expected ``data`` keys:
      - ``session_id``  (str)  -- UUID of the new session
      - ``target_id``   (str)
      - ``objective``   (str)
    """
    name: str = field(default="session.started", init=False, repr=False)


@dataclass
class ProxyRequestCaptured(_BaseEvent):
    """Fired when the SQLX proxy intercepts an HTTP request.

    Expected ``data`` keys:
      - ``request_id``  (str)
      - ``method``      (str)
      - ``url``         (str)
      - ``headers``     (dict)
      - ``body``        (str | None)
    """
    name: str = field(default="proxy.request_captured", init=False, repr=False)


@dataclass
class ProxyResponseReceived(_BaseEvent):
    """Fired when the SQLX proxy receives an HTTP response.

    Expected ``data`` keys:
      - ``request_id``  (str)
      - ``status_code`` (int)
      - ``headers``     (dict)
      - ``body``        (str | None)
    """
    name: str = field(default="proxy.response_received", init=False, repr=False)


@dataclass
class SQLMapStarted(_BaseEvent):
    """Fired when a SQLMap subprocess is launched.

    Expected ``data`` keys:
      - ``session_id``  (str)
      - ``args``        (list[str])  -- command-line arguments passed to sqlmap
      - ``pid``         (int | None) -- OS process ID if available
    """
    name: str = field(default="sqlmap.started", init=False, repr=False)


@dataclass
class SQLMapOutputReceived(_BaseEvent):
    """Fired for each chunk of stdout/stderr produced by SQLMap.

    Expected ``data`` keys:
      - ``session_id``  (str)
      - ``line``        (str)  -- raw output line
      - ``stream``      (str)  -- 'stdout' or 'stderr'
    """
    name: str = field(default="sqlmap.output_received", init=False, repr=False)


@dataclass
class AnalysisCompleted(_BaseEvent):
    """Fired when the AI analysis engine finishes processing SQLMap output.

    Expected ``data`` keys:
      - ``session_id``  (str)
      - ``summary``     (str)
      - ``findings``    (list[dict])
    """
    name: str = field(default="analysis.completed", init=False, repr=False)


@dataclass
class PatchApplied(_BaseEvent):
    """Fired when a remediation patch is applied to the workspace.

    Expected ``data`` keys:
      - ``session_id``  (str)
      - ``patch_id``    (str)
      - ``file_path``   (str)
      - ``description`` (str)
    """
    name: str = field(default="patch.applied", init=False, repr=False)


@dataclass
class RollbackCompleted(_BaseEvent):
    """Fired when a workspace rollback operation finishes.

    Expected ``data`` keys:
      - ``session_id``       (str)
      - ``revision_from``    (str)
      - ``revision_to``      (str)
      - ``files_restored``   (list[str])
    """
    name: str = field(default="rollback.completed", init=False, repr=False)


@dataclass
class FindingCreated(_BaseEvent):
    """Fired when a new vulnerability finding is recorded.

    Expected ``data`` keys:
      - ``session_id``   (str)
      - ``finding_id``   (str)
      - ``severity``     (str)   -- e.g. 'high', 'medium', 'low'
      - ``description``  (str)
      - ``parameter``    (str | None)
    """
    name: str = field(default="finding.created", init=False, repr=False)


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

#: All concrete event classes, useful for iteration or schema generation.
ALL_EVENTS = [
    TargetCreated,
    SessionStarted,
    ProxyRequestCaptured,
    ProxyResponseReceived,
    SQLMapStarted,
    SQLMapOutputReceived,
    AnalysisCompleted,
    PatchApplied,
    RollbackCompleted,
    FindingCreated,
]

#: Mapping from event name string to event class.
EVENT_REGISTRY: Dict[str, type] = {cls.name: cls for cls in ALL_EVENTS}
