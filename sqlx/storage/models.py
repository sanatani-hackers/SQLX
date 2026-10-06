"""
sqlx/storage/models.py
~~~~~~~~~~~~~~~~~~~~~~
Dataclass-based models for SQLX database entities.
These mirror the SQLite schema in database.py.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TargetRecord:
    id: str
    name: str
    url: str
    workspace_dir: str
    created_at: str
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "url": self.url,
            "workspace_dir": self.workspace_dir,
            "created_at": self.created_at, "description": self.description,
        }


@dataclass
class SessionRecord:
    id: str
    target_id: str
    objective: str
    status: str = "active"
    created_at: str = ""
    updated_at: str = ""
    findings_count: int = 0


@dataclass
class FindingRecord:
    session_id: str
    target_id: str
    finding: str
    severity: str = "info"
    created_at: str = ""
    id: Optional[int] = None


@dataclass
class AuditEvent:
    event_name: str
    actor: str = "system"
    target_id: Optional[str] = None
    session_id: Optional[str] = None
    data: dict = field(default_factory=dict)
    created_at: str = ""
    id: Optional[int] = None
