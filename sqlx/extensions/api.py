"""
sqlx/extensions/api.py
~~~~~~~~~~~~~~~~~~~~~~
Public sandboxed API for SQLX extensions — what extensions can import and use.
"""
from __future__ import annotations
from typing import Any, Dict, List


class ExtensionAPI:
    """Safe interface for extensions to interact with SQLX core systems."""

    def get_targets(self) -> List[Dict[str, Any]]:
        from sqlx.target.manager import TargetManager
        return [
            {"id": t.id, "name": t.name, "url": t.target_url}
            for t in TargetManager().list_targets()
        ]

    def get_recent_traffic(self, limit: int = 10) -> List[dict]:
        try:
            from sqlx import proxy_history
            return proxy_history.get_recent(limit)
        except Exception:
            return []

    def log_finding(self, target_id: str, session_id: str,
                    finding: str, severity: str = "info") -> str:
        from sqlx.storage.database import get_db
        get_db().insert_finding(target_id, session_id, finding, severity)
        return f"Finding logged for target {target_id}"

    def publish_event(self, event_name: str, data: dict) -> None:
        try:
            from sqlx.events.bus import bus
            bus.publish(event_name, data)
        except Exception:
            pass

    def register_tool(self, name: str, description: str,
                      fn: Any, parameters: dict) -> None:
        """Register an extension-provided tool into the agent tool registry."""
        from sqlx.agent.tools import registry
        registry.tools[name] = fn
        registry.schemas.append({
            "type": "function",
            "function": {
                "name":        name,
                "description": description,
                "parameters":  parameters,
            },
        })

    def query_findings(self, target_id: str = None) -> List[dict]:
        from sqlx.storage.database import get_db
        return get_db().get_findings(target_id=target_id)


# Shared API instance
api = ExtensionAPI()
