"""
sqlx/target/permissions.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Permission guards for AI agent operations.
Controls which tools are available at each permission level.
"""
from __future__ import annotations
from enum import Enum
from typing import Callable, Optional, Set


class PermissionLevel(Enum):
    READ_ONLY  = 0   # inspect only
    BASIC_SCAN = 1   # safe SQLMap flags
    FULL_SCAN  = 2   # level/risk escalation, tampers
    DATA_DUMP  = 3   # --dump, --dump-all
    WRITE_QUERY = 4  # --os-cmd, --sql-shell


# Minimum permission required per tool
_TOOL_PERMISSIONS: dict = {
    "list_targets":           PermissionLevel.READ_ONLY,
    "read_workspace_file":    PermissionLevel.READ_ONLY,
    "list_workspace_files":   PermissionLevel.READ_ONLY,
    "get_workspace_history":  PermissionLevel.READ_ONLY,
    "search_past_findings":   PermissionLevel.READ_ONLY,
    "analyze_recent_traffic": PermissionLevel.READ_ONLY,
    "fingerprint_target":     PermissionLevel.READ_ONLY,
    "correlate_traffic":      PermissionLevel.READ_ONLY,
    "compare_requests":       PermissionLevel.READ_ONLY,
    "list_sessions":          PermissionLevel.READ_ONLY,
    "run_sqlmap":             PermissionLevel.BASIC_SCAN,
    "replay_request":         PermissionLevel.BASIC_SCAN,
    "save_session_finding":   PermissionLevel.BASIC_SCAN,
    "generate_report":        PermissionLevel.BASIC_SCAN,
    "write_workspace_file":   PermissionLevel.FULL_SCAN,
    "edit_workspace_file":    PermissionLevel.FULL_SCAN,
    "apply_workspace_patch":  PermissionLevel.FULL_SCAN,
    "rollback_workspace":     PermissionLevel.FULL_SCAN,
}

_DESTRUCTIVE_SQLMAP_FLAGS = {
    "--dump", "--dump-all", "--all",
    "--os-cmd", "--os-shell", "--os-pwn",
    "--sql-shell", "--sql-query",
    "--file-write", "--file-dest",
}


class PermissionDenied(Exception):
    pass


class PermissionManager:
    """Controls which operations the AI agent is allowed to perform."""

    def __init__(self, level: PermissionLevel = PermissionLevel.FULL_SCAN):
        self.level = level
        self._confirm_callback: Optional[Callable[[str, dict], bool]] = None

    def set_confirm_callback(self, fn: Callable[[str, dict], bool]) -> None:
        """Called before DATA_DUMP / WRITE_QUERY level tools execute."""
        self._confirm_callback = fn

    def _required_level(self, tool_name: str, args: dict) -> PermissionLevel:
        req = _TOOL_PERMISSIONS.get(tool_name, PermissionLevel.FULL_SCAN)
        # Escalate for destructive SQLMap flags
        if tool_name == "run_sqlmap" and args:
            flags = set(args.get("args", []))
            if flags & _DESTRUCTIVE_SQLMAP_FLAGS:
                if any(f in flags for f in ("--os-cmd", "--os-shell", "--os-pwn",
                                             "--sql-shell", "--sql-query")):
                    req = PermissionLevel.WRITE_QUERY
                else:
                    req = PermissionLevel.DATA_DUMP
        return req

    def check(self, tool_name: str, args: dict = None) -> None:
        """Raise PermissionDenied if tool requires higher permission."""
        required = self._required_level(tool_name, args or {})
        if required.value > self.level.value:
            raise PermissionDenied(
                f'Tool "{tool_name}" requires {required.name} permission '
                f"but current level is {self.level.name}."
            )
        # DATA_DUMP / WRITE_QUERY always need explicit confirmation
        if required.value >= PermissionLevel.DATA_DUMP.value:
            if self._confirm_callback and not self._confirm_callback(tool_name, args or {}):
                raise PermissionDenied(f"User denied permission for {tool_name}")

    def is_allowed(self, tool_name: str, args: dict = None) -> bool:
        try:
            self.check(tool_name, args)
            return True
        except PermissionDenied:
            return False

    def get_allowed_tools(self) -> Set[str]:
        return {t for t in _TOOL_PERMISSIONS if self.is_allowed(t)}

    def summary(self) -> str:
        allowed = self.get_allowed_tools()
        return (
            f"Permission level: {self.level.name} — "
            f"{len(allowed)}/{len(_TOOL_PERMISSIONS)} tools available"
        )


# Module-level singleton (FULL_SCAN by default)
_permissions = PermissionManager(PermissionLevel.FULL_SCAN)
