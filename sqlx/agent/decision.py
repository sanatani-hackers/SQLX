"""
sqlx/agent/decision.py
~~~~~~~~~~~~~~~~~~~~~~
Decision engine: determines whether an agent action can execute autonomously,
needs user confirmation, or must be blocked entirely.
"""
from __future__ import annotations
import logging
from enum import Enum
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class Decision(Enum):
    EXECUTE = "execute"   # run immediately
    CONFIRM = "confirm"   # ask user first
    BLOCK   = "block"     # refuse entirely
    DEFER   = "defer"     # wait for more info


# Tools that always require explicit confirmation before executing
_ALWAYS_CONFIRM = frozenset([
    "apply_workspace_patch",
    "edit_workspace_file",
    "write_workspace_file",
    "rollback_workspace",
])

# Tools that are blocked in read-only mode
_WRITE_TOOLS = frozenset([
    "apply_workspace_patch",
    "edit_workspace_file",
    "write_workspace_file",
    "rollback_workspace",
    "run_sqlmap",
])


class DecisionEngine:
    """Determines whether an agent action can proceed autonomously,
    needs user confirmation, or should be blocked."""

    def __init__(self, autonomous: bool = True, read_only: bool = False):
        self.autonomous = autonomous   # False = confirm everything
        self.read_only  = read_only    # True  = block all write tools
        self._confirm_callback: Optional[Callable[[str, dict], bool]] = None
        self._custom_rules: List[Tuple[Callable, Decision, str]] = []

    def set_confirm_callback(self, fn: Callable[[str, dict], bool]) -> None:
        """fn(tool_name, args) -> bool (True = user approved)."""
        self._confirm_callback = fn

    def add_rule(self, condition: Callable[[str, dict], bool],
                 outcome: Decision, reason: str) -> None:
        """Add a custom rule: condition(tool_name, args) -> bool."""
        self._custom_rules.append((condition, outcome, reason))

    def evaluate(self, tool_name: str, args: dict) -> Tuple[Decision, str]:
        """Return (Decision, reason_string) for the given tool call."""

        # Read-only mode blocks write tools
        if self.read_only and tool_name in _WRITE_TOOLS:
            return Decision.BLOCK, f"Read-only mode: {tool_name} is a write operation"

        # Custom rules take priority
        for condition, outcome, reason in self._custom_rules:
            try:
                if condition(tool_name, args):
                    return outcome, reason
            except Exception:
                pass

        # Certain tools need confirmation unless in autonomous mode
        if tool_name in _ALWAYS_CONFIRM:
            if not self.autonomous:
                return Decision.CONFIRM, f"{tool_name} modifies workspace files"

        # Non-autonomous mode: confirm everything
        if not self.autonomous:
            return Decision.CONFIRM, "Agent is in supervised mode"

        return Decision.EXECUTE, "Autonomous execution approved"

    def request_confirmation(self, tool_name: str, args: dict, reason: str) -> bool:
        """Ask the user whether to proceed. Returns True if approved."""
        if self._confirm_callback:
            return self._confirm_callback(tool_name, args)
        # Fallback: stdin prompt
        try:
            desc = f"  Tool:   {tool_name}\n  Args:   {args}\n  Reason: {reason}"
            ans = input(f"\n[APPROVAL REQUIRED]\n{desc}\nProceed? [y/N] ").strip().lower()
            return ans in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False


# Module-level default engine (autonomous by default)
_engine = DecisionEngine(autonomous=True, read_only=False)
