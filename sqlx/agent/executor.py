"""
sqlx/agent/executor.py
~~~~~~~~~~~~~~~~~~~~~~
Tool executor with pre/post hooks, timing, event-bus publishing,
and clean error wrapping.
"""
from __future__ import annotations
import logging
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ExecutionResult:
    def __init__(self, tool: str, args: dict, output: str,
                 success: bool, duration_ms: float = 0.0, error: str = None):
        self.tool = tool
        self.args = args
        self.output = output
        self.success = success
        self.duration_ms = duration_ms
        self.error = error

    def __str__(self) -> str:
        return self.output

    def __bool__(self) -> bool:
        return self.success


class ToolExecutor:
    """Wraps the tool registry with pre/post hooks, timing, and safe error handling."""

    def __init__(self):
        self._pre_hooks: List[Callable] = []
        self._post_hooks: List[Callable] = []
        self._blocked: set = set()

    # ── configuration ──────────────────────────────────────────────────────

    def add_pre_hook(self, fn: Callable[[str, dict], None]) -> None:
        """Called before every tool execution: fn(tool_name, args)."""
        self._pre_hooks.append(fn)

    def add_post_hook(self, fn: Callable[[ExecutionResult], None]) -> None:
        """Called after every tool execution: fn(result)."""
        self._post_hooks.append(fn)

    def block_tool(self, tool_name: str) -> None:
        """Prevent a tool from executing (scope/permission enforcement)."""
        self._blocked.add(tool_name)

    def unblock_tool(self, tool_name: str) -> None:
        self._blocked.discard(tool_name)

    # ── execution ──────────────────────────────────────────────────────────

    def execute(self, tool_name: str, args: Dict[str, Any]) -> ExecutionResult:
        """Execute a registered tool with timing, hooks, and error wrapping."""
        from sqlx.agent.tools import registry

        if tool_name in self._blocked:
            return ExecutionResult(
                tool=tool_name, args=args,
                output=f'Tool "{tool_name}" is blocked by scope enforcement.',
                success=False, error="blocked",
            )

        # Pre-hooks
        for hook in self._pre_hooks:
            try:
                hook(tool_name, args)
            except Exception as exc:
                logger.warning("Pre-hook error: %s", exc)

        start = time.monotonic()
        try:
            raw = registry.execute(tool_name, args)
            # If runner returns a dict (run_and_collect), extract clean_output
            if isinstance(raw, dict):
                output = raw.get("clean_output") or str(raw)
            else:
                output = str(raw)
            success, error = True, None
        except Exception as exc:
            output = f"Tool error [{tool_name}]: {exc}"
            success, error = False, str(exc)
            logger.error("Tool %s failed: %s", tool_name, exc)

        duration_ms = (time.monotonic() - start) * 1000
        result = ExecutionResult(
            tool=tool_name, args=args, output=output,
            success=success, duration_ms=duration_ms, error=error,
        )

        # Post-hooks
        for hook in self._post_hooks:
            try:
                hook(result)
            except Exception as exc:
                logger.warning("Post-hook error: %s", exc)

        # Publish event
        try:
            from sqlx.events.bus import bus
            bus.publish("ToolExecuted", {
                "tool": tool_name, "args": args,
                "success": success, "duration_ms": duration_ms,
            })
        except Exception:
            pass

        return result


# Module-level singleton
_executor = ToolExecutor()
