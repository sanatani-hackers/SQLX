"""
sqlx/agent/agent.py
~~~~~~~~~~~~~~~~~~~
Core SQLX AI agent — optimized loop.

Improvements over v1:
  * Exponential-backoff retry on rate-limit / transient errors
  * Tool-call deduplication (same tool + args never fires twice per query)
  * Stuck-loop detection: nudges the LLM after 2 consecutive tool-only rounds
  * RAG context injection: top relevant past findings prepended automatically
  * Clean tool output extraction (uses clean_output key if present)
  * Forced final-summary call when iteration budget is exhausted
  * max_iterations default raised to 12
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlx.ai.provider import DummyProvider, LLMProvider
from sqlx.agent.memory import AgentMemory

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_PATH = Path(__file__).parent.parent / "ai" / "prompts" / "system.md"

_FALLBACK_SYSTEM_PROMPT = (
    "You are SQLX, an AI agent controlling SQLMap.\n"
    "You can analyze web traffic, create isolated workspaces, and run SQLMap against targets.\n"
    "Use the provided tools to interact with the environment.\n"
    "Available file tools: write_workspace_file (create new files), "
    "edit_workspace_file (modify existing files), apply_workspace_patch (unified-diff only)."
)

# Keywords that flag a finding in a tool response
_FINDING_KEYWORDS = frozenset([
    "injection found", "vulnerable", "blocked", "[injection found]",
    "boolean-based", "error-based", "time-based", "union-based",
])

# Retry delays in seconds (rate-limit / transient errors)
_RETRY_DELAYS: Tuple[int, ...] = (2, 5, 15)

# Error substrings that are safe to retry
_RETRIABLE_ERRORS = ("rate limit", "429", "503", "timeout", "connection", "overloaded")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_system_prompt() -> str:
    if _SYSTEM_PROMPT_PATH.exists():
        try:
            text = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError as exc:
            logger.warning("Could not read system prompt: %s", exc)
    return _FALLBACK_SYSTEM_PROMPT


def _response_has_finding(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in _FINDING_KEYWORDS)


def _call_key(tool_name: str, kwargs: Dict[str, Any]) -> tuple:
    """Hashable cache key for a tool call."""
    try:
        items = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in kwargs.items()))
    except TypeError:
        items = tuple(sorted(kwargs.items()))
    return (tool_name, items)


# ---------------------------------------------------------------------------
# Session state stub
# ---------------------------------------------------------------------------

from sqlx.session.state import SessionState


# ---------------------------------------------------------------------------
# Main agent
# ---------------------------------------------------------------------------

class SQLXAgent:
    """
    ReAct-style AI agent with:
      - retry/backoff on transient API errors
      - tool-call deduplication within each query
      - stuck-loop nudge after 2 consecutive tool-only rounds
      - automatic RAG context injection from past target findings
      - forced final-summary call on iteration-budget exhaustion
    """

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        max_iterations: int = 12,
        auto_approve: bool = False,
    ) -> None:
        self.provider: LLMProvider = provider or DummyProvider()
        self.memory: AgentMemory = AgentMemory()
        self.max_iterations: int = max_iterations
        self.auto_approve: bool = auto_approve
        self.active_session: Optional[SessionState] = None
        self._session_workspace_dir: Optional[str] = None
        self.active_target_id: Optional[str] = None   # set by set_session or dashboard

        self.memory.add_system_message(_load_system_prompt())

    def ask_for_approval(self, action: str, risk_level: str = 'medium') -> bool:
        if self.auto_approve:
            return True
        try:
            from rich.panel import Panel
            from rich import print as rprint
            import rich.prompt
            
            rprint(Panel(f"[bold red]Action:[/bold red] {action}\n[bold yellow]Risk Level:[/bold yellow] {risk_level}", title="Approval Required"))
            choice = rich.prompt.Prompt.ask('[A]pprove / [D]eny?', choices=['a','d'], default='d')
            return choice.lower() == 'a'
        except (KeyboardInterrupt, EOFError):
            return False

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------

    def set_session(self, session: SessionState, workspace_dir: str) -> None:
        self.active_session = session
        self._session_workspace_dir = workspace_dir
        self.active_target_id = getattr(session, "target_id", None)
        ctx = (
            f"Session context — ID: {session.id}\n"
            f"Objective: {session.objective}\n"
            f"Findings captured so far: {len(session.findings)}"
        )
        self.memory.add_system_message(ctx)
        logger.debug("Session %s attached to agent.", session.id)

    # ------------------------------------------------------------------
    # Internal: retry-aware LLM call
    # ------------------------------------------------------------------

    def _generate_with_retry(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        max_retries: int = 3,
    ) -> Any:
        """Call the provider with exponential-backoff retry on transient errors."""
        last_exc: Optional[Exception] = None
        for attempt, delay in enumerate(_RETRY_DELAYS[:max_retries]):
            try:
                return self.provider.generate(messages, tools=tools)
            except Exception as exc:
                last_exc = exc
                err_str = str(exc).lower()
                is_retriable = any(tok in err_str for tok in _RETRIABLE_ERRORS)
                if is_retriable and attempt < max_retries - 1:
                    logger.warning(
                        "Retriable error on attempt %d/%d (%s). Retrying in %ds…",
                        attempt + 1, max_retries, exc, delay,
                    )
                    time.sleep(delay)
                    continue
                raise  # non-retriable — propagate immediately
        raise RuntimeError(f"LLM call failed after {max_retries} retries: {last_exc}")

    # ------------------------------------------------------------------
    # Internal: pre-load observations (replaces reactive tool calls)
    # ------------------------------------------------------------------

    def _collect_observations(self, query: str) -> str:
        """Pre-load all available context before the LLM reasons.

        Collects proxy traffic, session findings, workspace state, and RAG
        results in one fast local pass and returns a compact prompt block.
        This eliminates 2–4 redundant tool calls per turn.
        """
        try:
            from sqlx.agent.observations import ObservationCollector
            obs = ObservationCollector().collect(
                target_id=self.active_target_id,
                session=self.active_session,
                workspace_dir=self._session_workspace_dir,
                rag_query=query,
            )
            if obs.is_empty():
                return ""
            return obs.to_prompt_text()
        except Exception as exc:
            logger.debug("Observation collection failed (non-fatal): %s", exc)
            # Fall back to RAG-only context
            try:
                from sqlx.ai.rag import _rag
                return _rag.format_for_context(query, top_k=3)
            except Exception:
                return ""

    # ------------------------------------------------------------------
    # Core loop
    # ------------------------------------------------------------------

    def _ask_internal(self, query: str) -> str:
        from sqlx.agent.tools import registry, _extract_result
        RISKY_TOOLS = {'apply_workspace_patch', 'write_workspace_file', 'rollback_workspace', 'edit_workspace_file'}

        # --- Pre-load all available context BEFORE the LLM reasons --------
        # Collects proxy traffic, session findings, workspace state, and RAG
        # in one fast local pass — eliminates 2–4 redundant reactive tool calls.
        obs_text = self._collect_observations(query)
        extra_messages: List[Dict[str, Any]] = []
        if obs_text:
            extra_messages = [{"role": "system", "content": obs_text}]

        # Per-query state
        seen_calls: Dict[tuple, str] = {}          # call_key -> cached result
        consecutive_tool_rounds: int = 0
        obs_refresh_counter: int = 0               # refresh observations periodically

        for iteration in range(self.max_iterations):

            # Refresh observations every 3 tool-call rounds so context stays current
            if obs_refresh_counter >= 3:
                fresh = self._collect_observations(query)
                if fresh:
                    extra_messages = [{"role": "system", "content": fresh}]
                obs_refresh_counter = 0

            # Build effective message list: persisted memory + ephemeral observations
            messages = self.memory.get_all() + extra_messages

            # --- Stuck-loop nudge -------------------------------------------
            if consecutive_tool_rounds >= 2:
                messages = messages + [{
                    "role": "user",
                    "content": (
                        "You've made several tool calls. "
                        "Please stop calling tools and give me a clear, "
                        "final text summary of everything you have found and done."
                    ),
                }]
                consecutive_tool_rounds = 0   # reset after nudge

            # --- LLM call with retry ----------------------------------------
            try:
                response = self._generate_with_retry(messages, tools=registry.schemas)
            except Exception as exc:
                logger.error("LLM call failed permanently: %s", exc)
                return f"LLM error: {exc}"

            # ---- Plain-text answer -----------------------------------------
            if isinstance(response, str):
                self.memory.add_ai_message(response)
                # Live-add to RAG if it contains findings
                if _response_has_finding(response):
                    self._feed_rag(response)
                return response

            # ---- Tool-call round -------------------------------------------
            consecutive_tool_rounds += 1
            obs_refresh_counter += 1
            self.memory.messages.append(response.model_dump(exclude_none=True))
            
            # Print AI reasoning if present
            ai_text = getattr(response, "content", None)
            if ai_text and str(ai_text).strip():
                try:
                    from rich import print as rprint
                    from rich.panel import Panel
                    from rich.markdown import Markdown
                    rprint(Panel(Markdown(str(ai_text)), title="[bold blue]Agent Thinking[/bold blue]", border_style="blue"))
                except ImportError:
                    print(f"Agent Thinking: {ai_text}")

            for tool_call in response.tool_calls:
                tool_name: str = tool_call.function.name
                try:
                    kwargs: Dict[str, Any] = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError as exc:
                    result = f"Error parsing tool arguments: {exc}"
                    self.memory.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result,
                    })
                    continue

                # --- Deduplication ------------------------------------------
                ckey = _call_key(tool_name, kwargs)
                if ckey in seen_calls:
                    result = f"[cached] {seen_calls[ckey]}"
                    logger.debug("Deduped tool call: %s", tool_name)
                else:
                    # Log the call
                    try:
                        from rich import print as rprint
                        rprint(f"[bold yellow]Agent calling tool:[/bold yellow] {tool_name}({kwargs})")
                    except ImportError:
                        logger.info("Agent calling tool: %s(%s)", tool_name, kwargs)

                    if tool_name in RISKY_TOOLS:
                        if not self.ask_for_approval(f'Agent wants to run {tool_name} with args: {kwargs}', risk_level='high'):
                            result = 'Action denied by user.'
                            seen_calls[ckey] = result
                            self.memory.messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": result,
                            })
                            continue

                    raw = registry.execute_with_timeout(tool_name, kwargs, timeout_seconds=120)
                    result = _extract_result(raw)
                    seen_calls[ckey] = result

                # Publish finding events
                if tool_name in ("analyze_recent_traffic", "run_sqlmap"):
                    if _response_has_finding(result):
                        self._publish_finding_event(tool_name, result)
                        self._feed_rag(result)

                self.memory.messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })

            logger.debug("Iteration %d/%d complete.", iteration + 1, self.max_iterations)

        # ---- Forced final summary ------------------------------------------
        logger.warning("Max iterations reached — forcing final summary call.")
        try:
            summary_messages = self.memory.get_all() + [{
                "role": "user",
                "content": "Summarize all findings and actions in a concise final answer.",
            }]
            summary_response = self._generate_with_retry(summary_messages, tools=None)
            final = (
                summary_response
                if isinstance(summary_response, str)
                else (getattr(summary_response, "content", None) or "")
            )
            self.memory.add_ai_message(final)
            return final
        except Exception as exc:
            logger.error("Forced summary call failed: %s", exc)
            return (
                "I completed multiple tool calls but could not produce a final summary. "
                "Check the tool outputs above for details."
            )

    def ask(self, query: str) -> str:
        """Drive the agentic loop for one user query and return the final answer."""
        if self.active_session is not None and self.active_session.memory_snapshot:
            if len(self.memory.messages) <= 2:
                self.memory.messages = self.active_session.restore_memory()

        self.memory.add_user_message(query)
        final_response = self._ask_internal(query)

        if self.active_session is not None:
            self.active_session.snapshot_memory(self.memory.get_all())
            self.active_session.add_typed_observation('execution', f'Agent answered query: {query[:100]}')
            if _response_has_finding(final_response):
                self.active_session.add_typed_observation('analysis', final_response[:300])
            if self._session_workspace_dir:
                from sqlx.session.manager import SessionManager
                SessionManager().save(self.active_session, self._session_workspace_dir)

        return final_response

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _publish_finding_event(self, source_tool: str, result_text: str) -> None:
        try:
            from sqlx.events.bus import bus
            payload: Dict[str, Any] = {
                "source_tool": source_tool,
                "summary": result_text[:500],
            }
            if self.active_session is not None:
                payload["session_id"] = self.active_session.id
            bus.publish("FindingCreated", payload)
            logger.info("FindingCreated event published from tool '%s'.", source_tool)
        except Exception as exc:
            logger.warning("Failed to publish FindingCreated event: %s", exc)

    def _feed_rag(self, text: str) -> None:
        """Live-add a finding to the RAG index."""
        try:
            from sqlx.ai.rag import _rag
            target_name = (
                self.active_session.id[:8]
                if self.active_session
                else "unknown"
            )
            _rag.add_finding(target_name, text[:1000])
        except Exception:
            pass
