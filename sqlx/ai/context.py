"""
sqlx/ai/context.py
~~~~~~~~~~~~~~~~~~
ContextBuilder — assembles the structured message list sent to the LLM.
Combines system prompt, RAG context, observations, session state, and
the user query in a single clean pass, within a token budget.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

MAX_CONTEXT_CHARS = 12_000


class ContextBuilder:
    """Assembles a clean LLM message list from multiple sources."""

    def __init__(self):
        self._system: str = ""
        self._rag_context: str = ""
        self._observations: str = ""
        self._session_context: str = ""
        self._target_context: str = ""
        self._history: List[Dict[str, str]] = []

    # ── setters ────────────────────────────────────────────────────────────

    def set_system_prompt(self, text: str) -> "ContextBuilder":
        self._system = text
        return self

    def set_rag_context(self, text: str) -> "ContextBuilder":
        self._rag_context = text
        return self

    def set_observations(self, text: str) -> "ContextBuilder":
        self._observations = text
        return self

    def set_target(self, target) -> "ContextBuilder":
        if target:
            self._target_context = (
                f"Active target: {target.name}\n"
                f"URL: {target.target_url}\n"
                f"ID: {target.id}"
            )
        return self

    def set_session(self, session) -> "ContextBuilder":
        if session:
            self._session_context = (
                f"Session: {session.id}\n"
                f"Objective: {session.objective}\n"
                f"Findings so far: {len(session.findings)}\n"
                f"Status: {session.status}"
            )
        return self

    def set_history(self, history: List[Dict[str, str]]) -> "ContextBuilder":
        self._history = history
        return self

    # ── build ──────────────────────────────────────────────────────────────

    def build(self, user_query: str) -> List[Dict[str, str]]:
        """Return a message list ready for provider.generate()."""
        messages: List[Dict[str, str]] = []

        # Assemble enriched system message
        system_parts = []
        if self._system:
            system_parts.append(self._system)
        if self._target_context:
            system_parts.append(self._target_context)
        if self._session_context:
            system_parts.append(self._session_context)
        if self._rag_context:
            system_parts.append(self._rag_context)
        if self._observations:
            system_parts.append(self._observations)

        if system_parts:
            combined = "\n\n".join(system_parts)
            if len(combined) > MAX_CONTEXT_CHARS:
                combined = combined[:MAX_CONTEXT_CHARS] + "\n...[context trimmed for token budget]"
            messages.append({"role": "system", "content": combined})

        # Conversation history
        messages.extend(self._history)

        # Current user query
        messages.append({"role": "user", "content": user_query})

        return messages

    def reset_ephemeral(self) -> None:
        """Clear per-query ephemeral fields (RAG, observations) after each call."""
        self._rag_context = ""
        self._observations = ""

    def reset_all(self) -> None:
        """Full reset (e.g. target switch)."""
        self.__init__()


# Module-level singleton
_builder = ContextBuilder()
