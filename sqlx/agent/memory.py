"""
sqlx/agent/memory.py
~~~~~~~~~~~~~~~~~~~~
Sliding-window conversation memory for the SQLX agent.

Keeps system messages intact while pruning the oldest non-system messages
when the window grows beyond ``max_messages``.  This prevents unbounded
context growth when running long agentic loops.
"""

from __future__ import annotations

from typing import Any, Dict, List


class AgentMemory:
    """Manages a bounded list of chat messages for LLM context.

    Parameters
    ----------
    max_messages:
        Maximum total messages to keep in memory (default 50).
        When the limit is exceeded the oldest *non-system* messages are
        dropped first, preserving all system messages unconditionally.
    """

    def __init__(self, max_messages: int = 50) -> None:
        self.messages: List[Dict[str, Any]] = []
        self.max_messages: int = max_messages

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_user_message(self, content: str) -> None:
        """Append a user-role message and apply the sliding window."""
        self.messages.append({"role": "user", "content": content})
        self._trim()

    def add_ai_message(self, content: str) -> None:
        """Append an assistant-role message and apply the sliding window."""
        self.messages.append({"role": "assistant", "content": content})
        self._trim()

    def add_system_message(self, content: str) -> None:
        """Prepend a system-role message.

        System messages are inserted at the front of the list (or just
        after any existing system messages) so they always remain at the
        top of the context window.
        """
        # Count how many system messages already exist at the head
        insert_pos = 0
        for msg in self.messages:
            if msg.get("role") == "system":
                insert_pos += 1
            else:
                break
        self.messages.insert(insert_pos, {"role": "system", "content": content})
        self._trim()

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_all(self) -> List[Dict[str, Any]]:
        """Return the full message list in chronological order."""
        return list(self.messages)

    def clear_non_system(self) -> None:
        """Remove all non-system messages, keeping the system context."""
        self.messages = [m for m in self.messages if m.get("role") == "system"]

    def token_estimate(self) -> int:
        """Rough token count estimate (characters ÷ 4).

        Only counts ``str`` content fields; structured tool-call payloads
        that are dicts or None are skipped to avoid errors.

        Returns
        -------
        int
            Estimated number of tokens in the current message window.
        """
        total_chars = 0
        for msg in self.messages:
            content = msg.get("content")
            if isinstance(content, str):
                total_chars += len(content)
        return total_chars // 4

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _trim(self) -> None:
        """Enforce the sliding window by dropping old non-system messages."""
        if len(self.messages) <= self.max_messages:
            return

        # Separate system messages from the rest
        system_msgs = [m for m in self.messages if m.get("role") == "system"]
        non_system_msgs = [m for m in self.messages if m.get("role") != "system"]

        # How many non-system messages can we keep?
        allowed_non_system = self.max_messages - len(system_msgs)
        if allowed_non_system < 0:
            allowed_non_system = 0

        # Drop the *oldest* non-system messages (front of list)
        trimmed = non_system_msgs[-allowed_non_system:] if allowed_non_system else []

        # Reconstruct: system messages first, then chronological remainder
        self.messages = system_msgs + trimmed

    def __len__(self) -> int:
        return len(self.messages)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AgentMemory(messages={len(self.messages)}, "
            f"max={self.max_messages}, "
            f"tokens≈{self.token_estimate()})"
        )
