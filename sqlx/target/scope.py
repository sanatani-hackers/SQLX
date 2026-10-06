"""
sqlx/target/scope.py
~~~~~~~~~~~~~~~~~~~~
Scope enforcement — prevents scanning hosts outside the authorized target.
"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse


class ScopeViolation(Exception):
    pass


class ScopeChecker:
    """Validates URLs against an authorized scope allowlist."""

    def __init__(self):
        self._allowed_hosts: List[str] = []
        self._blocked_patterns: List[str] = []

    def add_target_url(self, url: str) -> None:
        """Auto-extract host from target URL and add to allowlist."""
        host = urlparse(url).netloc.lower()
        if host and host not in self._allowed_hosts:
            self._allowed_hosts.append(host)

    def add_allowed_host(self, host: str) -> None:
        h = host.lower()
        if h not in self._allowed_hosts:
            self._allowed_hosts.append(h)

    def add_blocked_pattern(self, pattern: str) -> None:
        """Regex — any URL matching is always blocked."""
        self._blocked_patterns.append(pattern)

    def is_allowed(self, url: str) -> bool:
        if not self._allowed_hosts:
            return True   # No scope configured = permissive

        for pattern in self._blocked_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False

        host = urlparse(url).netloc.lower()
        return host in self._allowed_hosts

    def check(self, url: str) -> None:
        """Raise ScopeViolation if URL is out of scope."""
        if not self.is_allowed(url):
            raise ScopeViolation(
                f"URL out of scope: {url}\n"
                f"Allowed hosts: {self._allowed_hosts}"
            )

    def validate_sqlmap_args(self, args: List[str]) -> None:
        """Check that -u / --url in SQLMap args is within scope."""
        for i, arg in enumerate(args):
            if arg in ("-u", "--url") and i + 1 < len(args):
                self.check(args[i + 1])

    def summary(self) -> str:
        if not self._allowed_hosts:
            return "Scope: unrestricted (no target configured)"
        return f"Scope: allowed hosts = {self._allowed_hosts}"


# Module-level singleton
_scope = ScopeChecker()
