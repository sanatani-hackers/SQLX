"""
sqlx/analysis/response.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Deep analysis of HTTP responses: SQL error patterns, WAF blocks,
DBMS fingerprinting, and body content classification.
"""
from __future__ import annotations
import difflib
import hashlib
import re
from typing import Any, Dict, List, Optional

# SQL error patterns indicating error-based injection
_SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"syntax error.*postgresql",
    r"microsoft sql server",
    r"odbc sql server driver",
    r"ora-\d{5}",
    r"oracle error",
    r"db2 sql error",
    r"sqlite3\.operationalerror",
    r"division by zero",
    r"supplied argument is not a valid mysql",
]
_SQL_ERROR_RE = re.compile("|".join(_SQL_ERROR_PATTERNS), re.IGNORECASE)

# WAF block body patterns
_WAF_BLOCK_PATTERNS = [
    r"access denied",
    r"forbidden.*request",
    r"security violation",
    r"your request has been blocked",
    r"illegal character",
    r"cloudflare",
    r"mod_security",
    r"barracuda",
]
_WAF_BLOCK_RE = re.compile("|".join(_WAF_BLOCK_PATTERNS), re.IGNORECASE)

# WAF status codes
_WAF_STATUS_CODES = {403, 406, 429, 503}

# DBMS hint patterns
_DBMS_PATTERNS: Dict[str, str] = {
    "MySQL":      r"mysql|mariadb",
    "PostgreSQL": r"postgresql|pg_",
    "MSSQL":      r"microsoft sql server|mssql|sqlserver",
    "Oracle":     r"ora-\d{5}|oracle error",
    "SQLite":     r"sqlite",
    "DB2":        r"db2 sql",
}


class ResponseAnalyser:
    """Analyses a single HTTP response for injection and WAF signals."""

    def __init__(self, status: int, headers: Dict[str, str],
                 body: str, latency_ms: float = 0.0):
        self.status     = status
        self.headers    = headers
        self.body       = body
        self.latency_ms = latency_ms

    @classmethod
    def from_dict(cls, d: dict) -> "ResponseAnalyser":
        return cls(
            status=int(d.get("status", 0)),
            headers=d.get("headers", {}),
            body=d.get("body_text", "") or d.get("body", ""),
            latency_ms=float(d.get("latency_ms", 0)),
        )

    def has_sql_error(self) -> bool:
        return bool(_SQL_ERROR_RE.search(self.body))

    def has_waf_block(self) -> bool:
        return (
            self.status in _WAF_STATUS_CODES
            or bool(_WAF_BLOCK_RE.search(self.body[:3000]))
        )

    def is_suspicious(self) -> bool:
        return self.has_sql_error() or self.has_waf_block() or self.status in (500, 503)

    def extract_dbms_hints(self) -> List[str]:
        hints = []
        for dbms, pattern in _DBMS_PATTERNS.items():
            if re.search(pattern, self.body, re.IGNORECASE):
                hints.append(dbms)
        return hints

    def analyse(self) -> Dict[str, Any]:
        ct = next((v for k, v in self.headers.items()
                   if k.lower() == "content-type"), "")
        return {
            "status":          self.status,
            "body_length":     len(self.body),
            "has_sql_error":   self.has_sql_error(),
            "has_waf_block":   self.has_waf_block(),
            "is_suspicious":   self.is_suspicious(),
            "dbms_hints":      self.extract_dbms_hints(),
            "latency_ms":      self.latency_ms,
            "content_type":    ct,
        }

    # ── static helpers ─────────────────────────────────────────────────────

    @staticmethod
    def fingerprint(body: str) -> str:
        """Return a SHA-256 hex digest of the first 64 KB of *body*.

        Useful for deduplicating identical responses or detecting baseline
        drift when the same URL is requested multiple times.
        """
        return hashlib.sha256(body[:65536].encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def diff_bodies(a: str, b: str) -> Dict[str, Any]:
        """Compare two response bodies with :class:`difflib.SequenceMatcher`.

        Returns a dict with keys:
        - ``added``   – lines that appear in *b* but not *a*
        - ``removed`` – lines that appear in *a* but not *b*
        - ``changed`` – True when any lines differ
        - ``ratio``   – similarity ratio (1.0 = identical, 0.0 = nothing in common)
        """
        a_lines = a.splitlines()
        b_lines = b.splitlines()
        sm = difflib.SequenceMatcher(None, a_lines, b_lines, autojunk=False)
        added = removed = 0
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("replace", "delete"):
                removed += i2 - i1
            if tag in ("replace", "insert"):
                added += j2 - j1
        return {
            "added":   added,
            "removed": removed,
            "changed": added > 0 or removed > 0,
            "ratio":   round(1.0 - sm.ratio(), 4),   # 0 = identical, 1 = totally different
        }


class ResponseDiffer:
    """Compare two HTTP responses from the proxy history to spot anomalies.

    This is intentionally stateless — pass the two proxy-history record dicts
    returned by :meth:`ProxyHistory.get_by_id` or :meth:`ProxyHistory.get_all`.
    """

    def diff(self, baseline: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Compare *baseline* and *candidate* proxy history records.

        Parameters
        ----------
        baseline:
            The reference (normal) request/response record.
        candidate:
            The request/response to compare against the baseline.

        Returns
        -------
        dict with keys:
        - ``status_changed``  – True if HTTP status codes differ
        - ``length_delta``    – Signed byte difference in response body size
        - ``timing_delta_ms`` – Signed latency difference in milliseconds
        - ``body_ratio``      – Body divergence ratio (0 = identical, 1 = totally different)
        - ``suspicious``      – True if any anomaly threshold is met
        - ``reasons``         – Human-readable list explaining why suspicious=True
        """
        reasons: List[str] = []

        # ── status ──────────────────────────────────────────────────────────
        s1 = baseline.get("status", 0)
        s2 = candidate.get("status", 0)
        status_changed = s1 != s2
        if status_changed:
            reasons.append(f"Status changed: {s1} → {s2}")

        # ── body length ─────────────────────────────────────────────────────
        b1 = str(baseline.get("response_body") or "")
        b2 = str(candidate.get("response_body") or "")
        length_delta = len(b2) - len(b1)
        if b1 and abs(length_delta) / max(len(b1), 1) > 0.3:
            reasons.append(
                f"Body length changed by {length_delta:+d} bytes "
                f"({abs(length_delta) / max(len(b1), 1):.0%})"
            )

        # ── timing ──────────────────────────────────────────────────────────
        t1 = float(baseline.get("latency_ms") or 0)
        t2 = float(candidate.get("latency_ms") or 0)
        timing_delta_ms = t2 - t1

        # ── body ratio ──────────────────────────────────────────────────────
        body_diff = ResponseAnalyser.diff_bodies(b1, b2)
        body_ratio = body_diff["ratio"]
        if body_ratio > 0.3:
            reasons.append(f"Response body differs by {body_ratio:.0%}")

        suspicious = bool(reasons)

        return {
            "status_changed":  status_changed,
            "length_delta":    length_delta,
            "timing_delta_ms": round(timing_delta_ms, 2),
            "body_ratio":      body_ratio,
            "suspicious":      suspicious,
            "reasons":         reasons,
        }
