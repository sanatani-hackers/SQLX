"""
sqlx/analysis/response.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Deep analysis of HTTP responses: SQL error patterns, WAF blocks,
DBMS fingerprinting, and body content classification.
"""
from __future__ import annotations
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
