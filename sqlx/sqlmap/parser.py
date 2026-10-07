"""
sqlx/sqlmap/parser.py
──────────────────────
Parses raw SQLMap stdout into structured Python dicts.

Classes
-------
SQLMapOutputParser
    Stateless line-by-line parser.  Each line is classified and returned
    as a typed dict, or *None* when the line carries no structured meaning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

# ---------------------------------------------------------------------------
# Typed result objects
# ---------------------------------------------------------------------------

class InjectionType(str, Enum):
    """Canonical injection technique names (mirrors SQLMap's Type: field)."""
    BOOLEAN  = "boolean-based blind"
    TIME     = "time-based blind"
    UNION    = "UNION query"
    ERROR    = "error-based"
    STACKED  = "stacked queries"
    INLINE   = "inline query"
    UNKNOWN  = "unknown"

    @classmethod
    def from_string(cls, s: str) -> "InjectionType":
        s_lower = s.lower()
        for member in cls:
            if member.value in s_lower:
                return member
        return cls.UNKNOWN


@dataclass
class Finding:
    """A single confirmed SQL injection point extracted from sqlmap output.

    This is the typed alternative to parsing LLM-visible text strings —
    every field is directly usable by the agent decision layer without
    any further text processing.
    """
    parameter:      str                      # e.g. "page-id"
    injection_type: InjectionType            # e.g. InjectionType.TIME
    payload:        str         = ""         # the winning payload string
    dbms:           Optional[str] = None     # e.g. "MySQL >= 5.0"
    os:             Optional[str] = None     # e.g. "Linux"
    technologies:   List[str]   = field(default_factory=list)
    waf_detected:   bool        = False
    tamper_scripts: List[str]   = field(default_factory=list)
    confidence:     float       = 1.0        # 0–1; time-based = lower
    raw_title:      str         = ""         # Title: line from sqlmap
    discovered_at:  datetime    = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    # ── convenience ────────────────────────────────────────────────────────

    def is_exploitable(self) -> bool:
        """True for techniques that allow direct data extraction."""
        return self.injection_type in (
            InjectionType.UNION, InjectionType.ERROR, InjectionType.STACKED
        )

    def to_dict(self) -> dict:
        return {
            "parameter":      self.parameter,
            "injection_type": self.injection_type.value,
            "payload":        self.payload,
            "dbms":           self.dbms,
            "os":             self.os,
            "technologies":   self.technologies,
            "waf_detected":   self.waf_detected,
            "tamper_scripts": self.tamper_scripts,
            "confidence":     self.confidence,
            "raw_title":      self.raw_title,
            "is_exploitable": self.is_exploitable(),
            "discovered_at":  self.discovered_at.isoformat(),
        }

    def __str__(self) -> str:
        waf = " [WAF]" if self.waf_detected else ""
        return (
            f"[{self.injection_type.value}]{waf} "
            f"param={self.parameter!r} dbms={self.dbms or '?'} "
            f"confidence={self.confidence:.0%}"
        )



# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# SQLMap log prefix:  [HH:MM:SS] [LEVEL]
_PREFIX_RE = re.compile(
    r"^\[[\d:]+\]\s+\[(?P<level>INFO|WARNING|ERROR|CRITICAL|DEBUG)\]\s+(?P<msg>.+)$",
    re.IGNORECASE,
)

# "parameter 'X' is vulnerable"  (also handles "GET parameter", "POST parameter" etc.)
_VULN_RE = re.compile(
    r"(?:parameter\s+['\"]?(?P<parameter>[^'\"]+)['\"]?\s+)"
    r"(?:is vulnerable|appears to be\s+'?(?P<technique>[^']+)'?\s+injectable)",
    re.IGNORECASE,
)

# Alternate: "sqlmap identified the following injection point"
# then later lines like:
#   Parameter: id (GET)
#   Type: boolean-based blind
_PARAM_HDR_RE = re.compile(
    r"^[-\s]*Parameter:\s+(?P<parameter>.+?)\s+\((?:GET|POST|Cookie|URI|Header)\)",
    re.IGNORECASE,
)
_TYPE_RE = re.compile(r"^\s+Type:\s+(?P<technique>.+)$", re.IGNORECASE)

# Table row for database/table names:  | value |
_TABLE_ROW_RE = re.compile(r"^\|\s+(?P<value>.+?)\s+\|$")

# "available databases [N]:" — next rows will be DB names
_DB_HEADER_RE = re.compile(
    r"available databases\s*\[\d+\]", re.IGNORECASE
)

# "[*] starting at …" — session start marker
_START_RE = re.compile(r"^\[\*\]\s+starting", re.IGNORECASE)

# "back-end DBMS: MySQL 5.x"
_DBMS_RE = re.compile(
    r"back-?end\s+DBMS[:\s]+(?P<dbms>.+)", re.IGNORECASE
)

# "retrieved: value" (data extraction)
_RETRIEVED_RE = re.compile(r"retrieved:\s+(?P<value>.+)", re.IGNORECASE)

# Table listing header:  Database: mydb
_DB_NAME_HEADER_RE = re.compile(
    r"^Database:\s+(?P<db>.+)$", re.IGNORECASE
)


class SQLMapOutputParser:
    """Parse SQLMap stdout into typed event dicts.

    The parser is stateless for :meth:`parse_line` but tracks a small
    amount of context (current parameter, current db) inside
    :meth:`parse_full_output` for accurate multi-line parsing.
    """

    # ------------------------------------------------------------------
    # Single-line public API
    # ------------------------------------------------------------------

    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single SQLMap output line.

        Parameters
        ----------
        line:
            One line of SQLMap stdout (newlines should be stripped).

        Returns
        -------
        dict or None
            Structured event dict, or *None* if the line has no
            structured meaning.

            Possible ``type`` values and their extra keys:

            ``injection_found``
                ``parameter`` (str), ``technique`` (str)

            ``db_found``
                ``db_name`` (str)

            ``dbms_found``
                ``dbms`` (str)

            ``info`` / ``warning`` / ``error`` / ``debug``
                ``message`` (str)

            ``retrieved``
                ``value`` (str)
        """
        line = line.rstrip()
        if not line:
            return None

        # ── Prefixed log levels ────────────────────────────────────────
        m = _PREFIX_RE.match(line)
        if m:
            level = m.group("level").lower()
            msg = m.group("msg").strip()

            # Injection found inside an INFO line
            vuln = _VULN_RE.search(msg)
            if vuln:
                technique = (vuln.group("technique") or "").strip() or "unknown"
                return {
                    "type": "injection_found",
                    "parameter": vuln.group("parameter").strip(),
                    "technique": technique,
                    "raw": line,
                }

            # DBMS identified
            dbms_m = _DBMS_RE.search(msg)
            if dbms_m:
                return {
                    "type": "dbms_found",
                    "dbms": dbms_m.group("dbms").strip(),
                    "raw": line,
                }

            # Retrieved value
            ret_m = _RETRIEVED_RE.search(msg)
            if ret_m:
                return {
                    "type": "retrieved",
                    "value": ret_m.group("value").strip(),
                    "raw": line,
                }

            return {"type": level, "message": msg, "raw": line}

        # ── Table row  |  value  | ─────────────────────────────────────
        row_m = _TABLE_ROW_RE.match(line)
        if row_m:
            value = row_m.group("value").strip()
            # Heuristic: skip separator rows like "+----+"
            if re.fullmatch(r"[-+]+", value):
                return None
            return {"type": "db_found", "db_name": value, "raw": line}

        # ── Parameter: X (GET) ─────────────────────────────────────────
        param_m = _PARAM_HDR_RE.match(line)
        if param_m:
            return {
                "type": "parameter_header",
                "parameter": param_m.group("parameter").strip(),
                "raw": line,
            }

        # ── Type: boolean-based blind ──────────────────────────────────
        type_m = _TYPE_RE.match(line)
        if type_m:
            return {
                "type": "technique",
                "technique": type_m.group("technique").strip(),
                "raw": line,
            }

        # ── Database: dbname header ────────────────────────────────────
        db_hdr_m = _DB_NAME_HEADER_RE.match(line)
        if db_hdr_m:
            return {
                "type": "db_header",
                "db_name": db_hdr_m.group("db").strip(),
                "raw": line,
            }

        # ── [*] starting … ─────────────────────────────────────────────
        if _START_RE.match(line):
            return {"type": "info", "message": line.strip(), "raw": line}

        return None

    # ------------------------------------------------------------------
    # Full-output parser
    # ------------------------------------------------------------------

    def parse_full_output(self, lines: list[str]) -> dict:
        """Parse a complete list of SQLMap output lines.

        Parameters
        ----------
        lines:
            All stdout lines from a SQLMap run.

        Returns
        -------
        dict
            ``{injections, databases, tables, errors, warnings}``

            ``injections``  — list of ``{parameter, technique}`` dicts
            ``databases``   — list of database name strings
            ``tables``      — list of ``{database, table}`` dicts
            ``errors``      — list of error message strings
            ``warnings``    — list of warning message strings
        """
        result: dict = {
            "injections": [],
            "databases": [],
            "tables": [],
            "errors": [],
            "warnings": [],
        }

        # Context for multi-line constructs
        current_param: str | None = None
        in_db_listing = False
        current_db: str | None = None

        for raw_line in lines:
            event = self.parse_line(raw_line)
            if event is None:
                # Check for DB-listing header even in unprefixed lines
                if _DB_HEADER_RE.search(raw_line):
                    in_db_listing = True
                continue

            etype = event.get("type")

            if etype == "injection_found":
                entry = {
                    "parameter": event["parameter"],
                    "technique": event["technique"],
                }
                if entry not in result["injections"]:
                    result["injections"].append(entry)

            elif etype == "parameter_header":
                current_param = event["parameter"]

            elif etype == "technique":
                # Pair with the most recent parameter_header
                if current_param:
                    entry = {
                        "parameter": current_param,
                        "technique": event["technique"],
                    }
                    if entry not in result["injections"]:
                        result["injections"].append(entry)

            elif etype == "db_found":
                db_name = event["db_name"]
                if db_name and db_name not in result["databases"]:
                    result["databases"].append(db_name)

            elif etype == "db_header":
                # "Database: xyz" header — next table rows belong to this db
                current_db = event["db_name"]
                in_db_listing = False

            elif etype == "dbms_found":
                # Store DBMS under a top-level key if not already present
                result.setdefault("dbms", event["dbms"])

            elif etype == "error":
                result["errors"].append(event["message"])

            elif etype == "warning":
                result["warnings"].append(event["message"])

            elif etype == "retrieved":
                result.setdefault("retrieved_values", []).append(
                    event["value"]
                )

        return result
