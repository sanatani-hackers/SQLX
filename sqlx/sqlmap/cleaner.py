"""
sqlx/sqlmap/cleaner.py
~~~~~~~~~~~~~~~~~~~~~~
Filters raw SQLMap stdout into clean, LLM-friendly output.

Strips:  ASCII banner, legal disclaimer, progress bars, ANSI codes,
         redundant info lines, session-resume spam, blank lines.
Keeps:   injection findings, DBMS info, WAF alerts, payload details,
         errors, warnings, technology fingerprints.
"""
from __future__ import annotations

import re
from typing import List, Optional


# ---------------------------------------------------------------------------
# Compiled patterns — built once at import time
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Banner lines (ASCII art)
_BANNER_RE = re.compile(r"^\s*(?:___|\s*__H__|[|][-_ ]+[|]|^\s*\|___|V\.\.\.)")

# Lines to drop entirely
_NOISE_PATTERNS: List[re.Pattern] = [
    re.compile(r"^\[!\] legal disclaimer"),
    re.compile(r"^\[\*\] starting @"),
    re.compile(r"^\[\*\] ending @"),
    re.compile(r"^\[INFO\] resuming back-end"),          # duplicate resume noise
    re.compile(r"^\[INFO\] testing if the provided"),
    re.compile(r"^\[INFO\] checking if the target"),
    re.compile(r"^\[INFO\] heuristic.*quick test"),
    re.compile(r"^\[INFO\] target URL content is stable"),
    re.compile(r"^\[INFO\] GET parameter .* does not seem"),
    re.compile(r"^\[INFO\] flushed session"),
    re.compile(r"^\[INFO\] found a total of"),
    re.compile(r"^\[INFO\] sqlmap will dump"),
    re.compile(r"do you want sqlmap to try to optimize"),
    re.compile(r"you have not declared cookie"),
    re.compile(r"^\s*[-=]{3,}\s*$"),                    # divider lines
    re.compile(r"^\s*$"),                                # blank lines
    re.compile(r"\r"),                                   # carriage returns / progress
    re.compile(r"\[#"),                                  # progress bar chars
]

# Lines to ALWAYS keep
_KEEP_PATTERNS: List[re.Pattern] = [
    re.compile(r"\[CRITICAL\]"),
    re.compile(r"\[WARNING\]"),
    re.compile(r"\[ERROR\]"),
    re.compile(r"(?i)vulnerable|injectable|injection"),
    re.compile(r"(?i)back-end DBMS"),
    re.compile(r"(?i)web application technology"),
    re.compile(r"(?i)WAF|IPS|firewall"),
    re.compile(r"(?i)tamper script"),
    re.compile(r"(?i)payload|Type:|Title:|vector"),
    re.compile(r"(?i)parameter:"),
    re.compile(r"(?i)fetched data logged"),
    re.compile(r"---"),                                  # injection point summary blocks
    re.compile(r"^\+"),                                  # table-formatted data rows
]

# Patterns used to extract structured summary fields
_DBMS_RE = re.compile(r"back-end DBMS[:\s]+([^\n\r]+)", re.IGNORECASE)
_TECH_RE = re.compile(r"web application technology[:\s]+([^\n\r]+)", re.IGNORECASE)
_PARAM_RE = re.compile(r"Parameter:\s+(\S+)", re.IGNORECASE)
_TYPE_RE  = re.compile(r"Type:\s+([^\n\r]+)", re.IGNORECASE)
_WAF_RE   = re.compile(r"(?:target is protected|WAF/IPS)", re.IGNORECASE)
_ERR_RE   = re.compile(r"\[ERROR\]\s+(.+)")
_VULN_RE  = re.compile(r"(?:vulnerable|injectable|injection found)", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"Payload:\s+([^\n\r]+)", re.IGNORECASE)


class SQLMapOutputCleaner:
    """Strips noise from sqlmap stdout and produces structured summaries."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clean(self, lines: List[str], max_chars: int = 2500) -> str:
        """
        Return a cleaned, deduplicated string ready for LLM consumption.
        Lines are stripped of ANSI codes, banner art, and noise.
        Output is capped at *max_chars* with a tail note if truncated.
        """
        kept: List[str] = []
        seen: set = set()

        for raw in lines:
            line = _ANSI_RE.sub("", raw).strip()
            if not line:
                continue
            if _BANNER_RE.match(line):
                continue
            if any(p.search(line) for p in _NOISE_PATTERNS):
                # Only skip if it's not a keeper
                if not any(p.search(line) for p in _KEEP_PATTERNS):
                    continue
            # Deduplicate near-identical lines
            key = re.sub(r"\d+", "N", line)[:120]
            if key in seen:
                continue
            seen.add(key)
            kept.append(line)

        result = "\n".join(kept)
        if len(result) > max_chars:
            removed = len(result) - max_chars
            result = result[:max_chars] + f"\n…[{removed} chars removed]"
        return result

    def summarize(self, lines: List[str]) -> dict:
        """
        Return a structured dict:
        {
            injection_found: bool,
            dbms: str | None,
            technologies: list[str],
            waf_detected: bool,
            payloads: list[str],
            parameters: list[str],
            techniques: list[str],
            errors: list[str],
        }
        """
        blob = "\n".join(_ANSI_RE.sub("", l) for l in lines)

        dbms_m = _DBMS_RE.search(blob)
        tech_m = _TECH_RE.search(blob)

        return {
            "injection_found": bool(_VULN_RE.search(blob)),
            "dbms": dbms_m.group(1).strip() if dbms_m else None,
            "technologies": [t.strip() for t in tech_m.group(1).split(",")] if tech_m else [],
            "waf_detected": bool(_WAF_RE.search(blob)),
            "payloads": [m.group(1).strip() for m in _PAYLOAD_RE.finditer(blob)][:5],
            "parameters": list(dict.fromkeys(m.group(1).strip() for m in _PARAM_RE.finditer(blob))),
            "techniques": list(dict.fromkeys(m.group(1).strip() for m in _TYPE_RE.finditer(blob))),
            "errors": [m.group(1).strip() for m in _ERR_RE.finditer(blob)][:5],
        }

    def to_findings(self, lines: List[str]) -> list:
        """Convert raw sqlmap stdout into a list of typed :class:`~sqlx.sqlmap.parser.Finding` objects.

        This is the primary bridge between text output and structured data,
        replacing the need for direct SQLMap API access.  Each unique
        (parameter, technique) pair becomes one ``Finding``.

        The method pairs parameters with their techniques and payloads by
        walking through the injection-point summary block that sqlmap always
        emits between ``---`` delimiters.

        Returns:
            List of :class:`~sqlx.sqlmap.parser.Finding` (may be empty).
        """
        from sqlx.sqlmap.parser import Finding, InjectionType

        blob = "\n".join(_ANSI_RE.sub("", l) for l in lines)
        summary = self.summarize(lines)

        dbms        = summary["dbms"]
        technologies = summary["technologies"]
        waf_detected = summary["waf_detected"]

        # ── Extract tamper scripts from output ──────────────────────────────
        _TAMPER_RE = re.compile(r"tamper script[s]?\s+'?([^'\n,]+)'?", re.IGNORECASE)
        tamper_scripts = list(dict.fromkeys(
            m.group(1).strip() for m in _TAMPER_RE.finditer(blob)
        ))

        # ── Walk the injection-point summary block ──────────────────────────
        # sqlmap emits blocks like:
        #   ---
        #   Parameter: page-id (GET)
        #       Type: time-based blind
        #       Title: MySQL >= 5.0.12 AND time-based blind
        #       Payload: page-id=1 AND SLEEP(5)
        #   ---
        _TITLE_RE   = re.compile(r"^\s+Title:\s+(.+)$",   re.IGNORECASE)
        _PAYLOAD_BLOCK_RE = re.compile(r"^\s+Payload:\s+(.+)$", re.IGNORECASE)

        findings: list[Finding] = []
        in_block   = False
        cur_param  = None
        cur_type   = None
        cur_title  = ""
        cur_payload = ""

        for raw in lines:
            line = _ANSI_RE.sub("", raw).strip()

            if line == "---":
                if in_block and cur_param and cur_type:
                    # Assign confidence based on technique
                    itype = InjectionType.from_string(cur_type)
                    conf = {
                        InjectionType.UNION:   0.95,
                        InjectionType.ERROR:   0.90,
                        InjectionType.BOOLEAN: 0.80,
                        InjectionType.TIME:    0.70,
                        InjectionType.STACKED: 0.85,
                    }.get(itype, 0.75)

                    findings.append(Finding(
                        parameter      = cur_param,
                        injection_type = itype,
                        payload        = cur_payload,
                        dbms           = dbms,
                        technologies   = technologies,
                        waf_detected   = waf_detected,
                        tamper_scripts = tamper_scripts,
                        confidence     = conf,
                        raw_title      = cur_title,
                    ))
                # Reset for next block
                in_block    = True
                cur_param   = None
                cur_type    = None
                cur_title   = ""
                cur_payload = ""
                continue

            if not in_block:
                continue

            m = _PARAM_RE.match(raw)
            if m:
                cur_param = m.group(1).strip()
                continue

            m = _TYPE_RE.match(raw)
            if m:
                cur_type = m.group(1).strip()
                continue

            m = _TITLE_RE.match(raw)
            if m:
                cur_title = m.group(1).strip()
                continue

            m = _PAYLOAD_BLOCK_RE.match(raw)
            if m:
                cur_payload = m.group(1).strip()
                continue

        # ── Fallback: if no block found but injection was detected ──────────
        if not findings and summary["injection_found"]:
            params     = summary["parameters"] or ["unknown"]
            techniques = summary["techniques"] or ["unknown"]
            payloads   = summary["payloads"]
            for i, param in enumerate(params):
                tech_str = techniques[i] if i < len(techniques) else techniques[0] if techniques else "unknown"
                findings.append(Finding(
                    parameter      = param,
                    injection_type = InjectionType.from_string(tech_str),
                    payload        = payloads[i] if i < len(payloads) else "",
                    dbms           = dbms,
                    technologies   = technologies,
                    waf_detected   = waf_detected,
                    tamper_scripts = tamper_scripts,
                    confidence     = 0.70,
                ))

        return findings
