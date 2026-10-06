"""
sqlx/reports/formatter.py
~~~~~~~~~~~~~~~~~~~~~~~~~
HTML/text formatting helpers shared between report generators.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List


# ── severity ───────────────────────────────────────────────────────────────

_SEVERITY_COLOURS: Dict[str, str] = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#28a745",
    "info":     "#17a2b8",
}


def severity_badge(severity: str) -> str:
    colour = _SEVERITY_COLOURS.get(severity.lower(), "#6c757d")
    return (
        f'<span style="background:{colour};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.85em">{severity.upper()}</span>'
    )


# ── time ───────────────────────────────────────────────────────────────────

def format_timestamp(ts: str = None) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        return ts.replace("T", " ").replace("Z", " UTC")[:22]
    except Exception:
        return str(ts)


# ── text ───────────────────────────────────────────────────────────────────

def truncate(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"… [{len(text) - max_len} chars omitted]"


# ── table row builders ─────────────────────────────────────────────────────

def findings_to_table_rows(findings: List[Dict[str, Any]]) -> str:
    rows = []
    for f in findings:
        text     = truncate(str(f.get("finding", "")), 300)
        severity = f.get("severity", "info")
        ts       = format_timestamp(f.get("timestamp") or f.get("created_at", ""))
        rows.append(
            f"<tr>"
            f"<td>{severity_badge(severity)}</td>"
            f"<td>{ts}</td>"
            f'<td style="font-family:monospace;font-size:0.9em">{text}</td>'
            f"</tr>"
        )
    return "\n".join(rows)


def commits_to_table_rows(history: List[Dict]) -> str:
    rows = []
    for c in history:
        rows.append(
            f"<tr>"
            f"<td><code>{c.get('hash', '')[:8]}</code></td>"
            f"<td>{format_timestamp(c.get('date', ''))}</td>"
            f"<td>{c.get('author', '')}</td>"
            f"<td>{c.get('message', '')}</td>"
            f"</tr>"
        )
    return "\n".join(rows)
