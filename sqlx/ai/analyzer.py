"""
sqlx/ai/analyzer.py
~~~~~~~~~~~~~~~~~~~
LLM-based and heuristic traffic/response analyser.
Provides richer interpretation of SQLMap output and HTTP anomalies than
the pure-pattern fingerprint module.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """Interprets SQLMap output and proxy traffic — uses LLM if configured,
    falls back to heuristics otherwise."""

    def __init__(self, provider=None):
        self.provider = provider

    def set_provider(self, provider) -> None:
        self.provider = provider

    # ── SQLMap analysis ────────────────────────────────────────────────────

    def analyse_sqlmap_output(self, clean_output: str, summary: dict) -> str:
        """Interpret SQLMap results and suggest next steps."""
        if not self.provider:
            return self._heuristic_sqlmap(summary)

        system_msg = (
            "You are a SQL injection expert. Analyse the following SQLMap output and provide:\n"
            "1. What was found (concise)\n"
            "2. Severity (Critical / High / Medium / Low / Info)\n"
            "3. Recommended next step (one sentence)\n"
            "Be concise. Do not repeat the raw output."
        )
        user_msg = f"Summary:\n{summary}\n\nOutput (truncated):\n{clean_output[:2000]}"
        try:
            return self.provider.generate(
                [{"role": "system", "content": system_msg},
                 {"role": "user",   "content": user_msg}],
                tools=None,
            )
        except Exception as exc:
            logger.warning("LLM analysis failed: %s", exc)
            return self._heuristic_sqlmap(summary)

    def _heuristic_sqlmap(self, summary: dict) -> str:
        parts = []
        if summary.get("injection_found"):
            dbms = summary.get("dbms") or "unknown DBMS"
            payloads = summary.get("payloads", [])
            parts.append(f"✓ Injection confirmed — {dbms}")
            if payloads:
                parts.append(f"  Payload: {payloads[0]}")
            parts.append("  Recommended: enumerate databases with --dbs")
        elif summary.get("waf_detected"):
            parts.append("⚠ WAF detected — try tamper scripts (e.g. space2comment, randomcase)")
        else:
            parts.append("No injection found — try higher --level/--risk or different tampers")
        for err in summary.get("errors", [])[:2]:
            parts.append(f"Error: {err}")
        return "\n".join(parts)

    # ── Traffic analysis ───────────────────────────────────────────────────

    def analyse_traffic_anomalies(self, transactions: list) -> str:
        """Summarise anomalies from a list of proxy transactions."""
        if not transactions:
            return "No proxy traffic to analyse."
        statuses: List[int] = []
        waf_hits = 0
        try:
            from sqlx.analysis.http import analyzer as http_analyzer
            for txn in transactions:
                a = http_analyzer.analyze_txn(txn)
                statuses.append(a.get("status", 0))
                if a.get("has_waf_headers"):
                    waf_hits += 1
        except Exception:
            pass

        lines = [f"Transactions analysed: {len(transactions)}"]
        if statuses:
            from collections import Counter
            for code, count in sorted(Counter(statuses).items()):
                lines.append(f"  HTTP {code}: {count}×")
        if waf_hits:
            lines.append(f"WAF/IPS responses: {waf_hits}")
        return "\n".join(lines)

    # ── Context summary ────────────────────────────────────────────────────

    def build_context_summary(self, target_url: str, session=None,
                               recent_observations: list = None) -> str:
        """Build a compact situation-summary for the agent system context."""
        parts = [f"Target: {target_url}"]
        if session:
            parts.append(f"Session: {session.id[:8]} | Objective: {session.objective}")
            parts.append(f"Findings so far: {len(session.findings)}")
        if recent_observations:
            critical = [o for o in recent_observations if getattr(o, "severity", "") == "critical"]
            if critical:
                parts.append(f"Critical signals: {len(critical)} (injection or WAF)")
        return "\n".join(parts)


# Module-level singleton (provider injected later by the agent)
_analyzer = TrafficAnalyzer()
