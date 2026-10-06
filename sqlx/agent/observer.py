"""
sqlx/agent/observer.py
~~~~~~~~~~~~~~~~~~~~~~
Aggregates signals from SQLMap output, proxy traffic, and manual notes
into a unified, ranked list of Observations the agent can reason about.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class Observation:
    source: str          # 'sqlmap' | 'proxy' | 'analysis' | 'manual'
    severity: str        # 'info' | 'warning' | 'critical'
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_context_string(self) -> str:
        return f"[{self.severity.upper()}][{self.source}] {self.message}"

    def __str__(self) -> str:
        return self.to_context_string()


class Observer:
    """Aggregates observations from all sources into a single ranked list."""

    def __init__(self):
        self._observations: List[Observation] = []

    # ── ingestion ──────────────────────────────────────────────────────────

    def observe_sqlmap_output(self, clean_output: str, summary: dict) -> List[Observation]:
        """Convert a SQLMapOutputCleaner summary dict into Observations."""
        new_obs: List[Observation] = []

        if summary.get("injection_found"):
            new_obs.append(Observation(
                source="sqlmap", severity="critical",
                message="SQL injection confirmed",
                details={
                    "payloads":    summary.get("payloads", []),
                    "dbms":        summary.get("dbms"),
                    "techniques":  summary.get("techniques", []),
                    "parameters":  summary.get("parameters", []),
                },
            ))

        if summary.get("waf_detected"):
            new_obs.append(Observation(
                source="sqlmap", severity="warning",
                message="WAF/IPS detected — responses may be filtered",
                details={"technologies": summary.get("technologies", [])},
            ))

        for err in summary.get("errors", []):
            new_obs.append(Observation(
                source="sqlmap", severity="warning",
                message=f"SQLMap error: {err}",
            ))

        if not new_obs and clean_output.strip():
            new_obs.append(Observation(
                source="sqlmap", severity="info",
                message="SQLMap run completed — no injection found in this run",
                details={"output_length": len(clean_output)},
            ))

        self._observations.extend(new_obs)
        return new_obs

    def observe_proxy_traffic(self, transactions) -> List[Observation]:
        """Extract anomalies from a list of proxy transactions."""
        new_obs: List[Observation] = []
        try:
            from sqlx.analysis.http import analyzer
            for txn in transactions:
                try:
                    analysis = analyzer.analyze_txn(txn)
                    url = txn.request.get("url", "") if hasattr(txn, "request") else ""
                    if analysis.get("has_waf_headers"):
                        new_obs.append(Observation(
                            source="proxy", severity="warning",
                            message=f"WAF headers detected on {url[:60]}",
                            details={"analysis": analysis},
                        ))
                    elif analysis.get("suspicious_status"):
                        new_obs.append(Observation(
                            source="proxy", severity="info",
                            message=f"Suspicious status {analysis.get('status')} on {url[:60]}",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        self._observations.extend(new_obs)
        return new_obs

    def add_manual(self, message: str, severity: str = "info",
                   details: dict = None) -> Observation:
        obs = Observation(
            source="manual", severity=severity,
            message=message, details=details or {},
        )
        self._observations.append(obs)
        return obs

    # ── retrieval ──────────────────────────────────────────────────────────

    def get_all(self) -> List[Observation]:
        return list(self._observations)

    def get_by_severity(self, severity: str) -> List[Observation]:
        return [o for o in self._observations if o.severity == severity]

    def get_critical(self) -> List[Observation]:
        return self.get_by_severity("critical")

    def format_for_context(self, max_items: int = 10) -> str:
        """Return recent observations as a block for LLM context injection."""
        recent = self._observations[-max_items:]
        if not recent:
            return ""
        lines = ["=== Current Observations ==="]
        for obs in recent:
            lines.append(obs.to_context_string())
        lines.append("=== End Observations ===")
        return "\n".join(lines)

    def clear(self) -> None:
        self._observations.clear()

    def __len__(self) -> int:
        return len(self._observations)


# Module-level singleton
_observer = Observer()
