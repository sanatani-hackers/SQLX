"""
sqlx/agent/observations.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Pre-loads all available context from every data source **before** the LLM
reasons about what to do next.

Instead of the agent calling ``analyze_recent_traffic`` → wait → then
``fingerprint_target`` → wait → etc., this module grabs everything from the
in-process caches (SQLite proxy history, session state, git workspace) in one
non-blocking pass and returns a concise ``Observations`` object the agent can
render directly into its system-message context.

Architecture
------------
``ObservationCollector.collect(target_id, session)``
    → reads SQLite, git, session state  (all local, no network I/O)
    → returns an ``Observations`` dataclass

``Observations.to_prompt_text()``
    → renders a compact, token-efficient block ready for the LLM

The rendered block is injected as an *ephemeral* system message (not stored in
persistent memory) so it is always fresh on every turn.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed sub-observation dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TrafficObservation:
    """Summary of recent proxy traffic."""
    request_count: int = 0
    status_codes: List[int] = field(default_factory=list)
    waf_detected: bool = False
    waf_indicators: List[str] = field(default_factory=list)
    injection_signals: List[str] = field(default_factory=list)   # e.g. 'timing_anomaly'
    top_urls: List[str] = field(default_factory=list)
    latest_request_id: Optional[int] = None

    def to_prompt_text(self) -> str:
        if self.request_count == 0:
            return "[TRAFFIC] No proxy traffic captured yet."
        lines = [f"[TRAFFIC] {self.request_count} request(s) captured"]
        if self.top_urls:
            lines.append(f"  URLs: {', '.join(self.top_urls[:3])}")
        if self.status_codes:
            code_summary = ", ".join(f"{c}×{self.status_codes.count(c)}"
                                     for c in sorted(set(self.status_codes)))
            lines.append(f"  Status codes: {code_summary}")
        if self.waf_detected:
            lines.append(f"  ⚠ WAF detected: {', '.join(self.waf_indicators)}")
        if self.injection_signals:
            lines.append(f"  🚨 Signals: {', '.join(self.injection_signals)}")
        if self.latest_request_id:
            lines.append(f"  Latest request ID: {self.latest_request_id}")
        return "\n".join(lines)


@dataclass
class SQLMapObservation:
    """Summary of the most recent SQLMap run (from session or last log)."""
    ran: bool = False
    injection_found: bool = False
    findings_count: int = 0
    dbms: Optional[str] = None
    techniques: List[str] = field(default_factory=list)
    waf_detected: bool = False
    parameters: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_prompt_text(self) -> str:
        if not self.ran:
            return "[SQLMAP] No sqlmap run recorded in this session."
        lines = ["[SQLMAP] Last run summary:"]
        if self.injection_found:
            lines.append(f"  ✓ INJECTION FOUND — {self.findings_count} point(s)")
            if self.parameters:
                lines.append(f"  Parameters: {', '.join(self.parameters)}")
            if self.techniques:
                lines.append(f"  Techniques: {', '.join(self.techniques)}")
            if self.dbms:
                lines.append(f"  DBMS: {self.dbms}")
        else:
            lines.append("  No injection found in last run.")
        if self.waf_detected:
            lines.append("  ⚠ WAF/IPS was detected.")
        if self.errors:
            lines.append(f"  Errors: {'; '.join(self.errors[:2])}")
        return "\n".join(lines)


@dataclass
class WorkspaceObservation:
    """Summary of workspace git state."""
    uncommitted_changes: int = 0
    last_commit_hash: str = ""
    last_commit_message: str = ""
    total_commits: int = 0

    def to_prompt_text(self) -> str:
        lines = ["[WORKSPACE]"]
        if self.last_commit_message:
            lines.append(f"  Last snapshot: {self.last_commit_message[:80]!r}")
        if self.uncommitted_changes:
            lines.append(f"  Uncommitted changes: {self.uncommitted_changes} file(s)")
        else:
            lines.append("  Workspace is clean.")
        if self.total_commits:
            lines.append(f"  Total snapshots: {self.total_commits}")
        return "\n".join(lines)


@dataclass
class SessionObservation:
    """Summary of the current session state."""
    session_id: Optional[str] = None
    objective: str = ""
    findings_count: int = 0
    observations_count: int = 0
    last_actions: List[str] = field(default_factory=list)
    findings_summary: List[Dict[str, Any]] = field(default_factory=list)

    def to_prompt_text(self) -> str:
        if not self.session_id:
            return "[SESSION] No active session."
        lines = [f"[SESSION] {self.session_id[:8]}"]
        if self.objective:
            lines.append(f"  Objective: {self.objective}")
        lines.append(f"  Findings: {self.findings_count}  |  Observations: {self.observations_count}")
        if self.findings_summary:
            for f in self.findings_summary[-3:]:  # show latest 3
                sev = f.get("severity", "?")
                desc = str(f.get("description") or f.get("summary", ""))[:80]
                lines.append(f"  • [{sev}] {desc}")
        if self.last_actions:
            lines.append(f"  Last actions: {' → '.join(self.last_actions[-3:])}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Aggregated observations object
# ---------------------------------------------------------------------------

@dataclass
class Observations:
    """Snapshot of all available knowledge at one point in time."""
    traffic:   TrafficObservation   = field(default_factory=TrafficObservation)
    sqlmap:    SQLMapObservation    = field(default_factory=SQLMapObservation)
    workspace: WorkspaceObservation = field(default_factory=WorkspaceObservation)
    session:   SessionObservation   = field(default_factory=SessionObservation)
    rag_context: str = ""           # relevant past findings from RAG

    def to_prompt_text(self) -> str:
        """Render a compact, token-efficient context block for the LLM.

        This replaces 3-5 reactive tool calls per turn by front-loading all
        available data. The LLM receives this *before* it decides what to do,
        so it can skip tool calls whose answers are already here.
        """
        sections = [
            "=== Current State ===",
            self.session.to_prompt_text(),
            "",
            self.traffic.to_prompt_text(),
            "",
            self.sqlmap.to_prompt_text(),
            "",
            self.workspace.to_prompt_text(),
        ]
        if self.rag_context:
            sections += ["", self.rag_context]
        sections.append("=== End State ===")
        return "\n".join(sections)

    def is_empty(self) -> bool:
        """True when nothing useful has been collected (avoids injecting blank context)."""
        return (
            self.traffic.request_count == 0
            and not self.sqlmap.ran
            and not self.session.session_id
            and not self.rag_context
        )


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class ObservationCollector:
    """Collects all observations from local sources with no blocking network I/O.

    Reads from:
    - SQLite proxy history (already in-process)
    - SessionState (in-memory / already loaded)
    - Git workspace (local shell command)
    - RAG index (in-process TF-IDF)

    All sources are local; this typically completes in <50 ms.
    """

    def collect(
        self,
        target_id: Optional[str] = None,
        session=None,              # SessionState | None
        workspace_dir: Optional[str] = None,
        rag_query: str = "",
    ) -> Observations:
        """Gather all observations and return an :class:`Observations` snapshot."""
        obs = Observations()
        obs.traffic   = self._collect_traffic(target_id)
        obs.sqlmap    = self._collect_sqlmap(session)
        obs.workspace = self._collect_workspace(workspace_dir)
        obs.session   = self._collect_session(session)
        obs.rag_context = self._collect_rag(rag_query)
        return obs

    # ── private collectors ────────────────────────────────────────────────

    def _collect_traffic(self, target_id: Optional[str]) -> TrafficObservation:
        result = TrafficObservation()
        try:
            from sqlx import proxy_history
            from sqlx.analysis.response import ResponseAnalyser

            records = proxy_history.get_recent(30)
            if not records:
                return result

            result.request_count = len(records)
            result.status_codes  = [r.get("status", 0) for r in records]
            result.latest_request_id = records[0].get("id")

            # Deduplicate top URLs
            seen_urls = {}
            for r in records:
                url = r.get("url", "")
                base = url.split("?")[0]
                seen_urls[base] = seen_urls.get(base, 0) + 1
            result.top_urls = sorted(seen_urls, key=seen_urls.get, reverse=True)[:3]

            # WAF detection: look for WAF status codes or headers
            waf_statuses = {403, 406, 429, 503}
            waf_hits = [r for r in records if r.get("status") in waf_statuses]
            if waf_hits:
                result.waf_detected = True
                result.waf_indicators.append(f"status {waf_hits[0]['status']}")

            # Injection signals: timing anomalies (>4s responses)
            slow = [r for r in records if float(r.get("latency_ms") or 0) > 4000]
            if slow:
                result.injection_signals.append(
                    f"timing_anomaly ({len(slow)} slow response(s), "
                    f"max {max(float(r.get('latency_ms',0)) for r in slow):.0f}ms)"
                )

            # Status-change signal across same URL
            from collections import defaultdict
            by_path: dict = defaultdict(set)
            for r in records:
                path = r.get("url", "").split("?")[0]
                by_path[path].add(r.get("status", 0))
            for path, codes in by_path.items():
                if len(codes) > 1:
                    result.injection_signals.append(f"status_variance on {path[-50:]}")
                    break

        except Exception as exc:
            logger.debug("Traffic collection failed: %s", exc)
        return result

    def _collect_sqlmap(self, session) -> SQLMapObservation:
        result = SQLMapObservation()
        if session is None:
            return result

        # Check session findings for sqlmap-sourced data
        try:
            findings = getattr(session, "findings", [])
            if not findings:
                return result

            result.ran = True
            sqlmap_findings = [
                f for f in findings
                if "injection" in str(f).lower() or "sqlmap" in str(f).lower()
                   or "technique" in str(f) or "payload" in str(f)
            ]
            if sqlmap_findings:
                result.injection_found = True
                result.findings_count  = len(sqlmap_findings)

            # Pull structured data from finding dicts
            for f in findings:
                if isinstance(f, dict):
                    if f.get("dbms") and not result.dbms:
                        result.dbms = f["dbms"]
                    for t in (f.get("techniques") or []):
                        if t not in result.techniques:
                            result.techniques.append(t)
                    for p in (f.get("parameters") or [f.get("parameter")] if f.get("parameter") else []):
                        if p and p not in result.parameters:
                            result.parameters.append(p)
                    result.waf_detected = result.waf_detected or bool(f.get("waf_detected"))
                    result.errors.extend(f.get("errors") or [])
        except Exception as exc:
            logger.debug("SQLMap observation collection failed: %s", exc)
        return result

    def _collect_workspace(self, workspace_dir: Optional[str]) -> WorkspaceObservation:
        result = WorkspaceObservation()
        if not workspace_dir:
            return result
        try:
            import subprocess
            from pathlib import Path
            wd = Path(workspace_dir)
            if not (wd / ".git").exists():
                return result

            # Last commit
            r = subprocess.run(
                ["git", "log", "-1", "--pretty=%h %s"],
                cwd=workspace_dir, capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                parts = r.stdout.strip().split(" ", 1)
                result.last_commit_hash    = parts[0]
                result.last_commit_message = parts[1] if len(parts) > 1 else ""

            # Total commits
            r2 = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=workspace_dir, capture_output=True, text=True, timeout=5,
            )
            if r2.returncode == 0:
                result.total_commits = int(r2.stdout.strip() or 0)

            # Uncommitted changes
            r3 = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=workspace_dir, capture_output=True, text=True, timeout=5,
            )
            if r3.returncode == 0:
                result.uncommitted_changes = len([
                    l for l in r3.stdout.splitlines() if l.strip()
                ])
        except Exception as exc:
            logger.debug("Workspace observation failed: %s", exc)
        return result

    def _collect_session(self, session) -> SessionObservation:
        result = SessionObservation()
        if session is None:
            return result
        try:
            result.session_id        = getattr(session, "id", None)
            result.objective         = getattr(session, "objective", "")
            result.findings_count    = len(getattr(session, "findings", []))
            result.observations_count = len(getattr(session, "observations", []))
            result.findings_summary  = list(getattr(session, "findings", []))[-5:]

            # Last few typed observation messages as action trail
            typed = getattr(session, "observation_types", {})
            exec_obs = typed.get("execution", [])
            result.last_actions = [o.replace("Agent answered query: ", "") for o in exec_obs[-3:]]
        except Exception as exc:
            logger.debug("Session observation failed: %s", exc)
        return result

    def _collect_rag(self, query: str) -> str:
        if not query:
            return ""
        try:
            from sqlx.ai.rag import _rag
            return _rag.format_for_context(query, top_k=3)
        except Exception:
            return ""
