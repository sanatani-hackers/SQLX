"""
sqlx/reports/html.py
~~~~~~~~~~~~~~~~~~~~
Standalone HTML report builder using the formatter module.
Produces a dark-themed, self-contained HTML audit report.
"""
from __future__ import annotations
from typing import Any, Dict

from sqlx.reports.formatter import (
    findings_to_table_rows, commits_to_table_rows, format_timestamp,
)

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SQLX Security Report — {target_name}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
          background:#0d1117; color:#c9d1d9; padding:24px; }}
  h1,h2,h3 {{ color:#58a6ff; margin-bottom:8px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
           padding:20px; margin:16px 0; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
  th {{ background:#21262d; color:#58a6ff; padding:10px 12px; text-align:left;
        border-bottom:1px solid #30363d; }}
  td {{ padding:8px 12px; border-bottom:1px solid #21262d; vertical-align:top; }}
  code {{ background:#21262d; padding:2px 6px; border-radius:4px;
          font-family:'Courier New',monospace; font-size:0.9em; }}
  a {{ color:#58a6ff; text-decoration:none; }}
  .meta {{ color:#8b949e; font-size:0.875em; margin-top:4px; }}
  .banner {{ background:linear-gradient(135deg,#1f2937,#111827);
             border-left:4px solid #58a6ff; padding:20px 24px;
             border-radius:4px; margin-bottom:20px; }}
  .empty {{ color:#8b949e; font-style:italic; padding:12px 0; }}
</style>
</head>
<body>

<div class="banner">
  <h1>🔍 SQLX Security Report</h1>
  <p class="meta">Target: <strong>{target_name}</strong></p>
  <p class="meta">URL: <a href="{target_url}">{target_url}</a></p>
  <p class="meta">Generated: {generated_at}</p>
</div>

<div class="card">
  <h2>Target Information</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>ID</td><td><code>{target_id}</code></td></tr>
    <tr><td>Name</td><td>{target_name}</td></tr>
    <tr><td>URL</td><td><a href="{target_url}">{target_url}</a></td></tr>
    <tr><td>Workspace</td><td><code>{workspace_dir}</code></td></tr>
  </table>
</div>

<div class="card">
  <h2>Findings ({findings_count})</h2>
  {findings_section}
</div>

<div class="card">
  <h2>Workspace History ({commits_count} commits)</h2>
  {history_section}
</div>

{proxy_section}

</body>
</html>"""


def build_html_report(data: Dict[str, Any]) -> str:
    """Build a full HTML report string from a report data dict."""
    target  = data.get("target", {})
    findings = data.get("findings", [])
    history  = data.get("workspace_history", [])
    traffic  = data.get("recent_traffic", [])

    # Findings table
    if findings:
        findings_section = (
            "<table><tr><th>Severity</th><th>Timestamp</th><th>Finding</th></tr>"
            + findings_to_table_rows(findings)
            + "</table>"
        )
    else:
        findings_section = '<p class="empty">No findings recorded.</p>'

    # History table
    if history:
        history_section = (
            "<table><tr><th>Hash</th><th>Date</th><th>Author</th><th>Message</th></tr>"
            + commits_to_table_rows(history)
            + "</table>"
        )
    else:
        history_section = '<p class="empty">No workspace history available.</p>'

    # Optional proxy section
    if traffic:
        rows = "".join(
            f"<tr><td>{t.get('method','')}</td>"
            f"<td>{t.get('url','')[:80]}</td>"
            f"<td>{t.get('status','')}</td>"
            f"<td>{t.get('latency_ms',0):.1f}ms</td></tr>"
            for t in traffic[:30]
        )
        proxy_section = (
            '<div class="card"><h2>Recent Proxy Traffic</h2>'
            "<table><tr><th>Method</th><th>URL</th><th>Status</th><th>Latency</th></tr>"
            + rows + "</table></div>"
        )
    else:
        proxy_section = ""

    return _TEMPLATE.format(
        target_id=target.get("id", "N/A")[:16],
        target_name=target.get("name", "Unknown"),
        target_url=target.get("target_url", ""),
        workspace_dir=target.get("workspace_dir", ""),
        generated_at=format_timestamp(),
        findings_count=len(findings),
        findings_section=findings_section,
        commits_count=len(history),
        history_section=history_section,
        proxy_section=proxy_section,
    )
