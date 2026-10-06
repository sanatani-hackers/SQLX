import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from sqlx.target.manager import TargetManager
from sqlx.workspace.manager import WorkspaceManager
from sqlx.analysis.http import analyzer

class ReportGenerator:
    def __init__(self, target_id: str):
        self.target_manager = TargetManager()
        self.target = self.target_manager.load_target(target_id)
        if not self.target:
            raise ValueError(f"Target '{target_id}' not found.")
            
        self.workspace = WorkspaceManager(self.target.workspace_dir)
        self.report_dir = Path(self.target.workspace_dir).parent / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_data(self) -> Dict[str, Any]:
        data = {
            "target": {
                "id": self.target.id,
                "name": self.target.name,
                "url": self.target.target_url,
                "created_at": self.target.created_at.isoformat()
            },
            "generated_at": datetime.utcnow().isoformat(),
            "workspace_history": [],
            "traffic_summary": []
        }
        
        # Pull Git History
        try:
            history = self.workspace.get_history()
            data["workspace_history"] = history
        except Exception:
            pass
            
        # Pull Recent Proxy Traffic
        recent_traffic = analyzer.get_recent(100)
        for txn in recent_traffic:
            analysis = analyzer.analyze_txn(txn)
            data["traffic_summary"].append({
                "method": txn.request.get("method"),
                "url": txn.request.get("url"),
                "status": analysis.get("status"),
                "latency_ms": txn.latency_ms,
                "waf_detected": analysis.get("has_waf_headers"),
                "suspicious": analysis.get("suspicious_status")
            })
            
        return data

    def export_json(self) -> str:
        data = self.generate_data()
        filename = self.report_dir / f"{self.target.name}_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        filename.write_text(json.dumps(data, indent=2))
        return str(filename)

    def export_html(self) -> str:
        data = self.generate_data()
        
        # Extremely lightweight HTML template without external dependencies
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SQLX Audit Report: {data['target']['name']}</title>
    <style>
        body {{ font-family: -apple-system, system-ui, sans-serif; padding: 2rem; max-width: 1200px; margin: auto; background: #f9fafb; color: #111827; }}
        h1 {{ border-bottom: 2px solid #2563eb; padding-bottom: 0.5rem; }}
        .card {{ background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f3f4f6; }}
        .warning {{ background: #fef2f2; color: #991b1b; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875em; }}
        .badge-green {{ background: #dcfce7; color: #166534; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875em; }}
    </style>
</head>
<body>
    <h1>SQLX Assessment Report</h1>
    
    <div class="card">
        <h2>Target Overview</h2>
        <p><strong>Name:</strong> {data['target']['name']}</p>
        <p><strong>URL:</strong> {data['target']['url']}</p>
        <p><strong>Generated:</strong> {data['generated_at']} UTC</p>
    </div>

    <div class="card">
        <h2>AI Workspace Modifications</h2>
        <table>
            <tr><th>Hash</th><th>Date</th><th>Author</th><th>Message</th></tr>
"""
        for commit in data["workspace_history"]:
            html += f"<tr><td><code>{commit['hash'][:8]}</code></td><td>{commit['date']}</td><td>{commit['author']}</td><td>{commit['message']}</td></tr>\n"
            
        html += """
        </table>
    </div>
    
    <div class="card">
        <h2>Captured Proxy Traffic Summary</h2>
        <table>
            <tr><th>Method</th><th>URL</th><th>Status</th><th>Latency (ms)</th><th>Flags</th></tr>
"""
        for txn in data["traffic_summary"]:
            flags = []
            if txn["waf_detected"]: flags.append('<span class="warning">WAF</span>')
            if txn["suspicious"]: flags.append('<span class="warning">SUSP</span>')
            
            status_cls = "badge-green" if str(txn['status']).startswith("2") else "warning" if str(txn['status']).startswith("4") else ""
            
            html += f"<tr><td>{txn['method']}</td><td><code>{txn['url'][:80]}</code></td><td><span class='{status_cls}'>{txn['status']}</span></td><td>{txn['latency_ms']:.1f}</td><td>{' '.join(flags)}</td></tr>\n"
            
        html += """
        </table>
    </div>
</body>
</html>
"""
        filename = self.report_dir / f"{self.target.name}_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.html"
        filename.write_text(html)
        return str(filename)
