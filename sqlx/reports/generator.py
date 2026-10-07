import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from sqlx.target.manager import TargetManager
from sqlx.workspace.manager import WorkspaceManager
from sqlx.analysis.http import analyzer

class ReportGenerator:
    def __init__(self, target_id: str, agent=None):
        self.target_manager = TargetManager()
        self.target = self.target_manager.load_target(target_id)
        if not self.target:
            raise ValueError(f"Target '{target_id}' not found.")
            
        self.agent = agent
        self.workspace = WorkspaceManager(self.target.workspace_dir)
        self.report_dir = Path(self.target.workspace_dir).parent / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_data(self, use_ai: bool = False, ai_summary: str = None, ai_risk_assessment: str = None, ai_remediation_steps: str = None) -> Dict[str, Any]:
        data = {
            "target": {
                "id": self.target.id,
                "name": self.target.name,
                "url": self.target.target_url,
                "created_at": self.target.created_at.isoformat(),
                "workspace_dir": self.target.workspace_dir
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
            
        
        if ai_summary or ai_risk_assessment or ai_remediation_steps:
            data["ai_summary"] = ai_summary
            data["ai_risk_assessment"] = ai_risk_assessment
            data["ai_remediation_steps"] = ai_remediation_steps
            # don't trigger the self.agent generation if provided
            use_ai = False
            
        if use_ai and self.agent:
            from sqlx.session.manager import SessionManager
            sm = SessionManager()
            sessions = sm.list_sessions(self.target.workspace_dir)
            if sessions:
                latest_session = sessions[-1]
                findings = latest_session.findings
                observations = latest_session.observations
                
                # We put findings in data so report formatters can use them
                data["findings"] = findings
                
                prompt = (
                    f"Write an executive summary, risk assessment, and remediation steps based on these findings: {findings} "
                    f"and observations: {observations}. "
                    "Format as JSON: {'ai_summary': '...', 'ai_risk_assessment': '...', 'ai_remediation_steps': '...'}"
                )
                try:
                    # Depending on how the provider works
                    if hasattr(self.agent, "provider"):
                        resp = self.agent.provider.generate([{"role": "user", "content": prompt}])
                        content = resp.content if hasattr(resp, "content") else str(resp)
                    else:
                        content = self.agent.ask(prompt)
                    
                    import re
                    match = re.search(r'\{.*\}', content, re.DOTALL)
                    if match:
                        parsed = json.loads(match.group(0))
                        data["ai_summary"] = parsed.get("ai_summary", "")
                        data["ai_risk_assessment"] = parsed.get("ai_risk_assessment", "")
                        data["ai_remediation_steps"] = parsed.get("ai_remediation_steps", "")
                except Exception as e:
                    print(f"AI generation failed: {e}")
                    
        return data

    def export_json(self, use_ai: bool = False, ai_summary: str = None, ai_risk_assessment: str = None, ai_remediation_steps: str = None) -> str:
        from sqlx.reports.json import build_json_report
        data = self.generate_data(use_ai=use_ai, ai_summary=ai_summary, ai_risk_assessment=ai_risk_assessment, ai_remediation_steps=ai_remediation_steps)
        json_str = build_json_report(data)
        filename = self.report_dir / f"{self.target.name}_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        filename.write_text(json_str)
        return str(filename)

    def export_html(self, use_ai: bool = False, ai_summary: str = None, ai_risk_assessment: str = None, ai_remediation_steps: str = None) -> str:
        from sqlx.reports.html import build_html_report
        data = self.generate_data(use_ai=use_ai, ai_summary=ai_summary, ai_risk_assessment=ai_risk_assessment, ai_remediation_steps=ai_remediation_steps)
        html_str = build_html_report(data)
        filename = self.report_dir / f"{self.target.name}_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.html"
        filename.write_text(html_str)
        return str(filename)
