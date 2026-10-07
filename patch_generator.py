def _patch_generator():
    import sys
    from pathlib import Path
    
    path = Path('/data/data/com.termux/files/home/SQLX/sqlx/reports/generator.py')
    content = path.read_text()
    
    # modify generate_data signature
    content = content.replace(
        'def generate_data(self, use_ai: bool = False) -> Dict[str, Any]:',
        'def generate_data(self, use_ai: bool = False, ai_summary: str = None, ai_risk_assessment: str = None, ai_remediation_steps: str = None) -> Dict[str, Any]:'
    )
    
    # inject the overrides before the if use_ai and self.agent:
    insertion = """
        if ai_summary or ai_risk_assessment or ai_remediation_steps:
            data["ai_summary"] = ai_summary
            data["ai_risk_assessment"] = ai_risk_assessment
            data["ai_remediation_steps"] = ai_remediation_steps
            # don't trigger the self.agent generation if provided
            use_ai = False
            
"""
    content = content.replace('if use_ai and self.agent:', insertion + '        if use_ai and self.agent:')
    
    # modify export_json and export_html
    content = content.replace(
        'def export_json(self, use_ai: bool = False) -> str:',
        'def export_json(self, use_ai: bool = False, ai_summary: str = None, ai_risk_assessment: str = None, ai_remediation_steps: str = None) -> str:'
    )
    content = content.replace(
        'def export_html(self, use_ai: bool = False) -> str:',
        'def export_html(self, use_ai: bool = False, ai_summary: str = None, ai_risk_assessment: str = None, ai_remediation_steps: str = None) -> str:'
    )
    
    content = content.replace(
        'data = self.generate_data(use_ai=use_ai)',
        'data = self.generate_data(use_ai=use_ai, ai_summary=ai_summary, ai_risk_assessment=ai_risk_assessment, ai_remediation_steps=ai_remediation_steps)'
    )
    
    path.write_text(content)

if __name__ == '__main__':
    _patch_generator()
