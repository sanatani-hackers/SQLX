def _patch_tools():
    import sys
    from pathlib import Path
    
    path = Path('/data/data/com.termux/files/home/SQLX/sqlx/agent/tools.py')
    content = path.read_text()
    
    # Replace the generate_report parameter schema and function signature
    old_params = """    parameters={
        "type": "object",
        "properties": {
            "target_id": {
                "type": "string",
                "description": "The ID or name of the target."
            },
            "format": {
                "type": "string",
                "enum": ["html", "json"],
                "description": "Output format for the report (default: 'html')."
            }
        },
        "required": ["target_id"]
    }
)
def generate_report(target_id: str, format: str = "html") -> str:"""

    new_params = """    parameters={
        "type": "object",
        "properties": {
            "target_id": {
                "type": "string",
                "description": "The ID or name of the target."
            },
            "format": {
                "type": "string",
                "enum": ["html", "json"],
                "description": "Output format for the report (default: 'html')."
            },
            "ai_summary": {
                "type": "string",
                "description": "Optional AI-generated executive summary to include in the report."
            },
            "ai_risk_assessment": {
                "type": "string",
                "description": "Optional AI-generated risk assessment."
            },
            "ai_remediation_steps": {
                "type": "string",
                "description": "Optional AI-generated remediation steps."
            }
        },
        "required": ["target_id"]
    }
)
def generate_report(target_id: str, format: str = "html", ai_summary: str = None, ai_risk_assessment: str = None, ai_remediation_steps: str = None) -> str:"""

    if old_params in content:
        content = content.replace(old_params, new_params)
    else:
        print("Could not find old_params in tools.py")
        sys.exit(1)
        
    old_call = """    try:
        if fmt == "json":
            path = gen.export_json()
        else:
            path = gen.export_html()"""
            
    new_call = """    try:
        if fmt == "json":
            path = gen.export_json(ai_summary=ai_summary, ai_risk_assessment=ai_risk_assessment, ai_remediation_steps=ai_remediation_steps)
        else:
            path = gen.export_html(ai_summary=ai_summary, ai_risk_assessment=ai_risk_assessment, ai_remediation_steps=ai_remediation_steps)"""
            
    if old_call in content:
        content = content.replace(old_call, new_call)
    else:
        print("Could not find old_call in tools.py")
        sys.exit(1)

    path.write_text(content)
    print("Patched tools.py successfully.")

if __name__ == '__main__':
    _patch_tools()
