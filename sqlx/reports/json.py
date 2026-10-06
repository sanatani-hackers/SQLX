"""
sqlx/reports/json.py
~~~~~~~~~~~~~~~~~~~~
JSON report serialisation from report data dict.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict


def build_json_report(data: Dict[str, Any]) -> str:
    """Serialise report data to a formatted JSON string."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator":    "SQLX v1.0",
        **data,
    }
    return json.dumps(report, indent=2, default=str)
