"""
sqlx/agent/planner.py
~~~~~~~~~~~~~~~~~~~~~
Task planner — converts a free-text objective into an ordered list of
concrete steps that the agent executor can process one by one.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class StepStatus(Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    DONE     = "done"
    FAILED   = "failed"
    SKIPPED  = "skipped"


@dataclass
class PlanStep:
    step_id: int
    description: str
    tool: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    status: StepStatus = StepStatus.PENDING
    result: Optional[str] = None
    error: Optional[str] = None


@dataclass
class TaskPlan:
    objective: str
    steps: List[PlanStep] = field(default_factory=list)
    target_id: Optional[str] = None

    def next_pending(self) -> Optional[PlanStep]:
        return next((s for s in self.steps if s.status == StepStatus.PENDING), None)

    def is_complete(self) -> bool:
        return all(
            s.status in (StepStatus.DONE, StepStatus.SKIPPED, StepStatus.FAILED)
            for s in self.steps
        )

    def summary(self) -> str:
        icons = {
            "pending": "○", "running": "●", "done": "✓",
            "failed": "✗", "skipped": "—",
        }
        lines = [f"Plan: {self.objective}"]
        for s in self.steps:
            icon = icons.get(s.status.value, "?")
            approval = " [needs approval]" if s.requires_approval else ""
            lines.append(f"  {icon} Step {s.step_id}: {s.description}{approval}")
        return "\n".join(lines)


# Objective keyword → ordered tool sequence
_TEMPLATES: Dict[str, List[str]] = {
    "scan":        ["fingerprint_target", "run_sqlmap", "save_session_finding", "generate_report"],
    "inject":      ["fingerprint_target", "run_sqlmap", "save_session_finding"],
    "enumerate":   ["run_sqlmap:dbs", "run_sqlmap:tables", "save_session_finding"],
    "dump":        ["run_sqlmap:dump", "save_session_finding", "generate_report"],
    "fingerprint": ["fingerprint_target", "analyze_recent_traffic", "save_session_finding"],
    "traffic":     ["analyze_recent_traffic", "correlate_traffic"],
    "correlate":   ["correlate_traffic", "compare_requests"],
    "replay":      ["replay_request"],
    "report":      ["generate_report"],
    "history":     ["get_workspace_history"],
    "session":     ["list_sessions"],
}

_DESTRUCTIVE = {"run_sqlmap:dump"}


class TaskPlanner:
    """Converts a user objective string into a TaskPlan with concrete steps."""

    def create_plan(self, objective: str, target_id: str = None) -> TaskPlan:
        plan = TaskPlan(objective=objective, target_id=target_id)
        obj_lower = objective.lower()
        step_id = 1

        # No target? first step is scope confirmation
        if not target_id:
            plan.steps.append(PlanStep(
                step_id=step_id,
                description="List available targets and confirm scope",
                tool="list_targets",
                requires_approval=True,
            ))
            step_id += 1

        # Match to template
        matched = False
        for keyword, tools in _TEMPLATES.items():
            if keyword in obj_lower:
                for tool_key in tools:
                    tool_name = tool_key.split(":")[0]
                    destructive = tool_key in _DESTRUCTIVE
                    plan.steps.append(PlanStep(
                        step_id=step_id,
                        description=f"Execute: {tool_key}",
                        tool=tool_name,
                        tool_args={"target_id": target_id} if target_id else {},
                        requires_approval=destructive,
                    ))
                    step_id += 1
                matched = True
                break

        if not matched:
            # Generic: fingerprint → scan → save → report
            for desc, tool, approval in [
                ("Fingerprint WAF and technology stack", "fingerprint_target", False),
                ("Run initial SQL injection scan",       "run_sqlmap",         False),
                ("Save discovered findings",             "save_session_finding", False),
                ("Generate audit report",                "generate_report",    False),
            ]:
                plan.steps.append(PlanStep(
                    step_id=step_id, description=desc, tool=tool,
                    tool_args={"target_id": target_id} if target_id else {},
                    requires_approval=approval,
                ))
                step_id += 1

        return plan
