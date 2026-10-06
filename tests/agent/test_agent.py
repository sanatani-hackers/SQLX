import pytest
from sqlx.agent.planner import TaskPlanner
from sqlx.agent.decision import DecisionEngine, Decision
from sqlx.agent.observer import Observer

def test_planner_creates_plan():
    planner = TaskPlanner()
    plan = planner.create_plan("Scan for injection and report", target_id="t1")
    assert plan.objective == "Scan for injection and report"
    assert len(plan.steps) > 0
    
    # Next pending should be the first step
    step = plan.next_pending()
    assert step is not None
    assert step.step_id == 1

def test_decision_engine():
    # Autonomous by default
    engine = DecisionEngine(autonomous=True, read_only=False)
    decision, _ = engine.evaluate("run_sqlmap", {})
    assert decision == Decision.EXECUTE
    
    # Destructive operations still need confirm in autonomous mode
    decision, _ = engine.evaluate("edit_workspace_file", {})
    assert decision == Decision.CONFIRM
    
    # Read-only mode blocks write operations
    ro_engine = DecisionEngine(autonomous=True, read_only=True)
    decision, _ = ro_engine.evaluate("run_sqlmap", {})
    assert decision == Decision.BLOCK

def test_observer():
    obs = Observer()
    obs.observe_sqlmap_output("injection points", {"injection_found": True, "payloads": ["' OR 1=1--"]})
    assert len(obs.get_critical()) == 1
    assert obs.get_critical()[0].details["payloads"] == ["' OR 1=1--"]
