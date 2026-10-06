# SQLX Agent Optimization: Efficient Loop & UX Design

A redesigned agent architecture focused on **efficient iteration**, **clear user communication**, and **reduced token waste**.

---

## Current Problems

1. **Agent iteration is inefficient**
   - Agent makes tool calls one at a time
   - Each tool call blocks for network I/O (proxy traffic, SQLMap output)
   - Agent re-analyzes the same traffic repeatedly
   - No caching of tool results within a session

2. **User experience is opaque**
   - Agent makes decisions without showing reasoning
   - No real-time feedback on what agent is doing
   - Users cannot guide agent mid-session
   - Reports are post-hoc, not interactive

3. **Tool ecosystem is fragmented**
   - Tools return inconsistent formats
   - No standard "observation" protocol
   - Tool failures cause agent confusion (lost context)

4. **Session state is not actionable**
   - Findings are just stored; no ranking or prioritization
   - No memory of what agent has already tried
   - No "learning" between agent invocations

---

## Solution: Agent 2.0 Architecture

### Core Principle: **Observations First, Tools Second**

Instead of:
```
Query → Tool Call → LLM → Tool Call → ...
```

Design:
```
Query → Collect Observations (parallel) → Analyze → Decide Actions → Execute (parallel) → Persist
```

---

## 1. Parallel Observation Collection

**Current:** Agent calls one tool, waits for response, calls next tool.  
**New:** Agent collects all available observations **before** deciding on actions.

### Implementation

```python
class ObservationCollector:
    """Collects observations in parallel without blocking agent."""
    
    def collect_all(self, target_id: str, session: SessionState) -> Observations:
        """
        Gather all relevant observations at once:
        - Recent proxy traffic (cached from history)
        - SQLMap output (if running)
        - Workspace changes (git diff)
        - Previous findings (from session)
        - Target scope (permissions)
        
        Returns structured Observations object.
        """
        observations = {}
        
        # 1. Proxy traffic (no network I/O — read from cache)
        observations['recent_traffic'] = self._get_cached_traffic(target_id, limit=20)
        observations['traffic_analysis'] = self._analyze_cached_traffic(observations['recent_traffic'])
        
        # 2. SQLMap status (non-blocking check)
        if self.sqlmap_runner.is_running(target_id):
            observations['sqlmap_status'] = 'RUNNING'
            observations['sqlmap_progress'] = self.sqlmap_runner.get_progress(target_id)
        else:
            observations['sqlmap_status'] = 'IDLE'
            observations['sqlmap_latest_output'] = self.sqlmap_runner.get_cached_output(target_id)
        
        # 3. Workspace state (no network I/O)
        observations['workspace_diff'] = self.workspace_mgr.get_diff(target_id)
        observations['workspace_history'] = self.workspace_mgr.get_history(target_id, limit=5)
        
        # 4. Session memory
        observations['findings'] = session.findings
        observations['previous_actions'] = session.observations
        
        # 5. Target scope
        observations['target_scope'] = self.target_mgr.get_scope(target_id)
        
        return Observations(**observations)
```

**Benefits:**
- All data is ready before agent thinks
- No blocking I/O during reasoning
- Agent never needs to retry/refresh
- Clear observation protocol for prompts

---

## 2. Structured Observation Protocol

Replace vague tool outputs with a strict **Observation Schema**.

```python
class Observation:
    """Base class for all observations."""
    type: str  # 'traffic', 'sqlmap', 'workspace', 'finding', etc.
    timestamp: datetime
    source: str  # which tool/component provided this
    confidence: float  # 0.0 - 1.0
    data: dict
    metadata: dict = {}  # context about the observation

class TrafficObservation(Observation):
    type = 'traffic'
    request_count: int
    status_codes: List[int]
    waf_indicators: List[str]
    injection_signals: List[str]  # ['timing_anomaly', 'response_diff', 'error_based']
    
class SQLMapObservation(Observation):
    type = 'sqlmap'
    status: str  # 'RUNNING', 'COMPLETE', 'FAILED'
    findings: List[Finding]
    databases_found: List[str]
    payloads_successful: List[str]
    
class WorkspaceObservation(Observation):
    type = 'workspace'
    uncommitted_changes: int
    last_commit_hash: str
    last_commit_message: str
    
class Observations:
    """Aggregated snapshot of all available knowledge."""
    traffic: TrafficObservation
    sqlmap: SQLMapObservation
    workspace: WorkspaceObservation
    findings: List[Finding]
    
    def to_prompt_text(self) -> str:
        """Convert to concise text for LLM."""
        lines = [
            f"[TRAFFIC] {self.traffic.request_count} requests captured",
            f"  Status codes: {set(self.traffic.status_codes)}",
            f"  WAF detected: {bool(self.traffic.waf_indicators)}",
            f"  Injection signals: {', '.join(self.traffic.injection_signals) or 'none'}",
            "",
            f"[SQLMAP] Status: {self.sqlmap.status}",
            f"  Findings: {len(self.sqlmap.findings)}",
            f"  Payloads successful: {self.sqlmap.payloads_successful}",
            "",
            f"[WORKSPACE] {self.workspace.uncommitted_changes} uncommitted changes",
            f"  Last action: {self.workspace.last_commit_message}",
            "",
            f"[SESSION] {len(self.findings)} findings recorded",
        ]
        return "\n".join(lines)
```

**Benefits:**
- Agent receives consistent, typed data
- Prompts are more concise and structured
- Easier to integrate findings into LLM context
- Clear traceability (source field)

---

## 3. Async Tool Execution with Polling

**Current:** Agent calls tool, blocks waiting for result.  
**New:** Agent submits actions in parallel, polls for completion.

```python
class ActionExecutor:
    """Execute actions (tools) in parallel with polling."""
    
    def submit_actions(self, actions: List[Action]) -> Dict[str, JobID]:
        """
        Submit multiple actions without waiting.
        Returns job IDs for polling.
        """
        job_ids = {}
        
        for action in actions:
            if action.type == 'run_sqlmap':
                job_id = self.sqlmap_runner.start_async(
                    action.target_id,
                    action.args,
                    timeout=action.timeout or 300
                )
            elif action.type == 'apply_patch':
                job_id = self.workspace_mgr.apply_patch_async(
                    action.target_id,
                    action.patch,
                    validate=True
                )
            elif action.type == 'replay_request':
                job_id = self.proxy_replayer.replay_async(
                    action.request_id,
                    action.modifications
                )
            else:
                # Quick synchronous actions
                job_id = self._execute_sync(action)
            
            job_ids[action.name] = job_id
        
        return job_ids
    
    def poll_actions(self, job_ids: Dict[str, JobID], timeout: float = 30) -> Dict[str, Result]:
        """Poll for action completion, return results as they arrive."""
        results = {}
        start = time.time()
        
        while job_ids and (time.time() - start) < timeout:
            for name, job_id in list(job_ids.items()):
                result = self._get_result(job_id)
                if result is not None:
                    results[name] = result
                    del job_ids[name]
            
            if job_ids:
                time.sleep(0.5)  # Poll every 500ms
        
        # Timeout on remaining jobs
        for name, job_id in job_ids.items():
            results[name] = Result(
                status='TIMEOUT',
                error=f'Job {job_id} exceeded {timeout}s timeout'
            )
        
        return results
```

**Benefits:**
- Multiple SQLMap runs can happen in parallel
- Workspace patches apply while proxy runs
- No wasted time blocking on single tool
- Agent can receive partial results and adapt

---

## 4. Agent Decision Framework

**Current:** Agent loop is generic ReAct: "think → call tool → observe → repeat".  
**New:** Agent follows a **structured decision tree** based on observations.

```python
class AgentDecisionEngine:
    """High-level decision logic based on observations."""
    
    def decide_actions(self, query: str, observations: Observations, session: SessionState) -> List[Action]:
        """
        Given observations, decide what actions to take.
        Returns a list of Action objects to execute.
        """
        actions = []
        
        # 1. Has SQLMap found injections?
        if observations.sqlmap.findings:
            # Action: analyze findings in detail
            actions.append(Action(
                type='analyze_findings',
                findings=observations.sqlmap.findings,
                priority='HIGH'
            ))
            
            # Action: save findings to session
            actions.append(Action(
                type='save_findings',
                findings=observations.sqlmap.findings,
                session_id=session.id
            ))
            
            # Possibly: ask user for confirmation before escalation
            if len(observations.sqlmap.findings) > 5:
                actions.append(Action(
                    type='request_approval',
                    description=f"Found {len(observations.sqlmap.findings)} injections. Recommend exploitation/reporting.",
                    risk_level='CRITICAL'
                ))
        
        # 2. Is SQLMap still running?
        if observations.sqlmap.status == 'RUNNING':
            # Action: wait for completion and re-observe
            actions.append(Action(
                type='wait_and_reobserve',
                target_id=session.target_id,
                timeout=60
            ))
        
        # 3. Has traffic analysis revealed new signals?
        elif observations.traffic.injection_signals:
            if 'timing_anomaly' in observations.traffic.injection_signals:
                # Action: run time-based SQLMap against vulnerable parameter
                actions.append(Action(
                    type='run_sqlmap',
                    target_id=session.target_id,
                    args=['--time-sec=5', '--technique=T'],
                    priority='HIGH'
                ))
            
            if 'response_diff' in observations.traffic.injection_signals:
                # Action: run union-based SQLMap
                actions.append(Action(
                    type='run_sqlmap',
                    target_id=session.target_id,
                    args=['--technique=U'],
                    priority='MEDIUM'
                ))
        
        # 4. Should we generate a report?
        if len(session.findings) > 0 and observations.sqlmap.status != 'RUNNING':
            actions.append(Action(
                type='generate_report',
                target_id=session.target_id,
                format='html'
            ))
        
        return actions
```

**Benefits:**
- Agent decisions are auditable (clear action list)
- No wasted tool calls
- Decisions follow domain logic, not generic LLM reasoning
- Easy to override/tune without retraining

---

## 5. User Experience Loop

**Current:** User starts agent, waits for result, reads output.  
**New:** Real-time dashboard showing agent progress and allowing intervention.

```python
class InteractiveAgentSession:
    """User-facing agent session with real-time updates."""
    
    def run_interactive(self, target_id: str, objective: str):
        """Run agent with live dashboard updates."""
        session = self.session_manager.start_session(target_id, objective)
        
        # Phase 1: Observe
        self.ui.show_status("📊 Collecting observations...")
        observations = self.observer.collect_all(target_id, session)
        self.ui.display_observations(observations)
        
        # Phase 2: Decide
        self.ui.show_status("🧠 Agent deciding actions...")
        actions = self.decision_engine.decide_actions(objective, observations, session)
        self.ui.display_actions(actions)
        
        # Phase 3: Approve (if risky)
        risky_actions = [a for a in actions if a.risk_level in ('HIGH', 'CRITICAL')]
        if risky_actions and not self.auto_approve:
            self.ui.show_status("⏸️  Awaiting approval...")
            for action in risky_actions:
                if not self.ui.prompt_approval(action):
                    actions.remove(action)
        
        # Phase 4: Execute
        self.ui.show_status("⚙️  Executing actions...")
        job_ids = self.executor.submit_actions(actions)
        
        # Phase 5: Monitor
        while job_ids:
            self.ui.show_status(f"⏳ Running {len(job_ids)} jobs...")
            results = self.executor.poll_actions(job_ids, timeout=5)
            
            for action_name, result in results.items():
                self.ui.update_action_status(action_name, result)
                if result.status == 'COMPLETE':
                    session.add_observation(Observation(
                        type='action_complete',
                        action=action_name,
                        result=result.data
                    ))
            
            job_ids = {k: v for k, v in job_ids.items() if k not in results}
        
        # Phase 6: Re-observe
        self.ui.show_status("📊 Re-observing...")
        observations = self.observer.collect_all(target_id, session)
        self.ui.display_observations(observations)
        
        # Phase 7: Decide again (loop)
        if self.should_continue(observations, session):
            self.ui.show_status("🔄 Running next iteration...")
            self.run_interactive(target_id, objective)  # Recursively continue
        else:
            self.ui.show_status("✅ Agent loop complete")
            self.session_manager.save(session)
            self.ui.display_summary(session)
```

**Benefits:**
- User sees exactly what agent is doing in real-time
- User can stop/modify/approve actions mid-session
- No surprise actions
- Builds trust

---

## 6. Session Memory & Learning

**Current:** Agent forgets everything between CLI invocations.  
**New:** Agent builds a persistent **decision journal** that informs future sessions.

```python
class SessionMemory:
    """Persistent memory of what agent has tried and learned."""
    
    def record_decision(self, session_id: str, decision: Decision):
        """Record a decision made by the agent."""
        record = {
            'timestamp': datetime.utcnow(),
            'decision': decision.action,
            'observations': decision.observations,
            'result': decision.result,
            'outcome': decision.outcome,  # success, partial, failed, escalated
            'reasoning': decision.reasoning
        }
        
        # Store in session
        session = self.session_mgr.load(session_id)
        session.decision_history.append(record)
        self.session_mgr.save(session)
        
        # Also store in global searchable index (for "have we tried this before?")
        self.rag.add_decision(
            target_name=session.target_id,
            decision=decision.action,
            outcome=decision.outcome,
            text=decision.reasoning
        )
    
    def get_similar_past_decisions(self, query: str, top_k: int = 3) -> List[Decision]:
        """
        Query: "SQL injection in login endpoint"
        Returns: past decisions that are semantically similar.
        """
        return self.rag.query_decisions(query, top_k=top_k)
```

**Example Use:**
```
Agent is asked: "Check if username parameter is vulnerable to SQLi"
Agent searches memory: "Have we tested this before?"
Memory returns: "Yes, on 2026-10-04, we tested login.username with boolean-based technique. Found it vulnerable."
Agent decides: "Skip redundant test, escalate to exploitation."
```

**Benefits:**
- Agent learns from past sessions
- Avoids redundant testing
- Faster convergence to findings
- Clear audit trail

---

## 7. Structured Prompt Template

Instead of feeding raw observations, use a **consistent prompt structure**.

```python
AGENT_PROMPT_TEMPLATE = """
You are SQLX, an automated SQL injection testing agent.

## Current State

### Observations
{observations_text}

### Session History (last 3 actions)
{session_history}

### Similar Past Findings
{similar_findings}

## Available Actions

1. **run_sqlmap** — Test for SQL injection
   Args: target_id, technique (T/U/E/B), timeout
   
2. **analyze_traffic** — Analyze recent proxy traffic for anomalies
   Args: target_id, limit
   
3. **apply_patch** — Apply tamper script to SQLMap
   Args: target_id, patch_content, reason
   
4. **replay_request** — Replay request with modifications
   Args: request_id, modifications
   
5. **save_finding** — Record a vulnerability finding
   Args: target_id, finding_summary, confidence, impact
   
6. **request_approval** — Ask user for approval before risky action
   Args: action_description, risk_level (LOW/MEDIUM/HIGH/CRITICAL)
   
7. **generate_report** — Generate HTML/JSON audit report
   Args: target_id, format

## Your Task

{user_query}

## Decision Process

1. Analyze current observations — what data do we have?
2. Check past sessions — have we learned something relevant?
3. Identify gaps — what do we NOT know?
4. Decide actions — which tools will fill gaps most efficiently?
5. Rank by confidence — high-confidence actions first.

## Output Format

Respond with a JSON block:
```json
{{
  "thinking": "Your reasoning here (1-2 sentences)",
  "confidence": 0.85,
  "actions": [
    {{"type": "run_sqlmap", "args": [...], "priority": "HIGH"}},
    {{"type": "save_finding", "args": [...], "priority": "MEDIUM"}}
  ],
  "explanation": "Why these actions will help"
}}
```

Do NOT call tools directly. Output the action list; the executor will run them.
"""
```

**Benefits:**
- Agent reasons systematically
- Clear input/output contract
- Easier to debug and trace
- Less token waste (no rambling)

---

## 8. Efficiency Metrics Dashboard

Track agent performance.

```python
class AgentMetrics:
    """Track efficiency of agent sessions."""
    
    def record_session(self, session: SessionState, duration_sec: float):
        token_efficiency = len(session.findings) / duration_sec  # findings per second
        action_efficiency = len(session.findings) / len(session.decision_history)  # findings per action
        
        metrics = {
            'session_id': session.id,
            'target_id': session.target_id,
            'duration_sec': duration_sec,
            'findings_count': len(session.findings),
            'actions_taken': len(session.decision_history),
            'token_efficiency': token_efficiency,
            'action_efficiency': action_efficiency,
            'tool_call_count': sum(1 for d in session.decision_history if d.type == 'tool_call'),
            'llm_call_count': sum(1 for d in session.decision_history if d.type == 'llm_reasoning')
        }
        
        self.db.insert('session_metrics', metrics)
        return metrics
    
    def get_dashboard(self) -> Dict:
        """Return metrics for UI dashboard."""
        recent_sessions = self.db.query('session_metrics', limit=10, order_by='session_id DESC')
        
        return {
            'avg_duration': sum(s['duration_sec'] for s in recent_sessions) / len(recent_sessions),
            'avg_findings_per_session': sum(s['findings_count'] for s in recent_sessions) / len(recent_sessions),
            'avg_token_efficiency': sum(s['token_efficiency'] for s in recent_sessions) / len(recent_sessions),
            'recent_sessions': recent_sessions
        }
```

**Benefits:**
- Track if agent is getting faster/better
- Identify bottlenecks
- Optimize prompt/tool design based on data

---

## Implementation Roadmap

### Phase 1: Observation Collection (Week 1)
- [ ] Implement `ObservationCollector` class
- [ ] Define `Observation` schema
- [ ] Integrate with existing traffic analyzer, SQLMap runner, workspace manager
- [ ] Test: observations collect without blocking

### Phase 2: Decision Engine (Week 1)
- [ ] Implement `AgentDecisionEngine` class
- [ ] Define `Action` schema
- [ ] Add decision logic for common SQL injection scenarios
- [ ] Test: decisions are reasonable given observations

### Phase 3: Async Execution (Week 2)
- [ ] Implement `ActionExecutor` with parallel job submission
- [ ] Add polling loop
- [ ] Modify SQLMap runner to support async start/status
- [ ] Test: multiple actions run in parallel

### Phase 4: User Experience (Week 2)
- [ ] Implement `InteractiveAgentSession` with real-time UI updates
- [ ] Add approval gates for risky actions
- [ ] Integrate with existing dashboard
- [ ] Test: user can monitor and control agent

### Phase 5: Session Memory (Week 3)
- [ ] Implement `SessionMemory` for decision logging
- [ ] Integrate with RAG index
- [ ] Add "similar past decisions" retrieval
- [ ] Test: agent avoids redundant actions

### Phase 6: Metrics & Monitoring (Week 3)
- [ ] Implement `AgentMetrics` collection
- [ ] Add dashboard visualizations
- [ ] Test: metrics accurately reflect agent performance

---

## Expected Impact

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Agent iterations per target | 8-12 | 4-6 | 40-50% reduction |
| Time to first finding | 2-3 min | 30-60 sec | 60% faster |
| User intervention needed | High (unclear actions) | Low (clear, visible actions) | Much better UX |
| Token efficiency (findings/token) | Low (redundant tool calls) | High (no wasted calls) | 50-70% less tokens |
| Session resumability | No | Yes (memory preserved) | Game-changer |
| Auditability | Medium (implicit reasoning) | High (explicit decision log) | Better compliance |

---

## Code Organization

```
sqlx/
├── agent/
│   ├── agent.py (update main loop)
│   ├── observations.py (new — ObservationCollector)
│   ├── decisions.py (new — AgentDecisionEngine)
│   ├── executor.py (new — ActionExecutor)
│   ├── memory.py (existing, extend with SessionMemory)
│   └── tools.py (update tool response format)
├── ui/
│   ├── dashboard.py (update with real-time agent UI)
│   └── session_monitor.py (new — live session display)
├── metrics/
│   └── agent_metrics.py (new — efficiency tracking)
└── session/
    └── memory.py (new — decision journal)
```

---

## Next Steps

1. **Review** this design with the team.
2. **Prioritize** which phase to start with.
3. **Create GitHub issues** for each phase task.
4. **Assign** implementation owners.
5. **Integrate** incrementally — no big refactor.

This design should result in a **faster, more efficient, more transparent** agent that users can trust.
