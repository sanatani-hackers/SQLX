# SQLX Development Backlog

Prioritized by phase and dependency.

---

## 🔴 PRIORITY 1: Core Completeness (MVP Foundation)

These block the rest of the system from working end-to-end.

### 1.1 Complete the Proxy ↔ Analysis ↔ Agent Loop

**Status:** 70% done | ~60% of phase 3-4

**What exists:**
- Proxy server captures requests/responses and publishes events
- Traffic analyzer subscribes to events and builds history
- Basic HTTP transaction recording

**What's missing:**
- Proxy history persistence — currently stored only in memory; needs to survive session restarts
  - Add `sqlx/proxy/persistence.py` to store request/response pairs to disk (JSON or SQLite)
  - Implement `get_all()`, `get_by_id()`, `get_recent()` on persistent storage
  - Current code tries to call `proxy_history.get_by_id()` but module doesn't export it properly
- Request ID tracking — the plan calls for stable IDs across the session
  - Add explicit request ID assignment in proxy handler (increment counter or UUID)
  - Ensure response can be matched back to request via ID
  - Store ID in both proxy history and analysis layer
- Analysis response.py module — exists but is incomplete
  - Should detect response anomalies: status code changes, body size changes, timing changes
  - Currently only `analyze_txn()` does basic checks; needs deeper response diff analysis
  - Add response fingerprinting (hash of response body for baseline comparisons)

**Estimated effort:** 1-2 days  
**Files to create/modify:**
- `sqlx/proxy/persistence.py` (new)
- `sqlx/proxy/server.py` (modify to assign request IDs)
- `sqlx/analysis/response.py` (complete implementation)

---

### 1.2 Fix Agent Tool Execution Loop

**Status:** 80% done | agent core is solid but tools are not fully wired

**What exists:**
- `SQLXAgent.ask()` implements a ReAct loop
- Tool registry and execution framework
- Most tools exist (run_sqlmap, read_workspace_file, apply_workspace_patch, etc.)

**What's missing:**
- Tool error recovery — agent does not handle tool timeouts or long-running operations
  - Add timeout wrapper to `registry.execute()`
  - Implement cancellation token for long-running SQLMap jobs
  - Add retry logic for transient tool failures
- Tool output standardization — different tools return different formats
  - Standardize all tool responses to `{ "clean_output": str, "summary": dict, "success": bool }`
  - Currently `run_sqlmap` does this well, but others are ad-hoc
  - Update tools to follow this pattern
- Agent approval flow — plan requires asking user for risky operations
  - Add `ask_for_approval(action_description, risk_level)` method to `SQLXAgent`
  - Integrate into tools like `apply_workspace_patch` and `write_workspace_file`
  - Currently tools execute without approval gate
- Tool findings injection into memory — findings should feed back into agent context
  - Modify agent to automatically add findings to the RAG index
  - Store findings alongside session state
  - Current finding detection works but is not fully connected

**Estimated effort:** 1-2 days  
**Files to create/modify:**
- `sqlx/agent/agent.py` (add approval flow, improve error handling)
- `sqlx/agent/tools.py` (standardize response format)

---

### 1.3 Session State & Persistence

**Status:** 60% done | basic structure exists, but incomplete workflow

**What exists:**
- `SessionManager`, `SessionState`, and persistence module exist
- Sessions can be created and stored to JSON
- Session resume command exists

**What's missing:**
- Session ↔ Agent connection — agent does not actually load/save session state
  - Modify `SQLXAgent.ask()` to load session context before executing
  - Save session after each agent turn (findings, observations, memory snapshots)
  - Currently agent memory is ephemeral per CLI invocation
- Observations logging — no structured way to record agent observations
  - `SessionState.add_observation()` exists but the agent does not use it
  - Add observation types: analysis, planning, execution, validation
- Session memory integration — agent memory is separate from session state
  - Move agent memory to session state
  - Implement session context injection to agent memory on resume
- Finding validation/review — findings should be marked as unreviewed until user confirms
  - Add finding status (`new`, `confirmed`, `false_positive`, `exploited`)
  - Add user review workflow in the dashboard

**Estimated effort:** 2 days  
**Files to create/modify:**
- `sqlx/session/state.py` (expand to track observations, memory snapshots)
- `sqlx/agent/agent.py` (integrate session save/load)
- `sqlx/ui/dashboard.py` (add session context display)

---

### 1.4 Workspace Validation & Rollback Guarantee

**Status:** 80% done | basic rollback works but validation is weak

**What exists:**
- Git-based workspace history
- Rollback to commit
- Snapshot before patch

**What's missing:**
- Pre-patch validation — should verify patch applies cleanly before committing
  - Add dry-run test: `git apply --check` before actual apply
  - Return validation result to the agent
  - Currently `apply_workspace_patch` can fail silently
- Post-patch validation — should verify the workspace still has a valid SQLMap copy
  - Add validation: `python sqlmap/sqlmap.py --version` after patch
  - Add checks that key files still exist
  - Return validation status to the tool caller
- Automatic rollback on failure — if validation fails, rollback automatically
  - Wrap workspace modifications in transaction-like semantics
  - On validation failure, call rollback to the last known-good commit
  - Report rollback to the agent and user
- Backup metadata — snapshots should store more context
  - current snapshot only stores git commit
  - Add: patch content, validation result, AI reasoning, risk level

**Estimated effort:** 1 day  
**Files to create/modify:**
- `sqlx/workspace/manager.py` (add validation helpers)
- `sqlx/agent/tools.py` (update patch tools to call validation)

---

## 🟡 PRIORITY 2: Safety & Audit (Phase 5-6 Items)

These are critical for production use but not strictly blocking the MVP loop.

### 2.1 Audit Logging Infrastructure

**Status:** 20% done | event bus exists but no persistent audit log

**What exists:**
- Event bus publishes events
- Events for major actions exist

**What's missing:**
- Persistent audit log — events are only in-memory
  - Create `sqlx/audit/logger.py` to subscribe to all events and write to disk
  - Log to `targets/<target>/logs/audit.jsonl` (JSON lines format)
  - Include timestamp, actor, action, before/after state, result
- Audit event enrichment — some events are missing critical context
  - `ProxyResponseReceived` should include request fingerprint
  - `SQLMapStarted` should include target context
  - `PatchApplied` should include diff summary and validation result
- Audit query API —  need to search/filter audit logs
  - Add `get_events_for_target()`, `get_events_by_actor()`, `get_events_by_type()`
- Audit trail in HTML reports — reports should show audit log timeline
  - Modify `ReportGenerator` to include audit events chronologically

**Estimated effort:** 2-3 days  
**Files to create/modify:**
- `sqlx/audit/logger.py` (new)
- `sqlx/events/events.py` (add missing event types)
- `sqlx/events/handlers.py` (add audit handler)
- `sqlx/reports/generator.py` (integrate audit log)

---

### 2.2 Target Isolation Enforcement

**Status:** 60% done | workspaces are isolated but no enforcement layer

**What exists:**
- Each target has a separate workspace directory
- Each target gets a separate SQLMap copy

**What's missing:**
- Permission checks — should verify the agent cannot escape the workspace
  - Add `security/permissions.py` with checks for path traversal
  - All file operations should validate they stay within `target.workspace_dir`
- Resource quotas — should limit SQLMap CPU/memory per target
  - Add timeout enforcement (already in runner but should be configurable)
  - Add memory limits via subprocess resource limits
  - Add disk-space quota checks before snapshots
- Target scope validation — verify target URLs are in an authorized list
  - Implement `target.scope` (CIDR ranges, domain list, regex patterns)
  - Check every URL through agent tools against scope
  - Reject out-of-scope requests with a clear error
- Cross-target data leakage detection — ensure one target cannot read another
  - Run periodic checks that workspace directories are properly isolated

**Estimated effort:** 2 days  
**Files to create/modify:**
- `sqlx/target/scope.py` (complete implementation)
- `sqlx/target/permissions.py` (add actual enforcement)
- `sqlx/security/validation.py` (new)

---

### 2.3 Approval & User Consent Gates

**Status:** 30% done | skeleton exists but not integrated

**What exists:**
- CLI prompt infrastructure exists
- Agent has logic for user nudges

**What's missing:**
- Approval workflow for risky operations
  - Define risk levels: info, warning, critical
  - Create approval form: approve / deny / abort
  - High-risk operations: patch application, workspace modification, workspace rollback
- Two-person approval for critical operations
  - Support multi-approver workflows
- Approval audit trail — record who approved what
  - Already possible with audit logging if integrated properly
- User review checkpoint — after findings, ask user before escalation
  - Show finding summary, confidence, recommended action
  - Options: confirm, discard, modify
- Timeout on approvals — approvals should expire if not answered
  - Add timeout parameter (default 5 minutes)

**Estimated effort:** 1.5 days  
**Files to create/modify:**
- `sqlx/approval/flow.py` (new)
- `sqlx/ui/dashboard.py` (add approval UI)
- Modify tools in `sqlx/agent/tools.py` to check approvals

---

## 🟢 PRIORITY 3: Feature Completeness (Remaining Items)

Important but not blocking MVP.

### 3.1 Complete Testing Suite (Phase 9)

**Status:** 10% done | tests folder exists, but many parts are minimal

**What exists:**
- Basic test structure for agent, proxy, SQLMap, workspace, and analysis

**What's missing:**
- Unit tests covering each module with adequate coverage
- Integration tests for end-to-end flows
- Security tests for isolation and rollback
- Controlled lab testing against vulnerable applications

**Estimated effort:** 3-4 days  
**Files to create/modify:**
- `tests/agent/test_agent.py`
- `tests/proxy/test_proxy.py`
- `tests/sqlmap/test_runner.py`
- `tests/workspace/test_workspace.py`
- `tests/analysis/test_analysis.py`

---

### 3.2 Documentation & Examples (Phase 7 Deliverable)

**Status:** 5% done | only architecture docs exist

**What's missing:**
- User guide (`docs/USER_GUIDE.md`)
- API reference (`docs/API.md`)
- Architecture deep-dive (`docs/ARCHITECTURE.md`)
- Troubleshooting guide (`docs/TROUBLESHOOTING.md`)
- Security guide (`docs/SECURITY.md`)
- Example scripts under `examples/`
- README expansion

**Estimated effort:** 2 days  
**Files to create:**
- `docs/USER_GUIDE.md`
- `docs/API.md`
- `docs/ARCHITECTURE.md`
- `docs/TROUBLESHOOTING.md`
- `docs/SECURITY.md`
- `examples/*.py`
- Expand `README.md`

---

### 3.3 Advanced Analysis Features (Phase 4 Items)

**Status:** 40% done | basic analysis exists, advanced features missing

**What exists:**
- HTTP transaction recording
- Basic response analysis (status, WAF headers)
- Traffic analyzer subscribes to events

**What's missing:**
- Timing analysis for response lag anomalies
- Improved fingerprinting for WAF / technology detection
- Correlation engine to connect payload changes with response changes
- Response diffing for deeper injection evidence

**Estimated effort:** 2-3 days  
**Files to modify:**
- `sqlx/analysis/timing.py`
- `sqlx/analysis/fingerprint.py`
- `sqlx/analysis/correlation.py`
- `sqlx/analysis/response.py`

---

### 3.4 Interactive Dashboard Enhancements (Phase 7)

**Status:** 50% done | basic dashboard exists but needs features

**What's missing:**
- Real-time traffic viewer
- Session context display
- Approval prompt UI
- Diff viewer
- Report browser
- Search in findings
- Alert notifications

**Estimated effort:** 2-3 days  
**Files to modify:**
- `sqlx/ui/dashboard.py`
- `sqlx/ui/tui.py`
- `sqlx/ui/console.py`

---

## 🔵 PRIORITY 4: Nice-to-Have (Future Enhancements)

### 4.1 Extension System

**Status:** 70% done | framework exists but no real extensions

**What's missing:**
- Real plugin examples and a stable registry contract
- Extension dependency management

### 4.2 Database Integration

**Status:** 20% done | models exist, but migrations are missing

**What's missing:**
- SQLite/Postgres setup
- Migration framework
- Replacement of JSON-based persistence with database queries

### 4.3 Multi-User & Team Features

**Status:** 0% done

**What's missing:**
- User authentication / RBAC
- Session sharing
- Team audit logs
- Workspace locking

---

## Summary Table

| Priority | Component | Phase | Status | Effort | Blocker? |
|----------|-----------|-------|--------|--------|----------|
| 1.1 | Proxy ↔ Analysis ↔ Agent Loop | 3-4 | 70% | 1-2d | Yes |
| 1.2 | Agent Tool Execution Loop | 5 | 80% | 1-2d | Yes |
| 1.3 | Session State & Persistence | 5 | 60% | 2d | Yes |
| 1.4 | Workspace Validation & Rollback | 2 | 80% | 1d | No |
| 2.1 | Audit Logging Infrastructure | 6 | 20% | 2-3d | No |
| 2.2 | Target Isolation Enforcement | 6 | 60% | 2d | No |
| 2.3 | Approval & User Consent Gates | 6 | 30% | 1.5d | No |
| 3.1 | Complete Testing Suite | 9 | 10% | 3-4d | No |
| 3.2 | Documentation & Examples | 7 | 5% | 2d | No |
| 3.3 | Advanced Analysis Features | 4 | 40% | 2-3d | No |
| 3.4 | Interactive Dashboard | 7 | 50% | 2-3d | No |

---

## Recommended Execution Path (Next 2 Weeks)

### Week 1 (Priority 1 — Unblock MVP)
1. 1.1 Proxy persistence + request ID tracking
2. 1.2 Tool standardization + approval flow skeleton
3. 1.3 Session ↔ Agent integration
4. 1.4 Workspace validation wrappers
5. Buffer for integration issues

Goal: End-to-end MVP flow works: create target → run agent → get findings → optionally modify workspace → generate report.

### Week 2 (Priority 2 — Safety)
1. 2.1 Audit logging
2. 2.2 Target scope enforcement
3. 2.3 Approval workflow UI
4. Buffer

Goal: The system is production-safe with an audit trail and approval gates.

### After (Priority 3 — Polish)
- Testing suite
- Documentation
- Advanced analysis
- Dashboard enhancements

---

## Final Recommendation

The project has already built a strong foundation: the architecture, module structure, target/workspace model, proxy layer, and AI tool registry are all in place. The next milestone is not new architecture — it is closing the loop between proxy data, persistent sessions, tool execution, validation, and approval.

If that loop is closed correctly, SQLX becomes a credible MVP. The project can then mature through auditing, reporting, and testing.
