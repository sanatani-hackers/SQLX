# SQLX — AI-Powered SQLMap Agent

## 1. Project Vision

SQLX is an AI-powered orchestration layer built around the original SQLMap project.

SQLMap remains the core execution engine. SQLX adds an AI agent, shared proxy, request/response analysis, target-specific workspaces, persistent target-specific code modifications, session management, versioning, rollback, and reporting.

The project is intended for authorized security testing and controlled lab environments.

---

# 2. Core Concept

```text
                         ┌─────────────────────┐
                         │        USER         │
                         │   CLI / Dashboard   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    SQLX AI AGENT    │
                         │                     │
                         │ Observe → Analyze   │
                         │ Plan → Ask → Act    │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
       ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
       │   SQLMap    │       │ Shared Proxy │       │  Workspace  │
       │   Adapter   │       │    Layer     │       │   Manager   │
       └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
              │                     │                     │
              ▼                     ▼                     ▼
       Original SQLMap        HTTP Traffic        Target-specific
                                                    SQLMap copy
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    ▼
                             ┌──────────────┐
                             │   Event Bus  │
                             └──────┬───────┘
                                    ▼
                              AI Re-analysis
```

---

# 3. Repository Structure

```text
SQLX/
│
├── sqlmap/                         # ORIGINAL SQLMAP
│   ├── sqlmap.py
│   ├── lib/
│   ├── plugins/
│   ├── tamper/
│   └── ...
│
├── sqlx.py                         # Main entry point
│
├── sqlx/
│   │
│   ├── agent/                      # AI AGENT
│   │   ├── agent.py
│   │   ├── planner.py
│   │   ├── executor.py
│   │   ├── observer.py
│   │   ├── decision.py
│   │   ├── memory.py
│   │   └── tools.py
│   │
│   ├── ai/                         # LLM abstraction
│   │   ├── provider.py
│   │   ├── analyzer.py
│   │   ├── context.py
│   │   └── prompts/
│   │       ├── system.md
│   │       ├── planner.md
│   │       └── analyst.md
│   │
│   ├── sqlmap/                     # SQLMAP BRIDGE
│   │   ├── runner.py
│   │   ├── adapter.py
│   │   ├── parser.py
│   │   ├── options.py
│   │   └── monitor.py
│   │
│   ├── proxy/                      # SHARED PROXY
│   │   ├── server.py
│   │   ├── interceptor.py
│   │   ├── request.py
│   │   ├── response.py
│   │   ├── transformer.py
│   │   ├── replay.py
│   │   ├── history.py
│   │   └── diff.py
│   │
│   ├── analysis/                   # TRAFFIC ANALYSIS
│   │   ├── http.py
│   │   ├── response.py
│   │   ├── timing.py
│   │   ├── fingerprint.py
│   │   └── correlation.py
│   │
│   ├── workspace/                  # TARGET WORKSPACES
│   │   ├── manager.py
│   │   ├── snapshot.py
│   │   ├── backup.py
│   │   ├── patcher.py
│   │   ├── diff.py
│   │   └── rollback.py
│   │
│   ├── target/                     # TARGET MANAGEMENT
│   │   ├── manager.py
│   │   ├── scope.py
│   │   ├── profile.py
│   │   └── permissions.py
│   │
│   ├── extensions/                 # EXTENSION SYSTEM
│   │   ├── loader.py
│   │   ├── api.py
│   │   └── registry.py
│   │
│   ├── session/                    # SESSION MANAGEMENT
│   │   ├── manager.py
│   │   ├── state.py
│   │   └── persistence.py
│   │
│   ├── events/                     # INTERNAL EVENT BUS
│   │   ├── bus.py
│   │   ├── events.py
│   │   └── handlers.py
│   │
│   ├── storage/                    # DATABASE
│   │   ├── database.py
│   │   ├── models.py
│   │   └── migrations/
│   │
│   ├── reports/                    # REPORTING
│   │   ├── json.py
│   │   ├── html.py
│   │   └── formatter.py
│   │
│   └── ui/                         # USER INTERFACE
│       ├── terminal.py
│       ├── commands.py
│       ├── console.py
│       └── dashboard.py
│
├── targets/                        # TARGET DATA
│   │
│   ├── target_001/
│   │   ├── target.json
│   │   ├── sqlmap/
│   │   ├── backups/
│   │   ├── patches/
│   │   ├── sessions/
│   │   ├── traffic/
│   │   ├── findings/
│   │   ├── logs/
│   │   └── memory/
│   │
│   └── target_002/
│       └── ...
│
├── tests/
│   ├── agent/
│   ├── proxy/
│   ├── sqlmap/
│   ├── analysis/
│   └── workspace/
│
├── docs/
├── examples/
├── pyproject.toml
└── README.md
```

---

# 4. Original SQLMap Integration

The original SQLMap source is the foundation of SQLX.

SQLX should keep the upstream SQLMap code isolated from its own orchestration code.

```text
Original SQLMap
       │
       ▼
SQLX SQLMap Adapter
       │
       ▼
Agent / Session / Events
```

Responsibilities of the adapter:

* Start SQLMap
* Pass configuration
* Monitor execution
* Capture output
* Parse useful results
* Stop execution when requested
* Associate execution with a target/session

SQLX should not unnecessarily duplicate SQLMap functionality.

---

# 5. AI Agent

The AI agent is the central controller.

## Agent responsibilities

* Understand the user's objective
* Maintain current task state
* Observe SQLMap output
* Observe proxy traffic
* Analyze responses
* Decide which available tool is relevant
* Ask the user for decisions when required
* Track previous actions
* Coordinate workspace changes
* Explain findings
* Maintain session context

## Agent loop

```text
USER TASK
   ↓
SCOPE CHECK
   ↓
OBSERVE
   ↓
ANALYZE
   ↓
PLAN
   ↓
ASK USER WHEN REQUIRED
   ↓
EXECUTE
   ↓
VALIDATE
   ↓
SAVE STATE
   ↓
OBSERVE AGAIN
```

---

# 6. AI Tool Interface

The AI should operate through structured tools rather than having unrestricted access to the entire application.

```text
SQLMap
├── run
├── status
├── output
└── stop

Proxy
├── list_requests
├── inspect_request
├── inspect_response
├── compare
└── replay

Analysis
├── analyze_response
├── compare
└── correlate

Workspace
├── read_source
├── diff
├── create_backup
├── generate_patch
├── apply_patch
└── rollback

Session
├── save
├── load
└── history

Reports
└── generate
```

This makes agent actions traceable and testable.

---

# 7. Shared Proxy

The proxy is available to both the user and the AI.

```text
                         SHARED PROXY
                              │
                ┌─────────────┴─────────────┐
                │                           │
              USER                         AI
                │                           │
          Inspect/Edit                Observe/Analyze
          Replay                      Propose Changes
          History                     Correlate Results
```

The proxy should maintain request IDs.

Example:

```text
Request #142
├── timestamp
├── actor
├── original request
├── transformed request
├── response
├── timing
├── related session
└── analysis events
```

Every action should be recorded with an actor:

```text
actor = user
actor = ai
actor = system
```

---

# 8. Request / Response Analysis

The analysis layer converts raw HTTP traffic into structured observations.

Possible observations:

* Status-code changes
* Header changes
* Body differences
* Response-size changes
* Timing differences
* Repeated response patterns
* Correlation between request changes and responses

The AI receives structured observations along with relevant context.

---

# 9. Target Management

Each target receives an isolated workspace.

```text
                  ORIGINAL SQLMAP
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
      TARGET A                       TARGET B
          │                             │
          ▼                             ▼
   Working SQLMap                 Working SQLMap
          │                             │
      AI changes                    AI changes
          │                             │
   Backup + Revision             Backup + Revision
```

A change made for Target A must not silently affect Target B.

The original baseline remains protected.

---

# 10. Target-Specific Code Modification

One of SQLX's major features is the ability for the agent to modify the SQLMap working copy for a specific target/workspace.

## Modification pipeline

```text
AI identifies issue
       ↓
Read relevant source
       ↓
Generate patch
       ↓
Create snapshot
       ↓
Show diff
       ↓
Apply patch
       ↓
Run validation/tests
       ↓
PASS ───────────► Commit
       │
       └─────────► FAIL → Rollback
```

The modification belongs only to the target workspace.

Example:

```text
targets/
└── target_001/
    ├── sqlmap/
    ├── backups/
    ├── patches/
    └── history/
```

---

# 11. Versioning

Every persistent workspace change should receive a revision.

```text
baseline
   │
   ├── change-001
   │
   ├── change-002
   │
   └── change-003
          │
        current
```

Required operations:

```text
diff
history
snapshot
rollback
restore
```

Git can be used internally to provide reliable revision tracking.

---

# 12. Backup System

Before every persistent code modification:

```text
Current Workspace
       ↓
Create Snapshot
       ↓
Generate Patch
       ↓
Apply Patch
       ↓
Validate
```

Each snapshot should contain:

* Target ID
* Workspace revision
* Timestamp
* Changed files
* Patch
* Validation result
* Actor
* Reason for change

---

# 13. Event Bus

The Event Bus connects the major components without tightly coupling them.

Example events:

```text
TargetCreated
SessionStarted
ProxyRequestCaptured
ProxyResponseReceived
SQLMapStarted
SQLMapOutputReceived
AnalysisCompleted
AIPlanCreated
ApprovalRequested
PatchCreated
PatchApplied
ValidationPassed
ValidationFailed
RollbackCompleted
FindingCreated
```

Example:

```text
Proxy
  │
  └──► ProxyResponseReceived
              │
              ▼
         Event Bus
              │
       ┌──────┴──────┐
       ▼             ▼
    Analysis         AI
```

---

# 14. Session Management

A session should be resumable.

```text
Session
├── target
├── objective
├── SQLMap state
├── proxy history
├── observations
├── AI memory
├── workspace revision
├── findings
└── event history
```

Example conceptual command:

```text
sqlx session resume target_001
```

---

# 15. AI Memory

Memory should be separated into layers.

## Short-term memory

Current task and recent observations.

## Session memory

Information discovered during the current assessment.

## Workspace memory

Target-specific code modifications and their reasons.

## Project memory

Knowledge about SQLX itself rather than target-specific information.

Target data should not accidentally become global project memory.

---

# 16. User Interaction

SQLX should support both autonomous workflow and human decisions.

Example:

```text
SQLX > Target initialized.

AI > Analysis complete.

AI > I found an unusual response pattern.

AI > Proposed next action:
     [action summary]

Continue?
[y/N]
```

For code modifications:

```text
AI > A workspace modification is proposed.

Files: 2
Patch: 1
Validation: pending

[View Diff]
[Apply]
[Cancel]
```

---

# 17. Reporting

Reports should combine:

* Target/session information
* SQLMap findings
* Proxy observations
* Request/response analysis
* AI explanations
* Workspace changes
* Revision history
* Validation results
* Audit timeline

Output formats:

```text
JSON
HTML
Terminal
```

---

# 18. Extension System

SQLX should support extensions without modifying the core.

```text
extensions/
├── loader.py
├── api.py
└── registry.py
```

Potential extension categories:

```text
AI Providers
Analysis Modules
Proxy Modules
Reporters
Database Adapters
UI Components
```

---

# 19. Safety / Reliability Model

The architecture should enforce:

1. Explicit target scope.
2. Target isolation.
3. Audit logging.
4. Automatic backups before persistent changes.
5. Diff visibility.
6. Validation before committing changes.
7. Easy rollback.
8. No silent modification of the original SQLMap baseline.
9. Clear distinction between user and AI actions.
10. Testing primarily against authorized targets and controlled labs.

---

# 20. Development Roadmap

## Phase 1 — Foundation

* Integrate original SQLMap
* Create SQLX CLI
* Build SQLMap runner
* Capture process output
* Create target/session model

## Phase 2 — Workspace

* Per-target SQLMap workspace
* Snapshots
* Git/revision tracking
* Diff
* Patch application
* Rollback

## Phase 3 — Proxy

* Proxy server
* Request capture
* Response capture
* History
* Replay
* Request/response diff

## Phase 4 — Analysis

* HTTP parser
* Response analyzer
* Timing observations
* SQLMap/proxy correlation
* Structured events

## Phase 5 — AI

* LLM provider interface
* Agent state
* Tool calling
* Planner
* Observer
* Analyzer
* Decision loop

## Phase 6 — AI Code Modification

* Source inspection
* Patch generation
* Automatic backup
* Validation
* Commit/rollback
* Target-specific modification history

## Phase 7 — UI

* Interactive terminal
* Proxy traffic viewer
* AI conversation view
* Diff viewer
* Session manager

## Phase 8 — Reporting

* JSON reports
* HTML reports
* Complete audit timeline

## Phase 9 — Testing

* Unit tests
* Integration tests
* Proxy tests
* SQLMap adapter tests
* Workspace rollback tests
* Agent/tool tests
* Controlled lab testing

---

# 21. MVP

The first usable SQLX version should contain:

```text
Original SQLMap
      +
SQLMap Runner
      +
Target Workspace
      +
Shared Proxy
      +
Request/Response Analysis
      +
AI Tool Interface
      +
Interactive Agent
```

Advanced features can then be added incrementally.

---

# 22. Final Architecture

```text
                       ┌──────────────────────┐
                       │       SQLX 🧠        │
                       │ AI SQLMap Platform   │
                       └──────────┬───────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          ▼                       ▼                       ▼
   ORIGINAL SQLMAP          SHARED PROXY              AI AGENT
          │                       │                       │
          │                 User + AI               Planner
          │                 traffic view            Analyzer
          │                 request tools            Executor
          │                       │                   Memory
          └───────────────────────┼───────────────────────┘
                                  │
                                  ▼
                         TARGET WORKSPACE
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
                 Backup         Patch         Revision
                    │             │             │
                    └─────────────┼─────────────┘
                                  ▼
                             Validation
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
                       Keep             Rollback
```

---

# 23. Design Principles

**SQLMap = Execution Core**

**Proxy = Traffic Workspace**

**Analysis = Observation Layer**

**AI Agent = Reasoning + Orchestration**

**Workspace = Target-Specific Evolution**

**Events = Communication Backbone**

**Session = Persistent Context**

**Versioning = Change History**

**User = Decision / Approval Layer**

The key architectural rule is:

> SQLX should extend and orchestrate the original SQLMap rather than becoming a separate replacement scanner.

This keeps the project modular, target-specific changes isolated, and the original SQLMap baseline recoverable at all times.
