## SQLX — Complete Architecture

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
│   ├── agent/                      # 🧠 AI AGENT
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
│   │   ├── prompts/
│   │   │   ├── system.md
│   │   │   ├── planner.md
│   │   │   └── analyst.md
│   │   ├── analyzer.py
│   │   └── context.py
│   │
│   ├── sqlmap/                     # SQLMAP BRIDGE
│   │   ├── runner.py
│   │   ├── adapter.py
│   │   ├── parser.py
│   │   ├── options.py
│   │   └── monitor.py
│   │
│   ├── proxy/                      # 🔀 SHARED PROXY
│   │   ├── server.py
│   │   ├── interceptor.py
│   │   ├── request.py
│   │   ├── response.py
│   │   ├── transformer.py
│   │   ├── replay.py
│   │   ├── history.py
│   │   └── diff.py
│   │
│   ├── analysis/                   # 🔬 TRAFFIC ANALYSIS
│   │   ├── http.py
│   │   ├── response.py
│   │   ├── timing.py
│   │   ├── fingerprint.py
│   │   └── correlation.py
│   │
│   ├── workspace/                  # 🎯 TARGET WORKSPACES
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
│   │   │
│   │   ├── sqlmap/
│   │   │   └── ...                 # Target-specific working copy
│   │   │
│   │   ├── backups/
│   │   │   ├── snapshot_001/
│   │   │   └── snapshot_002/
│   │   │
│   │   ├── patches/
│   │   │   ├── patch_001.diff
│   │   │   └── patch_002.diff
│   │   │
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

## 🧠 Core architecture

```text
                         ┌───────────────────┐
                         │       USER        │
                         │ CLI / Dashboard   │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │    SQLX AGENT 🧠  │
                         │                   │
                         │ Observe           │
                         │ Analyze           │
                         │ Plan              │
                         │ Ask               │
                         │ Execute           │
                         └─────────┬─────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
             ▼                     ▼                     ▼
      ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
      │   SQLMap    │       │    Proxy    │       │  Workspace  │
      │   Adapter   │       │    Layer    │       │   Manager   │
      └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
             │                     │                     │
             ▼                     ▼                     ▼
      Original SQLMap        HTTP Traffic        Target-specific
                                                   SQLMap copy
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   ▼
                            ┌──────────────┐
                            │ Event Bus    │
                            └──────┬───────┘
                                   ▼
                            AI Re-analysis
```

## 🔀 Shared Proxy

Proxy **User aur AI dono ke liye same interface** expose karega:

```text
                         PROXY
                           │
             ┌─────────────┴─────────────┐
             │                           │
           USER                         AI
             │                           │
       ┌─────▼─────┐               ┌─────▼─────┐
       │ Inspect   │               │ Observe   │
       │ Edit      │               │ Analyze   │
       │ Replay    │               │ Propose   │
       │ History   │               │ Correlate │
       └───────────┘               └───────────┘
```

Every action audit log mein:

```text
timestamp
actor: user | ai | system
request_id
action
before
after
result
```

## 🎯 Target isolation

Ye architecture ka important part hai.

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
     AI changes                   AI changes
          │                             │
      Backup + Git                 Backup + Git
```

**Target A ke modifications Target B ko affect nahi karenge.**

Original SQLMap baseline bhi untouched rahega.

## 🔄 AI agent lifecycle

```text
USER TASK
   │
   ▼
SCOPE CHECK
   │
   ▼
OBSERVE
   │
   ├── SQLMap output
   ├── Proxy traffic
   ├── Response data
   ├── Previous session
   └── Workspace state
   │
   ▼
ANALYZE
   │
   ▼
PLAN
   │
   ▼
USER APPROVAL ──────► if required
   │
   ▼
EXECUTE
   │
   ├── SQLMap operation
   ├── Proxy operation
   ├── Analysis
   └── Target workspace modification
   │
   ▼
TEST / VALIDATE
   │
   ▼
SAVE STATE
   │
   ▼
RE-OBSERVE
```

## 🛠️ Target-specific code modification

AI ko code modification capability milegi:

```text
AI identifies problem
        ↓
Read relevant SQLMap source
        ↓
Generate patch
        ↓
Show diff
        ↓
Create snapshot
        ↓
Apply patch
        ↓
Run tests
        ↓
Success ──────► commit
        │
        └──────► failure → rollback
```

History:

```text
Target A
│
├── baseline
├── change-001
├── change-002
├── change-003
└── current
```

So AI apne previous changes ko bhi understand kar sakta hai.

## 🧩 AI Tools

Agent ko giant unrestricted shell ke bajay structured tools dena clean architecture hoga:

```text
SQLMap
├── run
├── inspect_status
├── read_output
└── stop

Proxy
├── list_requests
├── inspect_request
├── inspect_response
├── compare
└── replay

Workspace
├── read_source
├── create_backup
├── generate_patch
├── apply_patch
├── diff
└── rollback

Session
├── save
├── load
└── history

Analysis
├── analyze_response
├── compare
└── correlate
```

Generated code ko **authorized target workspace** mein hi apply karna aur patch/test/rollback ko atomic rakhna architecture ko much safer aur recoverable banata hai.

### Final concept

```text
                  ┌─────────────────────────┐
                  │       SQLX 🧠            │
                  │ AI-powered SQLMap Agent │
                  └────────────┬────────────┘
                               │
       ┌───────────────────────┼───────────────────────┐
       ▼                       ▼                       ▼
  ORIGINAL SQLMAP         SHARED PROXY          TARGET WORKSPACE
       │                       │                       │
       │                  User + AI              Code Changes
       │                       │                 Backup / Patch
       │                       │                 Test / Rollback
       └───────────────────────┼───────────────────────┘
                               ▼
                         SESSION + EVENTS
                               │
                               ▼
                         AI REASONING LOOP
```


