# SQLX — AI-Powered SQLMap Agent

SQLX is an AI-powered orchestration layer built around the original SQLMap project.

SQLMap remains the core execution engine. SQLX adds an AI agent, shared proxy, request/response analysis, target-specific workspaces, persistent target-specific code modifications, session management, versioning, rollback, and reporting.

The project is intended for authorized security testing and controlled lab environments.

## Core Concept

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
```

See `project_plan.md` and `project_arch.md` for complete design details.
