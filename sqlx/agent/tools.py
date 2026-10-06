import inspect
from typing import Callable, Dict, Any, List
from pydantic import BaseModel

class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, Callable] = {}
        self.schemas: List[Dict[str, Any]] = []
        
    def register(self, name: str, description: str, parameters: Dict[str, Any]):
        """Decorator to register a tool with its JSON schema."""
        def decorator(func: Callable):
            self.tools[name] = func
            self.schemas.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": parameters
                }
            })
            return func
        return decorator
        
    def execute(self, name: str, kwargs: Dict[str, Any]) -> str:
        if name not in self.tools:
            return f"Error: Tool '{name}' not found."
        try:
            result = self.tools[name](**kwargs)
            return str(result)
        except Exception as e:
            return f"Error executing tool '{name}': {str(e)}"

# Global registry for AI tools
registry = ToolRegistry()

# Example Tool: List Targets
@registry.register(
    name="list_targets",
    description="Lists all available targets and their IDs.",
    parameters={
        "type": "object",
        "properties": {},
        "required": []
    }
)
def list_targets() -> str:
    from sqlx.target.manager import TargetManager
    manager = TargetManager()
    targets = manager.list_targets()
    if not targets:
        return "No targets found."
    return "\n".join([f"ID: {t.id} | Name: {t.name} | URL: {t.target_url}" for t in targets])

@registry.register(
    name="run_sqlmap",
    description="Runs SQLMap against a specific target with given arguments. Note: If you want to route traffic through the internal proxy, always use --proxy=http://127.0.0.1:8081",
    parameters={
        "type": "object",
        "properties": {
            "target_id": {
                "type": "string",
                "description": "The ID or name of the target"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of arguments to pass to SQLMap (e.g., ['--dbs', '--batch'])"
            }
        },
        "required": ["target_id", "args"]
    }
)
def run_sqlmap(target_id: str, args: List[str]) -> str:
    from sqlx.target.manager import TargetManager
    from sqlx.sqlmap.runner import SQLMapRunner
    
    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."
    
    # Publish SQLMapStarted event
    try:
        from sqlx.events.bus import bus
        bus.publish('SQLMapStarted', {'target_id': target_id, 'args': args})
    except Exception:
        pass
    
    runner = SQLMapRunner(target)
    try:
        result = runner.run_and_collect(args)  # new method returns {clean_output, summary, exit_code}
        
        # Save raw output to target logs
        from pathlib import Path
        log_dir = Path(target.workspace_dir) / 'logs'
        log_dir.mkdir(exist_ok=True)
        runner.save_output_to_file(log_dir / 'sqlmap_last.txt')
        
        # Publish output event
        bus.publish('SQLMapOutputReceived', {'target_id': target_id, 'summary': result.get('summary', {})})
        
        # Return the CLEAN output, not raw
        clean = result.get('clean_output', '')
        summary = result.get('summary', {})
        
        # Build a compact LLM-friendly response
        parts = []
        if summary.get('injection_found'):
            parts.append(f"[INJECTION FOUND] Payloads: {summary.get('payloads', [])}")
        if summary.get('dbms'):
            parts.append(f"[DBMS] {summary['dbms']}")
        if summary.get('waf_detected'):
            parts.append(f"[WAF] Detected")
        if summary.get('errors'):
            parts.append(f"[ERRORS] {'; '.join(summary['errors'][:3])}")
        parts.append("--- Output ---")
        parts.append(clean[:2000] if len(clean) > 2000 else clean)
        
        return '\n'.join(parts)
    except Exception as e:
        return f"Error running SQLMap: {str(e)}"

@registry.register(
    name="read_workspace_file",
    description="Reads the content of a file within a target's workspace.",
    parameters={
        "type": "object",
        "properties": {
            "target_id": {"type": "string"},
            "filepath": {"type": "string", "description": "Relative path to the file inside the workspace (e.g. 'sqlmap/tamper/charencode.py')"}
        },
        "required": ["target_id", "filepath"]
    }
)
def read_workspace_file(target_id: str, filepath: str) -> str:
    from sqlx.target.manager import TargetManager
    from pathlib import Path
    
    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."
        
    full_path = Path(target.workspace_dir) / filepath
    # Security check to prevent path traversal outside workspace
    if not str(full_path.resolve()).startswith(str(Path(target.workspace_dir).resolve())):
        return "Error: Path traversal detected."
        
    if not full_path.exists() or not full_path.is_file():
        return f"File not found: {filepath}"
        
    try:
        return full_path.read_text(errors="replace")
    except Exception as e:
        return f"Error reading file: {e}"

@registry.register(
    name="write_workspace_file",
    description=(
        "Creates or overwrites a file inside a target's workspace with the given content. "
        "Use this to create NEW files (e.g. tamper scripts) instead of apply_workspace_patch. "
        "The file path must be relative to the workspace root (e.g. 'sqlmap/tamper/my_tamper.py'). "
        "Automatically commits the change with the provided message."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target_id": {"type": "string", "description": "Target ID or name"},
            "filepath": {"type": "string", "description": "Relative path inside workspace, e.g. 'sqlmap/tamper/custom_union.py'"},
            "content": {"type": "string", "description": "Full file content to write"},
            "message": {"type": "string", "description": "Commit message for this change"}
        },
        "required": ["target_id", "filepath", "content", "message"]
    }
)
def write_workspace_file(target_id: str, filepath: str, content: str, message: str) -> str:
    from sqlx.target.manager import TargetManager
    from sqlx.workspace.manager import WorkspaceManager
    from pathlib import Path

    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."

    workspace = Path(target.workspace_dir)
    full_path = (workspace / filepath).resolve()

    # Security: prevent path traversal
    if not str(full_path).startswith(str(workspace.resolve())):
        return "Error: Path traversal detected. filepath must be inside the workspace."

    # Create parent directories if needed
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(content, encoding="utf-8")

    # Commit via WorkspaceManager
    wm = WorkspaceManager(target.workspace_dir)
    try:
        commit_hash = wm.create_snapshot(message)
        return f"File written and committed successfully.\nPath: {filepath}\nCommit: {commit_hash[:8]}"
    except Exception as e:
        return f"File written to {filepath} but commit failed: {e}"

@registry.register(
    name="apply_workspace_patch",
    description=(
        "Applies a UNIFIED DIFF patch to modify EXISTING files in a target's workspace. "
        "The patch MUST use standard unified diff format starting with '--- a/filepath' and '+++ b/filepath'. "
        "For creating NEW files, use write_workspace_file instead. "
        "Automatically creates a git snapshot before applying."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target_id": {"type": "string"},
            "patch_content": {"type": "string", "description": "Standard unified diff patch (--- a/file / +++ b/file format only). Do NOT use *** Begin Patch format."},
            "message": {"type": "string", "description": "Commit message explaining the change."}
        },
        "required": ["target_id", "patch_content", "message"]
    }
)
def apply_workspace_patch(target_id: str, patch_content: str, message: str) -> str:
    from sqlx.target.manager import TargetManager
    from sqlx.workspace.manager import WorkspaceManager

    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."

    # Detect non-unified-diff formats and give a clear error
    if "*** Begin Patch" in patch_content or "*** Add File" in patch_content:
        return (
            "Error: Patch is in '*** Begin Patch' format which is NOT supported by git apply. "
            "To CREATE a new file, use the write_workspace_file tool instead. "
            "To MODIFY an existing file, use standard unified diff format: "
            "'--- a/filepath\\n+++ b/filepath\\n@@ -line,count +line,count @@\\n-old line\\n+new line'"
        )

    wm = WorkspaceManager(target.workspace_dir)

    # Auto-backup before patching
    try:
        wm.create_snapshot(f"Auto-backup before: {message}")
    except Exception as e:
        return f"Failed to create backup snapshot: {e}"

    success = wm.apply_patch(patch_content)
    if not success:
        return (
            "Failed to apply patch. Possible reasons:\n"
            "1. The diff is not in standard unified diff format (--- a/ / +++ b/)\n"
            "2. The patch context lines don't match the current file content\n"
            "3. The file being patched doesn't exist — use write_workspace_file to create new files\n"
            "Tip: Read the file with read_workspace_file first, then build the diff against its exact current content."
        )

    try:
        commit_hash = wm.create_snapshot(message)
        return f"Patch applied successfully. New commit: {commit_hash[:8]}"
    except Exception as e:
        return f"Patch applied but failed to commit: {e}"


@registry.register(
    name="rollback_workspace",
    description="Rolls back a target's workspace to a specific commit hash (or 'HEAD' to discard uncommitted changes).",
    parameters={
        "type": "object",
        "properties": {
            "target_id": {"type": "string"},
            "commit_hash": {"type": "string", "description": "The commit hash to rollback to, or 'HEAD' to revert to the last commit."}
        },
        "required": ["target_id", "commit_hash"]
    }
)
def rollback_workspace(target_id: str, commit_hash: str) -> str:
    from sqlx.target.manager import TargetManager
    from sqlx.workspace.manager import WorkspaceManager
    
    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."
        
    wm = WorkspaceManager(target.workspace_dir)
    try:
        wm.rollback(commit_hash)
        return f"Successfully rolled back workspace to {commit_hash}"
    except Exception as e:
        return f"Failed to rollback: {e}"

@registry.register(
    name="list_workspace_files",
    description="Lists files in a target's workspace directory.",
    parameters={
        "type": "object",
        "properties": {
            "target_id": {"type": "string"},
            "directory": {"type": "string", "description": "Relative directory path (default is root '')."}
        },
        "required": ["target_id"]
    }
)
def list_workspace_files(target_id: str, directory: str = "") -> str:
    from sqlx.target.manager import TargetManager
    from pathlib import Path
    
    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."
        
    full_path = Path(target.workspace_dir) / directory
    if not str(full_path.resolve()).startswith(str(Path(target.workspace_dir).resolve())):
        return "Error: Path traversal detected."
        
    if not full_path.exists() or not full_path.is_dir():
        return f"Directory not found: {directory}"
        
    files = []
    for p in full_path.iterdir():
        # Exclude .git and pycache
        if p.name in (".git", "__pycache__"):
            continue
        files.append(f"{p.name}/" if p.is_dir() else p.name)
        
    return "\n".join(sorted(files))

@registry.register(
    name="analyze_recent_traffic",
    description="Gets the analysis of recent HTTP traffic passing through the shared proxy (e.g., to detect WAFs or blocked requests).",
    parameters={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "Number of recent transactions to analyze."}
        },
        "required": []
    }
)
def analyze_recent_traffic(limit: int = 10) -> str:
    from sqlx.analysis.http import analyzer
    recent = analyzer.get_recent(limit)
    if not recent:
        return "No recent traffic captured."
        
    results = []
    for txn in recent:
        analysis = analyzer.analyze_txn(txn)
        method = txn.request.get("method")
        url = txn.request.get("url")
        status = analysis.get("status")
        
        info = f"{method} {url} -> HTTP {status}"
        if analysis.get("has_waf_headers"):
            info += " [WARNING: WAF Headers Detected]"
        if analysis.get("suspicious_status"):
            info += " [WARNING: Suspicious Status Code]"
            
        results.append(info)
        
    return "\n".join(results)

# ---------------------------------------------------------------------------
# Tool: get_workspace_history
# ---------------------------------------------------------------------------

@registry.register(
    name="get_workspace_history",
    description=(
        "Returns the git commit history for a target's workspace as formatted text, "
        "useful for reviewing what changes have been made to SQLMap files."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target_id": {
                "type": "string",
                "description": "The ID or name of the target whose workspace history to retrieve."
            }
        },
        "required": ["target_id"]
    }
)
def get_workspace_history(target_id: str) -> str:
    """Return the git commit log for a target workspace as a human-readable string.

    Each entry is formatted as::

        [<short-hash>] <date> — <author>: <message>

    Parameters
    ----------
    target_id:
        ID or name of the target.

    Returns
    -------
    str
        Formatted commit history, or an error/empty message.
    """
    from sqlx.target.manager import TargetManager
    from sqlx.workspace.manager import WorkspaceManager

    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."

    try:
        wm = WorkspaceManager(target.workspace_dir)
        history = wm.get_history()
    except Exception as exc:
        return f"Error retrieving workspace history: {exc}"

    if not history:
        return "No commits found in workspace history."

    lines = []
    for commit in history:
        short_hash = commit.get("hash", "")[:8]
        date = commit.get("date", "")
        author = commit.get("author", "")
        message = commit.get("message", "")
        lines.append(f"[{short_hash}] {date} — {author}: {message}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: save_session_finding
# ---------------------------------------------------------------------------

@registry.register(
    name="save_session_finding",
    description=(
        "Saves a structured finding (free-text) associated with a specific target "
        "and session.  The finding is persisted inside the target's findings directory "
        "and returned as confirmation."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target_id": {
                "type": "string",
                "description": "The ID or name of the target."
            },
            "session_id": {
                "type": "string",
                "description": "An identifier for the current agent session."
            },
            "finding": {
                "type": "string",
                "description": "The finding text to persist (e.g. injection details, payloads found)."
            }
        },
        "required": ["target_id", "session_id", "finding"]
    }
)
def save_session_finding(target_id: str, session_id: str, finding: str) -> str:
    """Persist a finding to the target's ``findings/`` directory.

    If a ``SessionManager`` is available it is used; otherwise the tool
    falls back to a simple file write so it always succeeds.

    Parameters
    ----------
    target_id:
        ID or name of the target.
    session_id:
        Identifier for the current session.
    finding:
        Free-text finding to save.

    Returns
    -------
    str
        Confirmation message including the saved file path.
    """
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    from sqlx.target.manager import TargetManager

    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."

    # Attempt to use SessionManager if it is implemented
    try:
        from sqlx.session.manager import SessionManager  # type: ignore[import]
        sm = SessionManager(target)
        sm.save_finding(session_id=session_id, finding=finding)
        return f"Finding saved via SessionManager for session '{session_id}'."
    except (ImportError, AttributeError, TypeError):
        pass  # Fall back to direct file write

    # Direct file-write fallback
    findings_dir = Path(target.workspace_dir) / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_session = "".join(c if c.isalnum() else "_" for c in session_id)
    filename = findings_dir / f"{safe_session}_{timestamp}.json"

    record = {
        "target_id": target_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "finding": finding,
    }
    filename.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return f"Finding saved to: {filename}"


# ---------------------------------------------------------------------------
# Tool: generate_report
# ---------------------------------------------------------------------------

@registry.register(
    name="generate_report",
    description=(
        "Generates a comprehensive audit report for the given target and returns "
        "the file path of the produced report.  Supported formats: 'html' (default) and 'json'."
    ),
    parameters={
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
def generate_report(target_id: str, format: str = "html") -> str:
    """Generate an audit report for a target and return its file path.

    Delegates to :class:`sqlx.reports.generator.ReportGenerator`.

    Parameters
    ----------
    target_id:
        ID or name of the target.
    format:
        ``'html'`` (default) or ``'json'``.

    Returns
    -------
    str
        Absolute path to the generated report file, or an error message.
    """
    from sqlx.reports.generator import ReportGenerator

    try:
        gen = ReportGenerator(target_id)
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error initialising report generator: {exc}"

    fmt = (format or "html").strip().lower()
    try:
        if fmt == "json":
            path = gen.export_json()
        else:
            path = gen.export_html()
        return f"Report generated successfully: {path}"
    except Exception as exc:
        return f"Error generating report: {exc}"


# ---------------------------------------------------------------------------
# Tool: edit_workspace_file
# ---------------------------------------------------------------------------

@registry.register(
    name='edit_workspace_file',
    description=(
        'Make targeted text replacements in an EXISTING workspace file. '
        'Replaces the first occurrence of old_text with new_text. '
        'Safer than apply_workspace_patch for simple single-location edits. '
        'Use read_workspace_file first to see the exact current content.'
    ),
    parameters={
        'type': 'object',
        'properties': {
            'target_id': {'type': 'string'},
            'filepath': {'type': 'string', 'description': 'Relative path inside workspace'},
            'old_text': {'type': 'string', 'description': 'Exact text to find and replace (must exist in file)'},
            'new_text': {'type': 'string', 'description': 'Replacement text'},
            'message': {'type': 'string', 'description': 'Commit message'}
        },
        'required': ['target_id', 'filepath', 'old_text', 'new_text', 'message']
    }
)
def edit_workspace_file(target_id: str, filepath: str, old_text: str, new_text: str, message: str) -> str:
    from sqlx.target.manager import TargetManager
    from sqlx.workspace.manager import WorkspaceManager
    from pathlib import Path
    
    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."
    
    workspace = Path(target.workspace_dir)
    full_path = (workspace / filepath).resolve()
    
    if not str(full_path).startswith(str(workspace.resolve())):
        return 'Error: Path traversal detected.'
    
    if not full_path.exists():
        return f'File not found: {filepath}. Use write_workspace_file to create it.'
    
    content = full_path.read_text(encoding='utf-8')
    if old_text not in content:
        return f'old_text not found in {filepath}. Use read_workspace_file to check exact content.'
    
    new_content = content.replace(old_text, new_text, 1)  # replace first occurrence only
    full_path.write_text(new_content, encoding='utf-8')
    
    wm = WorkspaceManager(target.workspace_dir)
    try:
        commit_hash = wm.create_snapshot(message)
        return f'File edited and committed. Path: {filepath}, Commit: {commit_hash[:8]}'
    except Exception as e:
        return f'File edited but commit failed: {e}'


# ---------------------------------------------------------------------------
# Tool: search_past_findings
# ---------------------------------------------------------------------------

@registry.register(
    name="search_past_findings",
    description=(
        "Search past findings and observations from all previous target sessions "
        "using semantic keyword search. Returns the most relevant snippets ranked "
        "by TF-IDF relevance score."
    ),
    parameters={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Natural-language search query describing what to look for "
                    "(e.g. 'blind SQL injection WAF bypass MySQL')."
                ),
            },
            "top_k": {
                "type": "integer",
                "description": "Maximum number of results to return (default: 5).",
            },
        },
        "required": ["query"],
    },
)
def search_past_findings(query: str, top_k: int = 5) -> str:
    """Search indexed past findings using TF-IDF keyword scoring.

    Queries the module-level :data:`sqlx.ai.rag._rag` singleton, triggering a
    full index of all target directories on the first call.

    Parameters
    ----------
    query:
        Natural-language search string.
    top_k:
        Maximum number of result chunks to return.

    Returns
    -------
    str
        Formatted results with target name, relevance score, and text snippet;
        or a message indicating no relevant findings were found.
    """
    from sqlx.ai.rag import _rag

    results = _rag.query(query, top_k=top_k)
    if not results:
        return "No relevant past findings found."

    lines: list = []
    for r in results:
        snippet = r["text"].replace("\n", " ").strip()
        lines.append(
            f"[{r['target_name']}] (score={r['score']:.2f}) {snippet[:300]}"
        )
    return "\n\n".join(lines)

# ---------------------------------------------------------------------------
# Tool: replay_request
# ---------------------------------------------------------------------------

@registry.register(
    name="replay_request",
    description=(
        "Replay a previously captured HTTP request from the proxy history and "
        "return the new response. Replays the last captured request if no "
        "request_id is given. Optionally override query/body params before replay."
    ),
    parameters={
        "type": "object",
        "properties": {
            "request_id": {
                "type": "integer",
                "description": "ID of the captured request to replay. Omit to replay the last one.",
            },
            "modify_params": {
                "type": "object",
                "description": "Optional dict of query/body params to override before replaying.",
            },
        },
        "required": [],
    },
)
def replay_request(request_id: int = None, modify_params: dict = None) -> str:
    """Replay a captured proxy request and return a response summary."""
    try:
        from sqlx import proxy_history
        from sqlx.proxy.replay import RequestReplayer
    except ImportError as exc:
        return f"Replay unavailable: {exc}"

    records = proxy_history.get_all()
    if not records:
        return "No captured requests in proxy history. Is the proxy running?"

    rec = proxy_history.get_by_id(request_id) if request_id is not None else records[-1]
    if not rec:
        return f"Request ID {request_id} not found in proxy history."

    req_dict = {
        "method":  rec.get("method", "GET"),
        "url":     rec.get("url", ""),
        "headers": rec.get("request_headers", {}),
        "body":    rec.get("request_body", ""),
    }

    if modify_params:
        import urllib.parse
        if req_dict["method"].upper() == "GET":
            parsed = urllib.parse.urlparse(req_dict["url"])
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params.update(modify_params)
            req_dict["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        else:
            try:
                body_params = dict(urllib.parse.parse_qsl(req_dict["body"]))
                body_params.update(modify_params)
                req_dict["body"] = urllib.parse.urlencode(body_params)
            except Exception:
                pass

    try:
        result = RequestReplayer().replay(req_dict)
    except Exception as exc:
        return f"Replay failed: {exc}"

    status = result.get("status", "?")
    latency = result.get("latency_ms", 0)
    body = str(result.get("body_text", ""))[:1000]
    return (
        f"Replay: {req_dict['method']} {req_dict['url']}\n"
        f"Status: {status}  Latency: {latency:.1f}ms\n"
        f"Body:\n{body}"
    )


# ---------------------------------------------------------------------------
# Tool: compare_requests
# ---------------------------------------------------------------------------

@registry.register(
    name="compare_requests",
    description=(
        "Diff two captured HTTP response bodies from the proxy history. "
        "Returns a unified diff — useful for detecting injection-caused differences."
    ),
    parameters={
        "type": "object",
        "properties": {
            "request_id_1": {"type": "integer", "description": "ID of the first (baseline) request."},
            "request_id_2": {"type": "integer", "description": "ID of the second request (defaults to last)."},
        },
        "required": ["request_id_1"],
    },
)
def compare_requests(request_id_1: int, request_id_2: int = None) -> str:
    """Unified diff of two captured proxy response bodies."""
    try:
        from sqlx import proxy_history
    except ImportError as exc:
        return f"Proxy history unavailable: {exc}"

    records = proxy_history.get_all()
    if len(records) < 2:
        return "Need at least 2 captured requests to compare."

    r1 = proxy_history.get_by_id(request_id_1)
    r2 = proxy_history.get_by_id(request_id_2) if request_id_2 is not None else records[-1]
    if not r1:
        return f"Request ID {request_id_1} not found."
    if not r2:
        return f"Request ID {request_id_2} not found."

    import difflib
    body1 = str(r1.get("response_body", "")).splitlines()
    body2 = str(r2.get("response_body", "")).splitlines()
    diff_lines = list(difflib.unified_diff(
        body1, body2,
        fromfile=f"Request #{request_id_1}",
        tofile=f"Request #{request_id_2 or 'last'}",
        lineterm="",
    ))
    if not diff_lines:
        return "Response bodies are identical — no differences found."

    added   = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    diff_text = "\n".join(diff_lines)
    return f"Added: {added} lines  Removed: {removed} lines\n\n" + diff_text[:3000]


# ---------------------------------------------------------------------------
# Tool: correlate_traffic
# ---------------------------------------------------------------------------

@registry.register(
    name="correlate_traffic",
    description=(
        "Correlate recent proxy traffic with injection patterns. Analyses status "
        "codes, timing anomalies, and body-length changes to identify parameters "
        "that triggered backend differences — strong indicators of injectability."
    ),
    parameters={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "Recent requests to analyse (default 20)."},
        },
        "required": [],
    },
)
def correlate_traffic(limit: int = 20) -> str:
    """Correlate proxy traffic for injection indicators."""
    try:
        from sqlx import proxy_history
        from sqlx.analysis.correlation import PayloadCorrelator
    except ImportError as exc:
        return f"Correlation unavailable: {exc}"

    records = proxy_history.get_recent(limit)
    if not records:
        return "No recent proxy traffic to correlate."

    try:
        findings = PayloadCorrelator().correlate(records)
    except Exception as exc:
        return f"Correlation error: {exc}"

    if not findings:
        return "No significant correlations found in recent traffic."

    lines = ["Correlation Results:", "─" * 40]
    for f in findings:
        lines.append(
            f"[{f.get('severity','INFO')}] {f.get('url','')} — "
            f"{f.get('observation','')} (confidence: {f.get('confidence',0):.0%})"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: fingerprint_target
# ---------------------------------------------------------------------------

@registry.register(
    name="fingerprint_target",
    description=(
        "Fingerprint the WAF/IPS and web technology stack by analysing recent "
        "proxy responses. Returns detected WAF name, confidence, and technologies."
    ),
    parameters={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "Recent responses to use (default 5)."},
        },
        "required": [],
    },
)
def fingerprint_target(limit: int = 5) -> str:
    """WAF + technology fingerprint from recent proxy responses."""
    try:
        from sqlx import proxy_history
        from sqlx.analysis.fingerprint import WAFFingerprinter, TechFingerprinter
    except ImportError as exc:
        return f"Fingerprint unavailable: {exc}"

    records = proxy_history.get_recent(limit)
    if not records:
        return "No recent proxy traffic. Run SQLMap through the proxy first."

    wf, tf = WAFFingerprinter(), TechFingerprinter()
    lines = []
    for rec in records:
        resp = {
            "status":    rec.get("status"),
            "headers":   rec.get("response_headers", {}),
            "body_text": rec.get("response_body", ""),
        }
        wr = wf.analyse(resp)
        tr = tf.analyse(resp)
        url = rec.get("url", "")[:60]
        waf_str = f"WAF: {wr['waf_name']} ({wr['confidence']:.0%})" if wr["detected"] else "No WAF detected"
        tech_str = ", ".join(tr["technologies"]) or "Unknown"
        lines.append(f"{url}\n  {waf_str} | Technologies: {tech_str}")
    return "\n\n".join(lines) if lines else "No results."


# ---------------------------------------------------------------------------
# Tool: list_sessions
# ---------------------------------------------------------------------------

@registry.register(
    name="list_sessions",
    description="List all saved sessions for a target with IDs, objectives, status, and finding counts.",
    parameters={
        "type": "object",
        "properties": {
            "target_id": {"type": "string", "description": "The ID or name of the target."},
        },
        "required": ["target_id"],
    },
)
def list_sessions(target_id: str) -> str:
    """Return all sessions for a target as formatted text."""
    import json
    from pathlib import Path
    from sqlx.target.manager import TargetManager

    target = TargetManager().load_target(target_id)
    if not target:
        return f"Target '{target_id}' not found."

    sessions_dir = Path(target.workspace_dir) / "sessions"
    if not sessions_dir.exists():
        return "No sessions found for this target."

    rows = []
    for f in sorted(sessions_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            rows.append(
                f"[{data.get('id','')[:8]}] "
                f"status={data.get('status','?')} "
                f"findings={len(data.get('findings',[]))} "
                f"— {data.get('objective','')}"
            )
        except Exception:
            continue
    return "\n".join(rows) if rows else "No sessions found."
