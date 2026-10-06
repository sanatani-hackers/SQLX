"""
sqlx/ui/dashboard.py
~~~~~~~~~~~~~~~~~~~~~
Interactive AI chat dashboard with full readline-style editing.

Uses prompt_toolkit for the input line so arrow keys, history (↑↓),
Ctrl-A/E/W, and all other terminal shortcuts work properly.
"""
from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from sqlx.target.manager import TargetManager
from sqlx.workspace.manager import WorkspaceManager
from sqlx.analysis.http import analyzer
from sqlx.agent.agent import SQLXAgent

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# prompt_toolkit session (arrow keys, history, Ctrl shortcuts)
# ─────────────────────────────────────────────────────────────────────────────

def _make_pt_session():
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import InMemoryHistory
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        return PromptSession(
            history=InMemoryHistory(),
            auto_suggest=AutoSuggestFromHistory(),
            mouse_support=False,
        )
    except ImportError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────

class InteractiveDashboard:
    def __init__(self, agent: SQLXAgent, active_target=None):
        self.agent = agent
        self.target_manager = TargetManager()
        self.active_target = active_target
        self._pt_session = _make_pt_session()

    # ── input ─────────────────────────────────────────────────────────────────

    def _read_input(self) -> str:
        """Read a line with full arrow-key / history support."""
        target_str = (
            f"\033[32m{self.active_target.name}\033[0m " if self.active_target else ""
        )
        prompt_str = f"\n{target_str}You> "

        if self._pt_session:
            from prompt_toolkit.formatted_text import ANSI
            return self._pt_session.prompt(ANSI(prompt_str))
        else:
            return input(prompt_str)

    # ── main loop ─────────────────────────────────────────────────────────────

    def run(self):
        console.clear()
        console.print(Panel(
            "[bold cyan]SQLX AI Dashboard[/bold cyan]\n"
            "Type [bold green]/help[/bold green] for commands or just chat with the AI.\n"
            "[dim]Arrow keys ↑↓ for history, Ctrl-A/E to jump, Ctrl-W to delete word.[/dim]",
            border_style="cyan",
        ))

        while True:
            try:
                user_input = self._read_input().strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Exiting dashboard.[/dim]")
                break

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                break
            try:
                if user_input.startswith("/"):
                    self._handle_command(user_input)
                else:
                    self._handle_chat(user_input)
            except KeyboardInterrupt:
                console.print("\n[red]Action cancelled by user (Ctrl-C).[/red]")

    # ── command router ─────────────────────────────────────────────────────────

    def _handle_command(self, cmd_str: str):
        parts = cmd_str.strip().split()
        cmd = parts[0].lower()

        dispatch = {
            "/help":        lambda: self._show_help(),
            "/targets":     lambda: self._show_targets(),
            "/target":      lambda: self._set_target(parts[1]) if len(parts) > 1
                                    else console.print("[red]Usage: /target <id_or_name>[/red]"),
            "/traffic":     lambda: self._show_traffic(int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10),
            "/diff":        lambda: self._show_diff(),
            "/history":     lambda: self._show_history(),
            "/session":     lambda: (self._new_session(" ".join(parts[2:]) or "General assessment")
                                    if len(parts) > 1 and parts[1] == "new"
                                    else self._show_session()),
            "/sessions":    lambda: self._list_sessions(),
            "/resume":      lambda: self._resume_session(parts[1] if len(parts) > 1 else None),
            "/report":      lambda: self._generate_report(parts[1] if len(parts) > 1 else "html"),
            "/fingerprint": lambda: self._fingerprint_last_traffic(),
            "/replay":      lambda: self._replay_request(int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None),
            "/compare":     lambda: self._compare_requests(
                                    int(parts[1]) if len(parts) > 1 else None,
                                    int(parts[2]) if len(parts) > 2 else None),
            "/snapshot":    lambda: self._snapshot(" ".join(parts[1:]) if len(parts) > 1 else "manual snapshot"),
            "/rollback":    lambda: self._rollback(parts[1] if len(parts) > 1 else None),
            "/tui":         lambda: self._launch_tui(),
        }

        handler = dispatch.get(cmd)
        if handler:
            handler()
        else:
            console.print(f"[red]Unknown command: {cmd}[/red] — type /help")

    # ── chat ──────────────────────────────────────────────────────────────────

    def _handle_chat(self, message: str):
        # Inject active-target context so agent always knows the target
        if self.active_target and self.agent.active_session is None:
            self.agent.memory.add_system_message(
                f"Active target: {self.active_target.name} | "
                f"URL: {self.active_target.target_url} | "
                f"ID: {self.active_target.id}"
            )
        with console.status("[bold cyan]Agent is thinking…[/bold cyan]", spinner="dots"):
            response = self.agent.ask(message)
        console.print(Panel(
            Markdown(response),
            title="[bold blue]AI Agent[/bold blue]",
            border_style="blue",
        ))

    # ── /help ──────────────────────────────────────────────────────────────────

    def _show_help(self):
        table = Table(title="Dashboard Commands", header_style="bold cyan", border_style="cyan")
        table.add_column("Command", style="bold white", no_wrap=True)
        table.add_column("Description", style="dim")
        rows = [
            ("/targets",                "List all targets"),
            ("/target <name>",          "Switch active target"),
            ("/session",                "Show active session details"),
            ("/session new <obj>",       "Start a new session with objective"),
            ("/sessions",               "List all sessions for active target"),
            ("/resume <session_id>",    "Resume a previous session"),
            ("/traffic [n]",            "View last n proxy transactions"),
            ("/fingerprint",            "WAF & tech fingerprint of recent traffic"),
            ("/replay [id]",            "Replay captured request (last if no ID)"),
            ("/compare <id1> <id2>",    "Diff two captured requests/responses"),
            ("/diff",                   "Uncommitted workspace changes"),
            ("/history",                "Workspace git commit history"),
            ("/snapshot [msg]",         "Create a workspace snapshot"),
            ("/rollback <hash>",        "Roll back workspace to a commit"),
            ("/report [html|json]",     "Generate audit report"),
            ("/tui",                    "Switch to TUI target manager"),
            ("exit / quit",             "Exit the dashboard"),
        ]
        for cmd, desc in rows:
            table.add_row(cmd, desc)
        console.print(table)

    # ── targets ────────────────────────────────────────────────────────────────

    def _show_targets(self):
        targets = self.target_manager.list_targets()
        if not targets:
            console.print("[yellow]No targets found.[/yellow]")
            return
        table = Table(title="Available Targets", border_style="cyan", header_style="bold white")
        table.add_column("ID",   style="yellow",     no_wrap=True)
        table.add_column("Name", style="bold white",  no_wrap=True)
        table.add_column("URL",  style="blue")
        for t in targets:
            active_marker = " ◀" if self.active_target and t.id == self.active_target.id else ""
            table.add_row(t.id[:8], t.name + active_marker, t.target_url)
        console.print(table)

    def _set_target(self, name: str):
        target = self.target_manager.load_target(name)
        if target:
            self.active_target = target
            console.print(f"[dark_green]✔  Active target set to:[/dark_green] [bold white]{target.name}[/bold white]")
        else:
            console.print(f"[red]Target '{name}' not found.[/red]")

    # ── sessions ───────────────────────────────────────────────────────────────

    def _new_session(self, objective: str):
        if not self.active_target:
            console.print("[yellow]Select a target first (/target <name>).[/yellow]")
            return
        from sqlx.session.manager import SessionManager
        sm = SessionManager()
        sess = sm.start_session(self.active_target.id, objective, self.active_target.workspace_dir)
        self.agent.set_session(sess)
        console.print(
            f"[dark_green]✔  Session started:[/dark_green] "
            f"[yellow]{sess.id[:8]}[/yellow]  [dim]{objective}[/dim]"
        )

    def _show_session(self):
        s = getattr(self.agent, "active_session", None)
        if not s:
            console.print("[yellow]No active session. Use /session new <objective>[/yellow]")
            return
        console.print(Panel(
            f"[bold]ID:[/bold]           {s.id}\n"
            f"[bold]Objective:[/bold]    {s.objective}\n"
            f"[bold]Status:[/bold]       {s.status}\n"
            f"[bold]Findings:[/bold]     {len(s.findings)}\n"
            f"[bold]Observations:[/bold] {len(s.observations)}\n"
            f"[bold]Revision:[/bold]     {s.workspace_revision or 'N/A'}",
            title="[bold cyan]Active Session[/bold cyan]",
            border_style="cyan",
        ))

    def _list_sessions(self):
        if not self.active_target:
            console.print("[yellow]Select a target first (/target <name>).[/yellow]")
            return
        from sqlx.session.persistence import SessionPersistence
        import json
        from pathlib import Path
        sessions_dir = Path(self.active_target.workspace_dir) / "sessions"
        if not sessions_dir.exists():
            console.print("[yellow]No sessions found for this target.[/yellow]")
            return
        table = Table(title=f"Sessions — {self.active_target.name}",
                      border_style="cyan", header_style="bold white")
        table.add_column("ID",        style="yellow",    no_wrap=True)
        table.add_column("Objective", style="bold white")
        table.add_column("Status",    style="dim")
        table.add_column("Findings",  style="dark_green", justify="right")
        for f in sorted(sessions_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                table.add_row(
                    data.get("id", "")[:8],
                    data.get("objective", ""),
                    data.get("status", ""),
                    str(len(data.get("findings", []))),
                )
            except Exception:
                continue
        console.print(table)

    def _resume_session(self, session_id: str | None):
        if not self.active_target or not session_id:
            console.print("[yellow]Usage: /resume <session_id>[/yellow]")
            return
        import json
        from pathlib import Path
        sessions_dir = Path(self.active_target.workspace_dir) / "sessions"
        matches = list(sessions_dir.glob(f"{session_id}*.json")) if sessions_dir.exists() else []
        if not matches:
            console.print(f"[red]Session '{session_id}' not found.[/red]")
            return
        from sqlx.session.state import Session
        data = json.loads(matches[0].read_text())
        sess = Session(**{k: v for k, v in data.items()
                          if k in Session.__dataclass_fields__})
        self.agent.set_session(sess)
        console.print(
            f"[dark_green]✔  Session resumed:[/dark_green] "
            f"[yellow]{sess.id[:8]}[/yellow]  [dim]{sess.objective}[/dim]"
        )

    # ── proxy traffic ──────────────────────────────────────────────────────────

    def _show_traffic(self, limit: int):
        recent = analyzer.get_recent(limit)
        if not recent:
            console.print("[yellow]No recent traffic captured. Is the proxy running?[/yellow]")
            return
        table = Table(
            title=f"Recent HTTP Traffic (last {limit})",
            border_style="cyan", header_style="bold white",
        )
        table.add_column("#",          style="dim",       no_wrap=True)
        table.add_column("Method",     style="cyan",      no_wrap=True)
        table.add_column("URL",        overflow="fold")
        table.add_column("Status",     justify="right")
        table.add_column("ms",         justify="right",   style="dim")
        table.add_column("Flags",      style="red")
        for i, txn in enumerate(recent):
            analysis = analyzer.analyze_txn(txn)
            status = str(analysis.get("status", "---"))
            color = "dark_green" if status.startswith("2") else "yellow" if status.startswith("3") else "red"
            flags = []
            if analysis.get("has_waf_headers"):   flags.append("WAF")
            if analysis.get("suspicious_status"): flags.append("SUSP")
            table.add_row(
                str(i),
                txn.request.get("method", ""),
                txn.request.get("url", "")[:80],
                f"[{color}]{status}[/{color}]",
                f"{txn.latency_ms:.0f}",
                ",".join(flags),
            )
        console.print(table)

    def _fingerprint_last_traffic(self):
        from sqlx import proxy_history
        from sqlx.analysis.fingerprint import WAFFingerprinter, TechFingerprinter
        records = proxy_history.get_recent(5)
        if not records:
            console.print("[yellow]No captured traffic to fingerprint.[/yellow]")
            return
        wf, tf = WAFFingerprinter(), TechFingerprinter()
        table = Table(title="WAF & Tech Fingerprint", border_style="cyan", header_style="bold white")
        table.add_column("URL",          overflow="fold")
        table.add_column("WAF",          style="red")
        table.add_column("Confidence",   justify="right")
        table.add_column("Technologies", style="blue")
        for rec in records:
            resp = {
                "status":    rec.get("status"),
                "headers":   rec.get("response_headers", {}),
                "body_text": rec.get("response_body", ""),
            }
            wr = wf.analyse(resp)
            tr = tf.analyse(resp)
            table.add_row(
                rec.get("url", "")[:50],
                wr["waf_name"] or "None",
                f"{wr['confidence']:.0%}" if wr["detected"] else "—",
                ", ".join(tr["technologies"]) or "Unknown",
            )
        console.print(table)

    def _replay_request(self, req_id: int | None):
        from sqlx import proxy_history
        from sqlx.proxy.replay import RequestReplayer
        records = proxy_history.get_all()
        if not records:
            console.print("[yellow]No captured requests to replay.[/yellow]")
            return
        rec = proxy_history.get_by_id(req_id) if req_id is not None else records[-1]
        if not rec:
            console.print(f"[red]Request ID {req_id} not found.[/red]")
            return
        req_dict = {
            "method":  rec["method"],
            "url":     rec["url"],
            "headers": rec.get("request_headers", {}),
            "body":    rec.get("request_body", ""),
        }
        with console.status(f"[bold cyan]Replaying {req_dict['method']} {req_dict['url'][:50]}…[/bold cyan]"):
            result = RequestReplayer().replay(req_dict)
        status = result.get("status", "?")
        color = "dark_green" if str(status).startswith("2") else "red"
        console.print(Panel(
            f"[bold]Status:[/bold]  [{color}]{status}[/{color}]\n"
            f"[bold]Latency:[/bold] {result.get('latency_ms', 0):.1f} ms\n"
            f"[bold]Body:[/bold]\n{str(result.get('body_text', ''))[:600]}",
            title="[bold dark_green]Replay Result[/bold dark_green]",
            border_style="dark_green",
        ))

    def _compare_requests(self, id1: int | None, id2: int | None):
        from sqlx import proxy_history
        records = proxy_history.get_all()
        if len(records) < 2:
            console.print("[yellow]Need at least 2 captured requests to compare.[/yellow]")
            return
        r1 = proxy_history.get_by_id(id1) if id1 is not None else records[-2]
        r2 = proxy_history.get_by_id(id2) if id2 is not None else records[-1]
        if not r1 or not r2:
            console.print("[red]Could not find one or both requests.[/red]")
            return
        import difflib
        body1 = str(r1.get("response_body", ""))
        body2 = str(r2.get("response_body", ""))
        diff = "\n".join(difflib.unified_diff(
            body1.splitlines(), body2.splitlines(),
            fromfile=f"Request {id1 if id1 is not None else 'last-1'}",
            tofile=f"Request {id2 if id2 is not None else 'last'}",
            lineterm="",
        ))
        if not diff:
            console.print("[dark_green]Response bodies are identical.[/dark_green]")
        else:
            console.print(Panel(diff[:3000], title="Response Diff", border_style="yellow"))

    # ── workspace ──────────────────────────────────────────────────────────────

    def _show_diff(self):
        if not self.active_target:
            console.print("[yellow]Select a target first (/target <name>).[/yellow]")
            return
        wm = WorkspaceManager(self.active_target.workspace_dir)
        diff = wm.get_diff()
        if diff:
            console.print(Panel(diff, title=f"[bold yellow]Uncommitted Changes — {self.active_target.name}[/bold yellow]", border_style="yellow"))
        else:
            console.print("[dark_green]Working tree is clean.[/dark_green]")

    def _show_history(self):
        if not self.active_target:
            console.print("[yellow]Select a target first (/target <name>).[/yellow]")
            return
        wm = WorkspaceManager(self.active_target.workspace_dir)
        history = wm.get_history()
        table = Table(title=f"Workspace History — {self.active_target.name}",
                      border_style="cyan", header_style="bold white")
        table.add_column("Hash",    style="yellow",     no_wrap=True)
        table.add_column("Date",    style="dim",         no_wrap=True)
        table.add_column("Message", style="dark_green")
        for c in history:
            table.add_row(c["hash"][:8], c["date"][:16], c["message"])
        console.print(table)

    def _snapshot(self, message: str):
        if not self.active_target:
            console.print("[yellow]Select a target first (/target <name>).[/yellow]")
            return
        wm = WorkspaceManager(self.active_target.workspace_dir)
        h = wm.create_snapshot(message)
        console.print(f"[dark_green]✔  Snapshot saved:[/dark_green] [yellow]{h[:8]}[/yellow]  [dim]{message}[/dim]")

    def _rollback(self, commit_hash: str | None):
        if not self.active_target or not commit_hash:
            console.print("[yellow]Usage: /rollback <hash>[/yellow]")
            return
        wm = WorkspaceManager(self.active_target.workspace_dir)
        try:
            wm.rollback(commit_hash)
            console.print(f"[dark_green]✔  Rolled back to {commit_hash}[/dark_green]")
        except Exception as exc:
            console.print(f"[red]Rollback failed: {exc}[/red]")

    # ── report ─────────────────────────────────────────────────────────────────

    def _generate_report(self, fmt: str):
        if not self.active_target:
            console.print("[yellow]Select a target first (/target <name>).[/yellow]")
            return
        from sqlx.reports.generator import ReportGenerator
        with console.status("[bold cyan]Generating report…[/bold cyan]"):
            gen = ReportGenerator(self.active_target.id)
            path = gen.export_json() if fmt == "json" else gen.export_html()
        console.print(f"[dark_green]✔  Report saved:[/dark_green] [blue]{path}[/blue]")

    # ── TUI shortcut ───────────────────────────────────────────────────────────

    def _launch_tui(self):
        from sqlx.ui.tui import launch_tui
        launch_tui()
