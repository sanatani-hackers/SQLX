import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

import sqlx  # triggers __init__ bootstrap

from sqlx.target import TargetManager

console = Console()

def cmd_target_list(args):
    manager = TargetManager()
    targets = manager.list_targets()
    
    if not targets:
        console.print("[yellow]No targets found. Use 'sqlx target create' to create one.[/yellow]")
        return

    table = Table(title="SQLX Targets")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("URL", style="blue")
    table.add_column("Workspace", style="magenta")

    for t in targets:
        # Show shortened ID for readability
        short_id = t.id.split("-")[0]
        table.add_row(short_id, t.name, t.target_url, t.workspace_dir)

    console.print(table)

def cmd_target_delete(args):
    manager = TargetManager()
    target = manager.load_target(args.target)
    if not target:
        console.print(f"[red]Target '{args.target}' not found.[/red]")
        sys.exit(1)

    if not args.force:
        console.print(f"[bold yellow]About to permanently delete target:[/bold yellow]")
        console.print(f"  Name:      [cyan]{target.name}[/cyan]")
        console.print(f"  URL:       {target.target_url}")
        console.print(f"  Workspace: {target.workspace_dir}")
        console.print(f"[red]This will delete the entire workspace including git history and reports.[/red]")
        confirm = input(f"Type the target name to confirm: ").strip()
        if confirm != target.name:
            console.print("[yellow]Deletion cancelled.[/yellow]")
            return

    deleted = manager.delete_target(args.target)
    if deleted:
        console.print(f"[green]✓ Target '{target.name}' and its workspace deleted successfully.[/green]")
    else:
        console.print(f"[red]Failed to delete target '{target.name}'.[/red]")
        sys.exit(1)

def cmd_target_create(args):
    manager = TargetManager()
    try:
        profile = manager.create_target(
            name=args.name,
            target_url=args.url,
            description=args.description
        )
        console.print(f"[green]Successfully created target '{profile.name}'[/green]")
        console.print(f"Workspace: [magenta]{profile.workspace_dir}[/magenta]")
    except Exception as e:
        console.print(f"[red]Error creating target: {e}[/red]")
        sys.exit(1)

import time
from sqlx.sqlmap import SQLMapRunner

def cmd_target_run(args):
    manager = TargetManager()
    target = manager.load_target(args.target)
    if not target:
        console.print(f"[red]Target '{args.target}' not found.[/red]")
        sys.exit(1)
        
    runner = SQLMapRunner(target)
    sqlmap_args = args.sqlmap_args
    if sqlmap_args and sqlmap_args[0] == "--":
        sqlmap_args = sqlmap_args[1:]
        
    # By default append target url
    if "-u" not in sqlmap_args and "--url" not in sqlmap_args:
        sqlmap_args.extend(["-u", target.target_url])
        
    console.print(f"[cyan]Running SQLMap for target {target.name}...[/cyan]")
    console.print(f"Command args: {' '.join(sqlmap_args)}")
    
    try:
        runner.start(sqlmap_args)
        console.print("[yellow]Runner started...[/yellow]")
        while runner.is_running():
            lines = runner.get_output_lines()
            for line in lines:
                print(line)
            time.sleep(0.1)
            
        runner.wait()
        # Get remaining lines
        for line in runner.get_output_lines():
            print(line)
            
        console.print("[green]SQLMap execution completed.[/green]")
    except Exception as e:
        console.print(f"[red]Error running SQLMap: {e}[/red]")
        sys.exit(1)
    finally:
        runner.stop()

from sqlx.workspace.manager import WorkspaceManager, WorkspaceError

def cmd_target_snapshot(args):
    manager = TargetManager()
    target = manager.load_target(args.target)
    if not target:
        console.print(f"[red]Target '{args.target}' not found.[/red]")
        sys.exit(1)
        
    wm = WorkspaceManager(target.workspace_dir)
    try:
        commit_hash = wm.create_snapshot(args.message)
        console.print(f"[green]Snapshot created successfully![/green] Commit: {commit_hash[:8]}")
    except WorkspaceError as e:
        console.print(f"[red]Failed to create snapshot: {e}[/red]")

def cmd_target_history(args):
    manager = TargetManager()
    target = manager.load_target(args.target)
    if not target:
        console.print(f"[red]Target '{args.target}' not found.[/red]")
        sys.exit(1)
        
    wm = WorkspaceManager(target.workspace_dir)
    try:
        history = wm.get_history()
        table = Table(title=f"Workspace History: {target.name}")
        table.add_column("Hash", style="cyan")
        table.add_column("Date", style="blue")
        table.add_column("Author", style="magenta")
        table.add_column("Message", style="green")
        
        for commit in history:
            table.add_row(commit["hash"][:8], commit["date"], commit["author"], commit["message"])
            
        console.print(table)
    except WorkspaceError as e:
        console.print(f"[red]Failed to get history: {e}[/red]")

def cmd_target_diff(args):
    manager = TargetManager()
    target = manager.load_target(args.target)
    if not target:
        console.print(f"[red]Target '{args.target}' not found.[/red]")
        sys.exit(1)
        
    wm = WorkspaceManager(target.workspace_dir)
    try:
        diff = wm.get_diff()
        if diff:
            console.print(Panel(diff, title="Working Tree Changes", border_style="yellow"))
        else:
            console.print("[green]No changes in working tree.[/green]")
    except WorkspaceError as e:
        console.print(f"[red]Failed to get diff: {e}[/red]")

def cmd_target_rollback(args):
    manager = TargetManager()
    target = manager.load_target(args.target)
    if not target:
        console.print(f"[red]Target '{args.target}' not found.[/red]")
        sys.exit(1)
        
    wm = WorkspaceManager(target.workspace_dir)
    try:
        wm.rollback(args.commit)
        console.print(f"[green]Workspace successfully rolled back to {args.commit[:8]}[/green]")
    except WorkspaceError as e:
        console.print(f"[red]Failed to rollback: {e}[/red]")

def cmd_target_report(args):
    manager = TargetManager()
    target = manager.load_target(args.target)
    if not target:
        console.print(f"[red]Target '{args.target}' not found.[/red]")
        sys.exit(1)
        
    from sqlx.reports.generator import ReportGenerator
    generator = ReportGenerator(target.id)
    
    with console.status("[bold cyan]Generating reports...[/bold cyan]"):
        if args.format in ["json", "all"]:
            json_path = generator.export_json()
            console.print(f"[green]JSON Report generated:[/green] {json_path}")
            
        if args.format in ["html", "all"]:
            html_path = generator.export_html()
            console.print(f"[green]HTML Report generated:[/green] {html_path}")

def build_parser():
    parser = argparse.ArgumentParser(description="SQLX - AI-Powered SQLMap Agent")
    subparsers = parser.add_subparsers(dest="command", help="Command to run", required=True)

    # TARGET commands
    parser_target = subparsers.add_parser("target", help="Manage targets")
    target_subparsers = parser_target.add_subparsers(dest="target_cmd", required=True)
    
    # target list
    parser_list = target_subparsers.add_parser("list", help="List all targets")
    parser_list.set_defaults(func=cmd_target_list)

    # target delete
    parser_delete = target_subparsers.add_parser("delete", help="Delete a target and its workspace")
    parser_delete.add_argument("target", help="Target ID or Name")
    parser_delete.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    parser_delete.set_defaults(func=cmd_target_delete)
    
    # target create
    parser_create = target_subparsers.add_parser("create", help="Create a new target")
    parser_create.add_argument("name", help="Name of the target")
    parser_create.add_argument("url", help="Target URL")
    parser_create.add_argument("-d", "--description", default="", help="Description of the target")
    parser_create.set_defaults(func=cmd_target_create)
    
    # target run
    parser_run = target_subparsers.add_parser("run", help="Run SQLMap for a target")
    parser_run.add_argument("target", help="Target ID or Name")
    parser_run.add_argument("sqlmap_args", nargs=argparse.REMAINDER, help="Arguments to pass to SQLMap")
    parser_run.set_defaults(func=cmd_target_run)

    # target snapshot
    parser_snapshot = target_subparsers.add_parser("snapshot", help="Create a workspace snapshot")
    parser_snapshot.add_argument("target", help="Target ID or Name")
    parser_snapshot.add_argument("-m", "--message", required=True, help="Snapshot message")
    parser_snapshot.set_defaults(func=cmd_target_snapshot)
    
    # target history
    parser_history = target_subparsers.add_parser("history", help="View workspace history")
    parser_history.add_argument("target", help="Target ID or Name")
    parser_history.set_defaults(func=cmd_target_history)
    
    # target diff
    parser_diff = target_subparsers.add_parser("diff", help="View workspace changes")
    parser_diff.add_argument("target", help="Target ID or Name")
    parser_diff.set_defaults(func=cmd_target_diff)
    
    # target rollback
    parser_rollback = target_subparsers.add_parser("rollback", help="Rollback workspace to a commit")
    parser_rollback.add_argument("target", help="Target ID or Name")
    parser_rollback.add_argument("commit", help="Commit hash")
    parser_rollback.set_defaults(func=cmd_target_rollback)

    # target report
    parser_report = target_subparsers.add_parser("report", help="Generate HTML/JSON audit report for target")
    parser_report.add_argument("target", help="Target ID or Name")
    parser_report.add_argument("--format", choices=["html", "json", "all"], default="all", help="Report format")
    parser_report.set_defaults(func=cmd_target_report)

    # Other commands
    parser_session = subparsers.add_parser("session", help="Manage sessions")
    session_sub = parser_session.add_subparsers(dest="session_cmd")
    session_sub.add_parser("list", help="List sessions for a target").add_argument("target")
    p_new = session_sub.add_parser("new", help="Start a new session")
    p_new.add_argument("target")
    p_new.add_argument("objective", nargs="?", default="General assessment")
    p_resume = session_sub.add_parser("resume", help="Resume a previous session")
    p_resume.add_argument("target")
    p_resume.add_argument("session_id")

    p_proxy = subparsers.add_parser("proxy", help="Start shared proxy")
    p_proxy.add_argument("--port", type=int, default=8081, help="Port to listen on (default: 8081)")
    p_proxy.add_argument("--intercept", action="store_true", help="Enable interactive user interception (pauses requests in editor)")

    # agent
    parser_agent = subparsers.add_parser("agent", help="Start AI agent dashboard")
    parser_agent.add_argument("--provider", default="gemini",
                              help="LLM Provider: gemini, groq, ollama, openai, openrouter, llmsrelay, dummy")
    parser_agent.add_argument("--model", default=None, help="Specific model override")
    parser_agent.add_argument("--target", default=None, help="Pre-select a target by name or ID")

    # tui
    subparsers.add_parser("tui", help="Launch interactive TUI target manager")

    return parser

def _cmd_session(args):
    """Handle session subcommands."""
    import json
    from pathlib import Path
    from sqlx.target.manager import TargetManager

    cmd = getattr(args, "session_cmd", None)

    if cmd == "list":
        target = TargetManager().load_target(args.target)
        if not target:
            console.print(f"[red]Target '{args.target}' not found.[/red]")
            sys.exit(1)
        sessions_dir = Path(target.workspace_dir) / "sessions"
        if not sessions_dir.exists() or not list(sessions_dir.glob("*.json")):
            console.print(f"[yellow]No sessions found for '{target.name}'.[/yellow]")
            return
        table = Table(title=f"Sessions — {target.name}", border_style="cyan", header_style="bold white")
        table.add_column("ID",        style="yellow",     no_wrap=True)
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

    elif cmd == "new":
        target = TargetManager().load_target(args.target)
        if not target:
            console.print(f"[red]Target '{args.target}' not found.[/red]")
            sys.exit(1)
        from sqlx.session.manager import SessionManager
        sm = SessionManager()
        sess = sm.start_session(target.id, args.objective, target.workspace_dir)
        console.print(f"[dark_green]✔  Session started:[/dark_green] [yellow]{sess.id[:8]}[/yellow]  [dim]{args.objective}[/dim]")

    elif cmd == "resume":
        target = TargetManager().load_target(args.target)
        if not target:
            console.print(f"[red]Target '{args.target}' not found.[/red]")
            sys.exit(1)
        sessions_dir = Path(target.workspace_dir) / "sessions"
        matches = list(sessions_dir.glob(f"{args.session_id}*.json")) if sessions_dir.exists() else []
        if not matches:
            console.print(f"[red]Session '{args.session_id}' not found.[/red]")
            sys.exit(1)
        data = json.loads(matches[0].read_text())
        console.print(f"[dark_green]✔  Session found:[/dark_green] [yellow]{data.get('id','')[:8]}[/yellow]  [dim]{data.get('objective','')}[/dim]")
        console.print(f"   Status: {data.get('status','?')} | Findings: {len(data.get('findings',[]))}")
        console.print("[dim]Use ./sqlx.py agent --target <name> and then /resume <id> to continue in the AI dashboard.[/dim]")

    else:
        # No subcommand — show help
        console.print("[bold cyan]Session commands:[/bold cyan]")
        console.print("  ./sqlx.py session list   <target>                — list sessions")
        console.print("  ./sqlx.py session new    <target> [objective]    — start a session")
        console.print("  ./sqlx.py session resume <target> <session_id>   — show session info")

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "target":
        if hasattr(args, "func"):
            args.func(args)
        elif args.target_cmd == "list":
            cmd_target_list(args)
    elif args.command == "session":
        _cmd_session(args)
    elif args.command == "tui":
        from sqlx.ui.tui import launch_tui
        launch_tui()
    elif args.command == "proxy":
        port = getattr(args, "port", 8081)
        intercept = getattr(args, "intercept", False)
        
        mode = "[yellow]INTERCEPT MODE[/yellow]" if intercept else "listening"
        console.print(f"[cyan]Starting shared proxy on 127.0.0.1:{port}… ({mode}) (Ctrl-C to stop)[/cyan]")
        
        from sqlx.proxy import SharedProxyServer
        proxy = SharedProxyServer(port=port, interactive_intercept=intercept)
        proxy.set_request_callback(lambda req: console.print(f"  [cyan]→[/cyan] {req['method']} {req['url']}"))
        proxy.set_response_callback(lambda res: console.print(f"  [dark_green]←[/dark_green] HTTP {res['status']}"))
        try:
            proxy.start()
            if intercept:
                import queue
                from rich.prompt import Prompt
                from sqlx.proxy.server import ProxyHandler
                console.print("\n[dim]Waiting for HTTP traffic to intercept...[/dim]\n")
                
                while True:
                    try:
                        req_data, event, result_box = proxy.intercept_queue.get(timeout=0.5)
                        console.print(f"╭───────────────────────────────────────────────────╮")
                        console.print(f"│ [bold yellow]INTERCEPTED[/bold yellow] [green]{req_data['method']:<6}[/green] [cyan]{req_data['url'][:35]}[/cyan] │")
                        console.print(f"╰───────────────────────────────────────────────────╯")
                        
                        while True:
                            try:
                                choice = Prompt.ask(
                                    "[yellow][A][/yellow]ccept (forward), [yellow][D][/yellow]rop, or [yellow][E][/yellow]dit", 
                                    choices=["A", "a", "D", "d", "E", "e"], 
                                    default="A"
                                ).upper()
                                
                                if choice == "A":
                                    result_box["req_data"] = req_data
                                    console.print("[dim]Forwarded request.[/dim]\n")
                                    break
                                elif choice == "D":
                                    result_box["drop"] = True
                                    console.print("[red]Dropped request.[/red]\n")
                                    break
                                elif choice == "E":
                                    result_box["req_data"] = ProxyHandler.open_in_editor(req_data)
                                    console.print("[dim]Forwarded edited request.[/dim]\n")
                                    break
                            except (KeyboardInterrupt, EOFError):
                                result_box["drop"] = True
                                console.print("\n[red]Dropped request (interrupted).[/red]\n")
                                break
                                
                        event.set()
                        
                    except queue.Empty:
                        pass
            else:
                while True:
                    import time
                    time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping proxy…[/yellow]")
            proxy.stop()
    elif args.command == "agent":
        provider_name = args.provider
        console.print(f"[cyan]Starting AI Agent — provider:[/cyan] [bold white]{provider_name}[/bold white]")
        from sqlx.agent import SQLXAgent
        from sqlx.ai.provider import ProviderFactory
        from sqlx.ui.dashboard import InteractiveDashboard
        from sqlx.target.manager import TargetManager

        try:
            provider = ProviderFactory.create(provider_name, default_model=args.model)
        except Exception as e:
            console.print(f"[red]Provider error: {e}[/red]")
            sys.exit(1)

        agent = SQLXAgent(provider=provider)

        active_target = None
        if getattr(args, "target", None):
            active_target = TargetManager().load_target(args.target)
            if not active_target:
                console.print(f"[yellow]Warning: target '{args.target}' not found — starting without active target.[/yellow]")

        dashboard = InteractiveDashboard(agent, active_target=active_target)
        dashboard.run()
    else:
        parser.print_help()
        sys.exit(1)

