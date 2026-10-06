"""
sqlx/ui/tui.py
~~~~~~~~~~~~~~
Professional interactive TUI for SQLX target management.

Built on questionary + prompt_toolkit for arrow-key navigation,
and rich for colour output.

Colour scheme
─────────────
  Cyan        headers, titles, borders
  Bold White  selected items, labels
  Grey/dim    secondary info, IDs, paths
  Red         delete / errors
  Blue        URLs
  Yellow      warnings, key hints
  Dark Green  success, active status
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Questionary style — maps to the colour scheme
# ─────────────────────────────────────────────────────────────────────────────
SQLX_STYLE = Style([
    # question text
    ("qmark",         "fg:#00d7ff bold"),       # cyan  ❯
    ("question",      "fg:#ffffff bold"),        # bold white question
    ("answer",        "fg:#00ff87 bold"),        # dark green chosen answer
    # select list
    ("pointer",       "fg:#00d7ff bold"),        # cyan arrow
    ("highlighted",   "fg:#ffffff bold"),        # bold white highlighted row
    ("selected",      "fg:#00ff87"),             # dark green once selected
    # normal rows
    ("text",          "fg:#a8a8a8"),             # grey normal rows
    # instruction / hint
    ("instruction",   "fg:#ffaf00 italic"),      # yellow hint
    # separator
    ("separator",     "fg:#005f87"),             # dark blue separator
    # input box
    ("input",         "fg:#ffffff"),
])


# ─────────────────────────────────────────────────────────────────────────────
# Rich helpers
# ─────────────────────────────────────────────────────────────────────────────

def _header(text: str) -> None:
    console.print(Panel(
        f"[bold cyan]{text}[/bold cyan]",
        border_style="cyan",
        expand=False,
    ))


def _success(msg: str) -> None:
    console.print(f"  [bold dark_green]✔[/bold dark_green]  {msg}")


def _error(msg: str) -> None:
    console.print(f"  [bold red]✘[/bold red]  {msg}")


def _warn(msg: str) -> None:
    console.print(f"  [bold yellow]![/bold yellow]  {msg}")


def _info(msg: str) -> None:
    console.print(f"  [dim]{msg}[/dim]")


def _separator() -> None:
    console.print("[dim cyan]" + "─" * 60 + "[/dim cyan]")


# ─────────────────────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_targets():
    from sqlx.target.manager import TargetManager
    return TargetManager().list_targets()


def _short_id(full_id: str) -> str:
    return full_id[:8] if full_id else "--------"


# ─────────────────────────────────────────────────────────────────────────────
# Target list display
# ─────────────────────────────────────────────────────────────────────────────

def _print_targets(targets) -> None:
    if not targets:
        _warn("No targets found. Press [n] New Target to create one.")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        border_style="cyan",
        header_style="bold white",
        show_lines=False,
        expand=False,
    )
    table.add_column("ID",        style="dim",          no_wrap=True, width=10)
    table.add_column("Name",      style="bold white",   no_wrap=True, width=16)
    table.add_column("URL",       style="blue",         no_wrap=False)
    table.add_column("Workspace", style="dim",          no_wrap=True)

    for t in targets:
        table.add_row(
            _short_id(t.id),
            t.name,
            t.target_url,
            t.workspace_dir,
        )
    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Target detail panel
# ─────────────────────────────────────────────────────────────────────────────

def _show_target_detail(target) -> None:
    _separator()
    console.print(f"  [bold cyan]Name      [/bold cyan] [bold white]{target.name}[/bold white]")
    console.print(f"  [bold cyan]ID        [/bold cyan] [yellow]{_short_id(target.id)}[/yellow]")
    console.print(f"  [bold cyan]URL       [/bold cyan] [blue]{target.target_url}[/blue]")
    console.print(f"  [bold cyan]Workspace [/bold cyan] [dim]{target.workspace_dir}[/dim]")
    desc = getattr(target, "description", "") or ""
    if desc:
        console.print(f"  [bold cyan]Desc      [/bold cyan] {desc}")

    # Git history snippet
    _separator()
    console.print("  [bold cyan]Recent Commits[/bold cyan]")
    try:
        from sqlx.workspace.manager import WorkspaceManager
        history = WorkspaceManager(target.workspace_dir).get_history()[:5]
        if history:
            for c in history:
                console.print(
                    f"    [yellow]{c['hash'][:8]}[/yellow]"
                    f"  [dim]{c['date'][:16]}[/dim]"
                    f"  [dark_green]{c['message'][:50]}[/dark_green]"
                )
        else:
            _info("(no commits yet)")
    except Exception:
        _info("(git history unavailable)")
    _separator()


# ─────────────────────────────────────────────────────────────────────────────
# Action handlers
# ─────────────────────────────────────────────────────────────────────────────

def _action_run(target) -> None:
    extra = questionary.text(
        "Extra sqlmap args:",
        default="--level=1 --risk=1",
        style=SQLX_STYLE,
    ).ask()
    if extra is None:
        return
    args_list = extra.split()

    console.print()
    console.print(Panel(
        f"[bold white]Running SQLMap on[/bold white] [blue]{target.target_url}[/blue]",
        border_style="yellow",
        title="[bold yellow]SQLX Runner[/bold yellow]",
    ))

    try:
        from sqlx.sqlmap.runner import SQLMapRunner
        runner = SQLMapRunner(target)
        result = runner.run_and_collect(["-u", target.target_url] + args_list)

        console.print()
        console.print(Panel(
            result["clean_output"] or "[dim](no output)[/dim]",
            border_style="cyan",
            title="[bold cyan]Output[/bold cyan]",
        ))

        s = result["summary"]
        if s["injection_found"]:
            _success(f"Injection found! DBMS: {s.get('dbms','?')} | WAF: {s.get('waf_detected','?')}")
            if s.get("payloads"):
                console.print(f"  [bold white]Payload:[/bold white] [yellow]{s['payloads'][0]}[/yellow]")
        elif s.get("waf_detected"):
            _warn("WAF detected — payloads may have been blocked")
        else:
            _info("No injection detected in this run")

        # Save log
        log_path = Path(target.workspace_dir) / "logs" / "sqlmap_last.txt"
        runner.save_output_to_file(log_path)
        _info(f"Raw log saved → {log_path}")

    except Exception as exc:
        _error(str(exc))


def _action_history(target) -> None:
    try:
        from sqlx.workspace.manager import WorkspaceManager
        history = WorkspaceManager(target.workspace_dir).get_history()
    except Exception as exc:
        _error(str(exc))
        return

    if not history:
        _warn("No commits in this workspace yet.")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        border_style="cyan",
        header_style="bold white",
        show_lines=False,
    )
    table.add_column("Hash",    style="yellow",     width=10)
    table.add_column("Date",    style="dim",        width=22)
    table.add_column("Author",  style="dim",        width=14)
    table.add_column("Message", style="dark_green")

    for c in history:
        table.add_row(c["hash"][:8], c["date"], c.get("author",""), c["message"])

    console.print(Panel(table, title=f"[bold cyan]History — {target.name}[/bold cyan]",
                        border_style="cyan"))


def _action_snapshot(target) -> None:
    msg = questionary.text(
        "Commit message:", default="manual snapshot", style=SQLX_STYLE
    ).ask()
    if not msg:
        return
    try:
        from sqlx.workspace.manager import WorkspaceManager
        h = WorkspaceManager(target.workspace_dir).create_snapshot(msg)
        _success(f"Snapshot saved  →  [{h[:8]}] {msg}")
    except Exception as exc:
        _error(str(exc))


def _action_diff(target) -> None:
    try:
        from sqlx.workspace.manager import WorkspaceManager
        diff = WorkspaceManager(target.workspace_dir)._run_git(["diff"])
        if diff.strip():
            console.print(Panel(diff, title="[bold cyan]Uncommitted Changes[/bold cyan]",
                                border_style="yellow"))
        else:
            _success("Working tree is clean — no uncommitted changes")
    except Exception as exc:
        _error(str(exc))


def _action_rollback(target) -> None:
    try:
        from sqlx.workspace.manager import WorkspaceManager
        history = WorkspaceManager(target.workspace_dir).get_history()
    except Exception as exc:
        _error(str(exc))
        return

    if not history:
        _warn("No commits to roll back to.")
        return

    choices = [f"{c['hash'][:8]}  {c['message'][:50]}" for c in history]
    picked = questionary.select(
        "Roll back to which commit?",
        choices=choices + ["Cancel"],
        style=SQLX_STYLE,
    ).ask()

    if not picked or picked == "Cancel":
        return

    commit_hash = picked.split()[0]
    confirmed = questionary.confirm(
        f"Roll back to {commit_hash}? This discards later changes.",
        default=False,
        style=SQLX_STYLE,
    ).ask()
    if confirmed:
        try:
            from sqlx.workspace.manager import WorkspaceManager
            WorkspaceManager(target.workspace_dir).rollback(commit_hash)
            _success(f"Rolled back to {commit_hash}")
        except Exception as exc:
            _error(str(exc))


def _action_report(target) -> None:
    fmt = questionary.select(
        "Report format:",
        choices=["HTML", "JSON", "Both", "Cancel"],
        style=SQLX_STYLE,
    ).ask()
    if not fmt or fmt == "Cancel":
        return
    try:
        from sqlx.reports.generator import ReportGenerator
        gen = ReportGenerator(target.id)
        if fmt in ("HTML", "Both"):
            p = gen.export_html()
            _success(f"HTML report → {p}")
        if fmt in ("JSON", "Both"):
            p = gen.export_json()
            _success(f"JSON report → {p}")
    except Exception as exc:
        _error(str(exc))


def _action_delete(target) -> None:
    console.print(f"\n  [bold red]⚠  About to permanently delete:[/bold red]")
    console.print(f"     Name:      [bold white]{target.name}[/bold white]")
    console.print(f"     URL:       [blue]{target.target_url}[/blue]")
    console.print(f"     Workspace: [dim]{target.workspace_dir}[/dim]")
    console.print(f"  [red]This removes the entire workspace, git history, sessions and reports.[/red]\n")

    confirm_name = questionary.text(
        f"Type the target name to confirm deletion:",
        style=SQLX_STYLE,
    ).ask()

    if confirm_name != target.name:
        _warn("Name did not match — deletion cancelled.")
        return

    try:
        from sqlx.target.manager import TargetManager
        TargetManager().delete_target(target.id)
        _success(f"Target '{target.name}' deleted.")
    except Exception as exc:
        _error(str(exc))


def _action_agent(target) -> None:
    provider = questionary.select(
        "AI Provider:",
        choices=["gemini", "ollama", "groq", "openai", "openrouter", "llmsrelay", "dummy"],
        style=SQLX_STYLE,
    ).ask()
    if not provider:
        return

    model = questionary.text(
        "Model (leave blank for default):",
        style=SQLX_STYLE,
    ).ask() or None

    console.print()
    _separator()
    console.print(f"  [bold cyan]Launching agent[/bold cyan] — provider=[yellow]{provider}[/yellow]"
                  + (f" model=[yellow]{model}[/yellow]" if model else ""))
    _separator()
    console.print()

    try:
        from sqlx.ui.dashboard import InteractiveDashboard
        from sqlx.ai.provider import ProviderFactory
        from sqlx.agent.agent import SQLXAgent

        kwargs = {}
        if model:
            kwargs["default_model"] = model

        prov = ProviderFactory.create(provider, **kwargs)
        agent = SQLXAgent(provider=prov)

        # Pre-set the active target context
        agent.memory.add_system_message(
            f"Active target: {target.name} | URL: {target.target_url} | ID: {target.id}"
        )

        dashboard = InteractiveDashboard(agent=agent, active_target=target)
        dashboard.run()
    except Exception as exc:
        _error(str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Target action menu
# ─────────────────────────────────────────────────────────────────────────────

_TARGET_ACTIONS = [
    ("🚀  Run SQLMap",          _action_run),
    ("📜  View History",        _action_history),
    ("📸  Take Snapshot",       _action_snapshot),
    ("🔍  Show Diff",           _action_diff),
    ("⏪  Rollback",            _action_rollback),
    ("🤖  Launch AI Agent",     _action_agent),
    ("📊  Generate Report",     _action_report),
    ("🗑   Delete Target",       _action_delete),
    ("↩   Back to list",        None),
]


def _target_menu(target) -> None:
    while True:
        console.print()
        _show_target_detail(target)
        console.print()

        choice = questionary.select(
            f"Actions for  {target.name}:",
            choices=[label for label, _ in _TARGET_ACTIONS],
            style=SQLX_STYLE,
            use_shortcuts=False,
            use_arrow_keys=True,
        ).ask()

        if choice is None or choice == "↩   Back to list":
            break

        for label, fn in _TARGET_ACTIONS:
            if label == choice and fn is not None:
                console.print()
                fn(target)
                break

        questionary.press_any_key_to_continue(style=SQLX_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
# New-target wizard
# ─────────────────────────────────────────────────────────────────────────────

def _create_target_wizard() -> None:
    console.print()
    _header("New Target")

    name = questionary.text(
        "Target name:", style=SQLX_STYLE,
        validate=lambda v: True if v.strip() else "Name cannot be empty",
    ).ask()
    if not name:
        return

    url = questionary.text(
        "Target URL:",
        default="https://",
        style=SQLX_STYLE,
        validate=lambda v: True if v.startswith("http") else "Must start with http:// or https://",
    ).ask()
    if not url:
        return

    desc = questionary.text(
        "Description (optional):",
        default="",
        style=SQLX_STYLE,
    ).ask() or ""

    try:
        from sqlx.target.manager import TargetManager
        TargetManager().create_target(name.strip(), url.strip(), description=desc.strip())
        _success(f"Target '{name}' created successfully!")
    except Exception as exc:
        _error(str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Main TUI loop
# ─────────────────────────────────────────────────────────────────────────────

def _main_menu_choices(targets) -> List[str]:
    choices = []
    if targets:
        for t in targets:
            url_short = t.target_url[:45] + "…" if len(t.target_url) > 45 else t.target_url
            choices.append(f"[{_short_id(t.id)}]  {t.name:<16}  {url_short}")
        choices.append(questionary.Separator("─" * 58))
    choices.append("➕  New Target")
    choices.append("🔄  Refresh")
    choices.append("❌  Quit")
    return choices


def launch_tui() -> None:
    """Entry point for the TUI."""
    console.clear()
    console.print(Panel(
        "[bold cyan]SQLX[/bold cyan]  [dim]—  AI-Powered Security Testing Agent[/dim]",
        border_style="cyan",
        expand=False,
        padding=(0, 4),
    ))
    console.print()

    while True:
        targets = _load_targets()

        _print_targets(targets)
        console.print()

        choices = _main_menu_choices(targets)

        choice = questionary.select(
            "Select a target or action:",
            choices=choices,
            style=SQLX_STYLE,
            use_shortcuts=False,
            use_arrow_keys=True,
        ).ask()

        if choice is None or choice == "❌  Quit":
            console.print("\n[dim]Bye.[/dim]\n")
            break

        elif choice == "➕  New Target":
            _create_target_wizard()

        elif choice == "🔄  Refresh":
            console.clear()
            console.print(Panel(
                "[bold cyan]SQLX[/bold cyan]  [dim]—  AI-Powered Security Testing Agent[/dim]",
                border_style="cyan",
                expand=False,
                padding=(0, 4),
            ))

        elif targets:
            # Match selected target by short ID
            short_id = choice.split("]")[0].lstrip("[").strip()
            target = next((t for t in targets if t.id.startswith(short_id)), None)
            if target:
                _target_menu(target)
                console.clear()
                console.print(Panel(
                    "[bold cyan]SQLX[/bold cyan]  [dim]—  AI-Powered Security Testing Agent[/dim]",
                    border_style="cyan",
                    expand=False,
                    padding=(0, 4),
                ))
