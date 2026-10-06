"""
sqlx/ui/commands.py
~~~~~~~~~~~~~~~~~~~
Reusable rich CLI output helpers used by console.py and dashboard.py.
"""
from __future__ import annotations
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

_SEVERITY_COLOURS = {
    "critical": "red",
    "high":     "orange1",
    "medium":   "yellow",
    "low":      "dark_green",
    "info":     "cyan",
}


def print_target_table(targets) -> None:
    if not targets:
        console.print("[yellow]No targets found.[/yellow]")
        return
    table = Table(title="SQLX Targets", border_style="cyan", header_style="bold white")
    table.add_column("ID",   style="yellow",     no_wrap=True)
    table.add_column("Name", style="bold white",  no_wrap=True)
    table.add_column("URL",  style="blue")
    for t in targets:
        table.add_row(t.id[:8], t.name, t.target_url)
    console.print(table)


def print_finding(finding_text: str, severity: str = "info") -> None:
    colour = _SEVERITY_COLOURS.get(severity.lower(), "white")
    console.print(Panel(
        finding_text,
        title=f"[bold {colour}]Finding [{severity.upper()}][/bold {colour}]",
        border_style=colour,
    ))


def print_success(msg: str) -> None:
    console.print(f"[dark_green]✔[/dark_green]  {msg}")


def print_error(msg: str) -> None:
    console.print(f"[red]✘[/red]  {msg}")


def print_warn(msg: str) -> None:
    console.print(f"[yellow]![/yellow]  {msg}")


def print_info(msg: str) -> None:
    console.print(f"[cyan]ℹ[/cyan]  {msg}")


def confirm(prompt: str, default: bool = False) -> bool:
    """Interactive yes/no prompt. Returns True if user said yes."""
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        ans = input(prompt + suffix).strip().lower()
        return (ans in ("y", "yes")) if ans else default
    except (EOFError, KeyboardInterrupt):
        return False
