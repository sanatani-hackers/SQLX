"""
sqlx/ui/terminal.py
~~~~~~~~~~~~~~~~~~~
Terminal utilities for interactive CLI feedback — spinners, log tailing, and banners.
"""
from __future__ import annotations
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()

_BANNER = r"""
  ██████  ██████  ██      ██   ██
 ██      ██    ██ ██       ██ ██ 
 ███████ ██    ██ ██        ███  
      ██ ██ ▄▄ ██ ██       ██ ██ 
 ██████  ██████  ███████ ██   ██ 
            ▀▀                   
"""


def print_banner() -> None:
    """Print the SQLX ASCII art banner."""
    console.print(Panel(
        _BANNER.strip("\n"),
        title="[bold cyan]SQLX - AI-Powered SQLi Tester[/bold cyan]",
        subtitle="[dim]Authorized targets only[/dim]",
        border_style="blue",
    ))


class TerminalSpinner:
    """A simple thread-based CLI spinner."""

    def __init__(self, message: str = "Working"):
        self.message = message
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._frames = "|/-\\"

    def _spin(self) -> None:
        i = 0
        while not self._stop_event.is_set():
            sys.stdout.write(f"\r[{self._frames[i % 4]}] {self.message}...")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        # clear line
        sys.stdout.write("\r" + " " * (len(self.message) + 15) + "\r")
        sys.stdout.flush()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join()

    def __enter__(self) -> "TerminalSpinner":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()


class LogFollower:
    """Tails a log file continuously in the terminal."""

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self._stop_event = threading.Event()

    def follow(self) -> None:
        if not self.filepath.exists():
            console.print(f"[red]Log file not found: {self.filepath}[/red]")
            return

        with open(self.filepath, "r", encoding="utf-8") as f:
            f.seek(0, 2)  # Go to the end of the file
            try:
                while not self._stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    sys.stdout.write(line)
                    sys.stdout.flush()
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        console.print("\n[dim]Stopped following log.[/dim]")
