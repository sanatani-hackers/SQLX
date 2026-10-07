"""
sqlx/sqlmap/runner.py
~~~~~~~~~~~~~~~~~~~~~
Runs sqlmap as a subprocess for a given target workspace.

Improvements over v1:
  * Configurable timeout (default 300 s) with hard kill on expiry
  * Stores all raw lines in self._all_lines for later inspection
  * run_and_collect() convenience method → {clean_output, summary, exit_code, raw_lines}
  * save_output_to_file() persists raw stdout to disk
  * Output is cleaned via SQLMapOutputCleaner before being surfaced to callers
"""
from __future__ import annotations

import subprocess
import threading
import queue
import time
from pathlib import Path
from typing import Dict, List, Optional

from sqlx.target import TargetProfile


class SQLMapRunner:
    def __init__(self, target: TargetProfile, timeout: int = 300):
        self.target = target
        self.timeout = timeout
        self.process: Optional[subprocess.Popen] = None
        self.output_queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._reader_thread: Optional[threading.Thread] = None
        self._all_lines: List[str] = []

        self.sqlmap_dir = (Path(target.workspace_dir) / "sqlmap").absolute()
        self.sqlmap_script = self.sqlmap_dir / "sqlmap.py"

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self, args: List[str]) -> None:
        """Start sqlmap asynchronously."""
        if self.is_running():
            raise RuntimeError("SQLMap is already running for this target.")
        if not self.sqlmap_script.exists():
            raise FileNotFoundError(
                f"sqlmap.py not found in target workspace: {self.sqlmap_script}"
            )

        self._stop_event.clear()
        self._all_lines.clear()

        import sys
        cmd = [sys.executable, str(self.sqlmap_script), "--batch"] + args

        self.process = subprocess.Popen(
            cmd,
            cwd=str(self.sqlmap_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

    def stop(self) -> None:
        """Terminate the running process."""
        self._stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self._reader_thread:
            self._reader_thread.join(timeout=2.0)
        self.process = None

    # ------------------------------------------------------------------
    # Wait / query
    # ------------------------------------------------------------------

    def wait(self) -> int:
        """Block until done or timeout. Returns exit code."""
        if not self.process:
            return -1
        try:
            self.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.stop()
            return -1
        except KeyboardInterrupt:
            self.stop()
            raise
        if self._reader_thread:
            self._reader_thread.join(timeout=5.0)
        return self.process.returncode if self.process else -1

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def get_output_lines(self, timeout: float = 0.1) -> List[str]:
        """Drain the output queue and return raw lines."""
        lines: List[str] = []
        try:
            while True:
                lines.append(self.output_queue.get(timeout=timeout))
        except queue.Empty:
            pass
        return lines

    # ------------------------------------------------------------------
    # Convenience: run and collect everything
    # ------------------------------------------------------------------

    def run_and_collect(self, args: List[str]) -> Dict:
        """
        Start sqlmap, wait for completion, return a result dict:
        {
            raw_lines:    List[str],
            clean_output: str,
            summary:      dict  (injection_found, dbms, waf_detected, …),
            exit_code:    int,
        }
        """
        self.start(args)
        exit_code = self.wait()
        # Drain anything still in queue after process exit
        self.get_output_lines()

        from sqlx.sqlmap.cleaner import SQLMapOutputCleaner
        cleaner = SQLMapOutputCleaner()
        findings = cleaner.to_findings(self._all_lines)
        return {
            "raw_lines":    list(self._all_lines),
            "clean_output": cleaner.clean(self._all_lines),
            "summary":      cleaner.summarize(self._all_lines),
            "findings":     findings,                        # List[Finding]
            "findings_dicts": [f.to_dict() for f in findings],  # JSON-serializable
            "exit_code":    exit_code,
        }

    def save_output_to_file(self, filepath: Path) -> None:
        """Write all raw output lines to *filepath* (creates parent dirs)."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text("\n".join(self._all_lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # Internal reader thread
    # ------------------------------------------------------------------

    def _read_output(self) -> None:
        if not self.process or not self.process.stdout:
            return
        for line in iter(self.process.stdout.readline, ""):
            if self._stop_event.is_set():
                break
            stripped = line.strip()
            self._all_lines.append(stripped)
            self.output_queue.put(stripped)
        self.process.stdout.close()
        self.process.wait()
