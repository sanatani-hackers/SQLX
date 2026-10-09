"""
Async SQLMap runner - non-blocking subprocess execution with real-time progress.

This provides a practical middle ground:
- Non-blocking execution (doesn't block the agent)
- Real-time progress tracking
- Structured result parsing
- Uses subprocess (works reliably)
"""

import subprocess
import threading
import queue
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging

from sqlx.target import TargetProfile

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a discovered SQL injection."""
    url: str
    parameter: str
    parameter_type: str
    injection_type: str
    payload: str
    dbms: Optional[str] = None
    os: Optional[str] = None
    confidence: float = 0.0
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class AsyncSQLMapRunner:
    """Run SQLMap in background with real-time progress tracking."""

    def __init__(self, target: TargetProfile, session=None):
        self.target = target
        self.session = session
        self.process: Optional[subprocess.Popen] = None
        self._output_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._reader_thread: Optional[threading.Thread] = None
        self._complete_event = threading.Event()

        self._all_lines: List[str] = []
        self.findings: List[Finding] = []
        self.error: Optional[str] = None
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

        self.sqlmap_dir = (Path(target.workspace_dir) / "sqlmap").absolute()
        self.sqlmap_script = self.sqlmap_dir / "sqlmap.py"

    def start_async(self, url: str, args: Optional[List[str]] = None,
                   technique: str = 'BEUSTQ', timeout: int = 300):
        """Start SQLMap detection in background."""
        if self.is_running():
            raise RuntimeError("SQLMap is already running")

        if not self.sqlmap_script.exists():
            raise FileNotFoundError(f"sqlmap.py not found: {self.sqlmap_script}")

        self._stop_event.clear()
        self._complete_event.clear()
        self._all_lines.clear()
        self.findings.clear()
        self.error = None
        self._start_time = time.time()

        # Build command
        import sys
        cmd = [
            sys.executable,
            str(self.sqlmap_script),
            '--batch',
            '--url', url,
            '--technique', technique,
            '--timeout', str(timeout),
            '--threads', '4'
        ]

        if args:
            cmd.extend(args)

        # Start process
        self.process = subprocess.Popen(
            cmd,
            cwd=str(self.sqlmap_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Start output reader thread
        self._reader_thread = threading.Thread(
            target=self._read_and_parse_output,
            daemon=True
        )
        self._reader_thread.start()

        logger.info(f"Started async SQLMap: {url}")

    def _read_and_parse_output(self):
        """Read output and parse findings in real-time."""
        try:
            if not self.process or not self.process.stdout:
                return

            for line in iter(self.process.stdout.readline, ""):
                if self._stop_event.is_set():
                    break

                stripped = line.strip()
                self._all_lines.append(stripped)
                self._output_queue.put(stripped)

                # Parse findings from output
                self._parse_line_for_findings(stripped)

            self.process.stdout.close()
            self.process.wait()

        except Exception as e:
            logger.error(f"Output reader error: {e}")
            self.error = str(e)
        finally:
            self._end_time = time.time()
            self._complete_event.set()

    def _parse_line_for_findings(self, line: str):
        """Parse a line of output for injection findings."""
        # Pattern: "Parameter: id (GET)"
        param_match = re.search(r"Parameter:\s+(\S+)\s+\((\w+)\)", line)
        if param_match:
            self._current_param = param_match.group(1)
            self._current_param_type = param_match.group(2)

        # Pattern: "Type: boolean-based blind"
        type_match = re.search(r"Type:\s+(.+)", line)
        if type_match:
            self._current_injection_type = type_match.group(1).strip()

        # Pattern: "Title: ..."
        title_match = re.search(r"Title:\s+(.+)", line)
        if title_match:
            self._current_title = title_match.group(1).strip()

        # Pattern: "Payload: ..."
        payload_match = re.search(r"Payload:\s+(.+)", line)
        if payload_match and hasattr(self, '_current_param'):
            payload = payload_match.group(1).strip()

            # Create finding
            finding = Finding(
                url=self.target.target_url,
                parameter=getattr(self, '_current_param', 'unknown'),
                parameter_type=getattr(self, '_current_param_type', 'GET'),
                injection_type=getattr(self, '_current_injection_type', 'unknown'),
                payload=payload,
                dbms=self._extract_dbms_from_lines(),
                timestamp=datetime.utcnow()
            )

            self.findings.append(finding)
            logger.info(f"Found injection: {finding.parameter} ({finding.injection_type})")

            # Save to session if available
            if self.session:
                try:
                    self.session.add_finding({
                        'type': 'injection',
                        'url': finding.url,
                        'parameter': finding.parameter,
                        'technique': finding.injection_type,
                        'payload': finding.payload,
                        'dbms': finding.dbms
                    })
                except Exception as e:
                    logger.debug(f"Failed to save finding to session: {e}")

    def _extract_dbms_from_lines(self) -> Optional[str]:
        """Extract DBMS from recent output lines."""
        for line in reversed(self._all_lines[-20:]):
            dbms_match = re.search(r"back-end DBMS:\s+(\w+)", line, re.IGNORECASE)
            if dbms_match:
                return dbms_match.group(1)
        return None

    def get_findings(self) -> List[Finding]:
        """Get all findings discovered so far (non-blocking)."""
        return list(self.findings)

    def is_complete(self) -> bool:
        """Check if detection is complete."""
        return self._complete_event.is_set()

    def is_running(self) -> bool:
        """Check if process is still running."""
        return self.process is not None and self.process.poll() is None

    def wait_complete(self, timeout: Optional[int] = None) -> List[Finding]:
        """Block until detection completes."""
        self._complete_event.wait(timeout=timeout)
        return self.get_findings()

    def stop(self):
        """Stop the running detection."""
        logger.info("Stopping SQLMap detection")
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

    def progress(self) -> Dict[str, Any]:
        """Get detection progress."""
        elapsed = None
        if self._start_time:
            end = self._end_time if self._end_time else time.time()
            elapsed = end - self._start_time

        return {
            'findings_so_far': len(self.findings),
            'is_complete': self.is_complete(),
            'is_running': self.is_running(),
            'error': self.error,
            'elapsed_seconds': elapsed
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of detection results."""
        findings_by_type = {}
        for finding in self.findings:
            injection_type = finding.injection_type
            if injection_type not in findings_by_type:
                findings_by_type[injection_type] = []
            findings_by_type[injection_type].append(finding)

        return {
            'total_findings': len(self.findings),
            'by_type': {k: len(v) for k, v in findings_by_type.items()},
            'parameters_affected': list(set(f.parameter for f in self.findings)),
            'dbms_detected': list(set(f.dbms for f in self.findings if f.dbms)),
            'highest_confidence': max([f.confidence for f in self.findings], default=0),
            'completed': self.is_complete(),
            'error': self.error
        }

    def get_output_lines(self) -> List[str]:
        """Get all output lines."""
        return list(self._all_lines)
