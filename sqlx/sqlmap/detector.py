"""Async SQLMap detection wrapper."""

import threading
import queue
from typing import List, Optional, Dict, Any
import logging
import time

from .async_runner import AsyncSQLMapRunner, Finding

logger = logging.getLogger(__name__)


class AsyncSQLInjectionDetector:
    """Run SQLMap detection in background thread using subprocess."""

    def __init__(self, target_profile, session=None):
        self.target_profile = target_profile
        self.session = session
        self.runner = AsyncSQLMapRunner(target_profile, session=session)

        self.findings: List[Finding] = []
        self.error: Optional[str] = None

    def start_async(self, url: str, params: Optional[Dict[str, str]] = None,
                   technique: str = 'BEUSTQ', timeout: int = 300):
        """Start detection in background."""
        args = []
        if params:
            args.extend(['--testParameter', ','.join(params.keys())])

        self.runner.start_async(url=url, args=args, technique=technique, timeout=timeout)
        logger.info(f"Started async detection for {url}")

    def get_findings(self) -> List[Finding]:
        """Get all findings discovered so far (non-blocking)."""
        self.findings = self.runner.get_findings()
        return self.findings

    def is_complete(self) -> bool:
        """Check if detection is complete."""
        return self.runner.is_complete()

    def wait_complete(self, timeout: Optional[int] = None) -> List[Finding]:
        """Block until detection completes, return all findings."""
        return self.runner.wait_complete(timeout=timeout)

    def stop(self):
        """Stop detection."""
        self.runner.stop()

    def progress(self) -> Dict[str, Any]:
        """Get detection progress."""
        return self.runner.progress()

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of detection results."""
        return self.runner.get_summary()

