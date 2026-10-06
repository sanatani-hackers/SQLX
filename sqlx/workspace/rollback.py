"""
sqlx/workspace/rollback.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Rollback utilities — restore workspace to a previous git commit safely.
"""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import List

from sqlx.workspace.snapshot import Snapshot, SnapshotManager


class RollbackResult:
    def __init__(self, success: bool, message: str, new_head: str = None):
        self.success  = success
        self.message  = message
        self.new_head = new_head

    def __bool__(self) -> bool:
        return self.success

    def __str__(self) -> str:
        return self.message


class Rollback:
    """Rolls back a workspace to a previous commit."""

    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir).absolute()
        self.snap_mgr      = SnapshotManager(workspace_dir)

    def _git(self, args: list):
        r = subprocess.run(
            ["git"] + args, cwd=str(self.workspace_dir),
            capture_output=True, text=True,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def to_commit(self, commit_hash: str, hard: bool = True) -> RollbackResult:
        """Roll back to a specific commit (--hard by default)."""
        flag = "--hard" if hard else "--soft"
        code, _, err = self._git(["reset", flag, commit_hash])
        if code != 0:
            return RollbackResult(False, f"git reset failed: {err}")

        # Record the rollback as a new snapshot
        self.snap_mgr.create(f"rollback to {commit_hash[:8]}", reason="rollback")
        _, new_head, _ = self._git(["rev-parse", "HEAD"])
        return RollbackResult(
            True,
            f"Rolled back to {commit_hash[:8]}",
            new_head=new_head,
        )

    def to_previous(self) -> RollbackResult:
        """Roll back to the commit immediately before HEAD."""
        code, prev, err = self._git(["rev-parse", "HEAD~1"])
        if code != 0:
            return RollbackResult(False, "No previous commit to roll back to")
        return self.to_commit(prev)

    def list_rollback_points(self, max_count: int = 20) -> List[Snapshot]:
        """Return snapshots available for rollback."""
        return self.snap_mgr.list_snapshots(max_count)
