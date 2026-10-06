"""
sqlx/workspace/snapshot.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Snapshot management — wraps git commit operations with SQLX metadata.
"""
from __future__ import annotations
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class Snapshot:
    commit_hash: str
    message: str
    date: str
    author: str
    files_changed: int = 0
    target_id: Optional[str] = None
    reason: Optional[str] = None   # 'pre_patch' | 'manual' | 'post_scan' | 'rollback'

    def short_hash(self) -> str:
        return self.commit_hash[:8]

    def to_dict(self) -> dict:
        return {
            "commit_hash":   self.commit_hash,
            "message":       self.message,
            "date":          self.date,
            "author":        self.author,
            "files_changed": self.files_changed,
            "target_id":     self.target_id,
            "reason":        self.reason,
        }


class SnapshotManager:
    """Creates and lists snapshots (git commits) for a workspace."""

    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir).absolute()

    def _git(self, args: list) -> str:
        r = subprocess.run(
            ["git"] + args, cwd=str(self.workspace_dir),
            capture_output=True, text=True,
        )
        return r.stdout.strip()

    def create(self, message: str, target_id: str = None,
               reason: str = "manual") -> Snapshot:
        """git add -A + commit. Returns Snapshot metadata."""
        self._git(["add", "-A"])
        self._git(["commit", "-m", message, "--allow-empty"])
        commit_hash = self._git(["rev-parse", "HEAD"])
        date        = self._git(["log", "-1", "--format=%ci", "HEAD"])
        author      = self._git(["log", "-1", "--format=%an", "HEAD"])
        numstat     = self._git(["diff", "--shortstat", "HEAD~1", "HEAD"])
        files_changed = 0
        try:
            files_changed = int(numstat.split()[0]) if numstat else 0
        except Exception:
            pass
        return Snapshot(
            commit_hash=commit_hash, message=message, date=date,
            author=author, files_changed=files_changed,
            target_id=target_id, reason=reason,
        )

    def list_snapshots(self, max_count: int = 50) -> List[Snapshot]:
        """Return list of Snapshot objects from git log."""
        fmt = "%H%x1F%s%x1F%ci%x1F%an"
        output = self._git(["log", f"--max-count={max_count}", f"--format={fmt}"])
        snapshots: List[Snapshot] = []
        for line in output.splitlines():
            parts = line.split("\x1f")
            if len(parts) >= 4:
                snapshots.append(Snapshot(
                    commit_hash=parts[0], message=parts[1],
                    date=parts[2], author=parts[3],
                ))
        return snapshots

    def get_snapshot(self, commit_hash: str) -> Optional[Snapshot]:
        return next(
            (s for s in self.list_snapshots() if s.commit_hash.startswith(commit_hash)),
            None,
        )
