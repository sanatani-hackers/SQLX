"""
sqlx/workspace/diff.py
~~~~~~~~~~~~~~~~~~~~~~
Diff utilities for comparing workspace states — working tree vs HEAD,
two commits, or individual file contents at a specific revision.
"""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import List, Optional


class WorkspaceDiffer:
    """Provides diff views between workspace states."""

    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir).absolute()

    def _git(self, args: list) -> str:
        r = subprocess.run(
            ["git"] + args, cwd=str(self.workspace_dir),
            capture_output=True, text=True,
        )
        return r.stdout

    def working_tree_diff(self) -> str:
        """Uncommitted changes vs HEAD."""
        return self._git(["diff", "HEAD"])

    def staged_diff(self) -> str:
        """Staged (but not committed) changes."""
        return self._git(["diff", "--cached"])

    def between_commits(self, commit_a: str, commit_b: str = "HEAD") -> str:
        """Diff between two commits."""
        return self._git(["diff", commit_a, commit_b])

    def file_at_commit(self, filepath: str, commit: str) -> Optional[str]:
        """Return contents of a file at a specific commit."""
        r = subprocess.run(
            ["git", "show", f"{commit}:{filepath}"],
            cwd=str(self.workspace_dir), capture_output=True, text=True,
        )
        return r.stdout if r.returncode == 0 else None

    def changed_files(self, commit_a: str = "HEAD~1",
                      commit_b: str = "HEAD") -> List[str]:
        """List of files changed between two commits."""
        output = self._git(["diff", "--name-only", commit_a, commit_b])
        return [f for f in output.strip().splitlines() if f]

    def summary(self) -> str:
        """Short --stat summary of uncommitted changes."""
        stat = self._git(["diff", "--stat", "HEAD"]).strip()
        return stat or "No uncommitted changes"
