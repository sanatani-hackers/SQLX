"""
sqlx/workspace/patcher.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Applies unified diffs or string replacements to workspace files.
Always backs up before applying, then creates a git snapshot.
"""
from __future__ import annotations
import subprocess
from pathlib import Path

from sqlx.workspace.backup import BackupManager
from sqlx.workspace.snapshot import SnapshotManager


class PatchResult:
    def __init__(self, success: bool, message: str, commit_hash: str = None):
        self.success     = success
        self.message     = message
        self.commit_hash = commit_hash

    def __bool__(self) -> bool:
        return self.success

    def __str__(self) -> str:
        return self.message


class Patcher:
    """Applies unified diffs or targeted string replacements to workspace files."""

    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir).absolute()
        self.backup_mgr    = BackupManager(workspace_dir)
        self.snap_mgr      = SnapshotManager(workspace_dir)

    def apply_unified_diff(self, diff_content: str,
                           commit_message: str = "Apply patch") -> PatchResult:
        """Apply a unified diff string to the workspace. Backs up + commits."""
        if not any(diff_content.lstrip().startswith(p)
                   for p in ("---", "diff --git", "Index:")):
            return PatchResult(False, "Content does not look like a unified diff")

        patch_file = self.workspace_dir / ".sqlx_tmp.patch"
        try:
            patch_file.write_text(diff_content, encoding="utf-8")

            check = subprocess.run(
                ["git", "apply", "--check", str(patch_file)],
                cwd=str(self.workspace_dir), capture_output=True, text=True,
            )
            if check.returncode != 0:
                return PatchResult(False, f"Patch check failed:\n{check.stderr}")

            subprocess.run(
                ["git", "apply", str(patch_file)],
                cwd=str(self.workspace_dir), capture_output=True,
            )
            snap = self.snap_mgr.create(commit_message, reason="patch")
            return PatchResult(
                True,
                f"Patch applied — commit: {snap.short_hash()}",
                commit_hash=snap.commit_hash,
            )
        except Exception as exc:
            return PatchResult(False, f"Patch error: {exc}")
        finally:
            if patch_file.exists():
                patch_file.unlink()

    def apply_string_replacement(self, filepath: str, old_text: str,
                                  new_text: str, commit_message: str) -> PatchResult:
        """Replace first occurrence of old_text with new_text. Backs up + commits."""
        full_path = (self.workspace_dir / filepath).resolve()
        if not str(full_path).startswith(str(self.workspace_dir)):
            return PatchResult(False, "Path traversal detected")
        if not full_path.exists():
            return PatchResult(False, f"File not found: {filepath}")

        content = full_path.read_text(encoding="utf-8")
        if old_text not in content:
            return PatchResult(False, f"old_text not found in {filepath}")

        self.backup_mgr.backup_file(filepath, reason="pre_patch")
        full_path.write_text(content.replace(old_text, new_text, 1), encoding="utf-8")

        snap = self.snap_mgr.create(commit_message, reason="string_replace")
        return PatchResult(
            True,
            f"File edited: {filepath} — commit: {snap.short_hash()}",
            commit_hash=snap.commit_hash,
        )
