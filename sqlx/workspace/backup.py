"""
sqlx/workspace/backup.py
~~~~~~~~~~~~~~~~~~~~~~~~
File-level backup before destructive workspace changes.
Creates timestamped copies inside the workspace backups/ directory.
"""
from __future__ import annotations
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


class BackupManager:
    """Creates and restores file-level backups inside workspace backups/ dir."""

    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir).absolute()
        self.backup_dir = self.workspace_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def backup_file(self, relative_path: str, reason: str = "") -> Path:
        """Copy a file to backups/ before editing. Returns backup path."""
        source = (self.workspace_dir / relative_path).resolve()
        if not str(source).startswith(str(self.workspace_dir)):
            raise ValueError("Path traversal detected")
        if not source.exists():
            raise FileNotFoundError(f"File not found: {relative_path}")

        ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe     = relative_path.replace("/", "__").replace("\\", "__")
        dest     = self.backup_dir / f"{ts}__{safe}"
        shutil.copy2(str(source), str(dest))
        return dest

    def backup_files(self, relative_paths: List[str], reason: str = "") -> List[Path]:
        return [self.backup_file(p, reason) for p in relative_paths]

    def list_backups(self) -> List[Dict]:
        result = []
        for f in sorted(self.backup_dir.iterdir()):
            if f.is_file():
                parts = f.name.split("__", 1)
                result.append({
                    "path":      str(f),
                    "timestamp": parts[0] if len(parts) == 2 else "",
                    "original":  parts[1].replace("__", "/") if len(parts) == 2 else f.name,
                    "size":      f.stat().st_size,
                })
        return result

    def restore_backup(self, backup_path: str) -> str:
        """Restore a backup to its original location. Returns restored path."""
        backup = Path(backup_path)
        if not backup.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")
        parts = backup.name.split("__", 1)
        if len(parts) != 2:
            raise ValueError(f"Cannot determine original path from: {backup.name}")
        original_rel  = parts[1].replace("__", "/")
        original_path = self.workspace_dir / original_rel
        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(backup), str(original_path))
        return str(original_path)
