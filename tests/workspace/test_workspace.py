import os
from pathlib import Path
import pytest
from sqlx.target.scope import ScopeChecker
from sqlx.workspace.snapshot import SnapshotManager
from sqlx.workspace.backup import BackupManager

def test_scope_checker():
    scope = ScopeChecker()
    scope.add_allowed_host("example.com")
    
    assert scope.is_allowed("http://example.com/test") is True
    assert scope.is_allowed("http://sub.example.com") is False
    assert scope.is_allowed("http://evil.com") is False
    
    scope.add_blocked_pattern(r"admin")
    assert scope.is_allowed("http://example.com/admin/login") is False

def test_backup_manager(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    bm = BackupManager(str(workspace))
    test_file = workspace / "test.txt"
    test_file.write_text("hello")
    
    backup_path = bm.backup_file("test.txt")
    assert backup_path.exists()
    
    backups = bm.list_backups()
    assert len(backups) == 1
    assert backups[0]["original"] == "test.txt"

def test_snapshot_manager(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    import subprocess
    subprocess.run(["git", "init"], cwd=str(workspace))
    
    sm = SnapshotManager(str(workspace))
    test_file = workspace / "test.txt"
    test_file.write_text("hello")
    
    snap = sm.create("Initial commit")
    assert snap.commit_hash
    assert snap.files_changed == 1
