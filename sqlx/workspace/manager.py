import subprocess
from pathlib import Path
from typing import List, Dict, Optional

class WorkspaceError(Exception):
    pass

class WorkspaceManager:
    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir).absolute()
        self.sqlmap_dir = self.workspace_dir / "sqlmap"
        
    def _run_git(self, args: List[str], check: bool = True) -> str:
        cmd = ["git"] + args
        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.workspace_dir),
                capture_output=True,
                text=True,
                check=check
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise WorkspaceError(f"Git command failed: {' '.join(cmd)}\nError: {e.stderr.strip()}")

    def init_repo(self):
        """Initializes a git repository in the target's workspace directory."""
        if not self.workspace_dir.exists():
            raise FileNotFoundError(f"Target workspace directory not found: {self.workspace_dir}")
            
        if not (self.workspace_dir / ".git").exists():
            self._run_git(["init"])
            # Configure local git user for commits
            self._run_git(["config", "user.name", "SQLX Agent"])
            self._run_git(["config", "user.email", "agent@sqlx.local"])
            
            self._run_git(["add", "."])
            self._run_git(["commit", "-m", "baseline"])

    def create_snapshot(self, message: str) -> str:
        """Commits current changes to create a snapshot and returns the commit hash."""
        self._run_git(["add", "."])
        # Check if there are changes
        status = self._run_git(["status", "--porcelain"])
        if not status:
            return self.get_current_revision() # No changes
            
        self._run_git(["commit", "-m", message])
        return self.get_current_revision()

    def get_current_revision(self) -> str:
        """Returns the current commit hash."""
        return self._run_git(["rev-parse", "HEAD"])

    def get_diff(self, commit_a: str = "HEAD", commit_b: Optional[str] = None) -> str:
        """Gets diff between two commits, or working tree if commit_b is None."""
        if commit_b is None:
            # Diff between commit_a and working tree
            return self._run_git(["diff", commit_a], check=False)
        else:
            return self._run_git(["diff", commit_a, commit_b], check=False)

    def apply_patch(self, patch_content: str) -> bool:
        """Applies a patch (diff) to the working tree."""
        patch_file = self.workspace_dir / "patches" / "temp.patch"
        patch_file.parent.mkdir(parents=True, exist_ok=True)
        patch_file.write_text(patch_content)
        
        try:
            self._run_git(["apply", str(patch_file)])
            return True
        except WorkspaceError:
            return False
        finally:
            if patch_file.exists():
                patch_file.unlink()

    def rollback(self, commit_hash: str = "HEAD"):
        """Rolls back the workspace to a specific commit."""
        self._run_git(["reset", "--hard", commit_hash])
        self._run_git(["clean", "-fd"])

    def get_history(self) -> List[Dict[str, str]]:
        """Returns a list of commits in the workspace."""
        log_output = self._run_git(["log", "--pretty=format:%H|%an|%ad|%s", "--date=iso"])
        history = []
        if log_output:
            for line in log_output.split("\n"):
                parts = line.split("|", 3)
                if len(parts) == 4:
                    history.append({
                        "hash": parts[0],
                        "author": parts[1],
                        "date": parts[2],
                        "message": parts[3]
                    })
        return history
