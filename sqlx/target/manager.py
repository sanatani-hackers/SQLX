import os
import json
import shutil
from pathlib import Path
from typing import List, Optional

from .profile import TargetProfile

class TargetManager:
    def __init__(self, base_dir: str = "targets"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def create_target(self, name: str, target_url: str, description: str = "") -> TargetProfile:
        # Create a safe directory name
        safe_name = "".join(c if c.isalnum() else "_" for c in name).lower()
        # Find unique directory name
        target_dir = self.base_dir / safe_name
        counter = 1
        while target_dir.exists():
            target_dir = self.base_dir / f"{safe_name}_{counter}"
            counter += 1
            
        profile = TargetProfile(
            name=name,
            target_url=target_url,
            description=description,
            workspace_dir=str(target_dir)
        )
        
        self._init_workspace(target_dir)
        self.save_target(profile)
        return profile
        
    def _init_workspace(self, target_dir: Path):
        """Initializes the target-specific workspace layout."""
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "sqlmap").mkdir(exist_ok=True)
        (target_dir / "backups").mkdir(exist_ok=True)
        (target_dir / "patches").mkdir(exist_ok=True)
        (target_dir / "sessions").mkdir(exist_ok=True)
        (target_dir / "traffic").mkdir(exist_ok=True)
        (target_dir / "findings").mkdir(exist_ok=True)
        (target_dir / "logs").mkdir(exist_ok=True)
        (target_dir / "memory").mkdir(exist_ok=True)
        
        # Copy original sqlmap to the target workspace if it exists in the root
        original_sqlmap = Path("sqlmap")
        if original_sqlmap.exists() and original_sqlmap.is_dir():
            target_sqlmap = target_dir / "sqlmap"
            if target_sqlmap.exists():
                shutil.rmtree(target_sqlmap)
            shutil.copytree(original_sqlmap, target_sqlmap)
            
            # Remove the copied .git directory to start a fresh history for the workspace
            target_git = target_sqlmap / ".git"
            if target_git.exists():
                shutil.rmtree(target_git)
            
            # Initialize version tracking
            from sqlx.workspace.manager import WorkspaceManager
            try:
                wm = WorkspaceManager(str(target_dir))
                wm.init_repo()
            except Exception as e:
                print(f"Warning: Failed to initialize workspace git repository: {e}")
            
    def save_target(self, profile: TargetProfile):
        """Saves the target profile to target.json."""
        target_dir = Path(profile.workspace_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "target.json"
        
        with open(target_file, "w") as f:
            f.write(profile.model_dump_json(indent=4))
            
    def load_target(self, target_id_or_name: str) -> Optional[TargetProfile]:
        """Loads a target profile by directory name or ID."""
        for target_dir in self.base_dir.iterdir():
            if not target_dir.is_dir():
                continue
            
            target_file = target_dir / "target.json"
            if target_file.exists():
                with open(target_file, "r") as f:
                    try:
                        data = json.load(f)
                        profile = TargetProfile(**data)
                        if profile.id == target_id_or_name or target_dir.name == target_id_or_name or profile.name == target_id_or_name:
                            # Update workspace dir in case it was moved
                            profile.workspace_dir = str(target_dir)
                            return profile
                    except Exception as e:
                        print(f"Error loading {target_file}: {e}")
        return None

    def list_targets(self) -> List[TargetProfile]:
        """Lists all existing target profiles."""
        targets = []
        for target_dir in self.base_dir.iterdir():
            if target_dir.is_dir():
                target_file = target_dir / "target.json"
                if target_file.exists():
                    with open(target_file, "r") as f:
                        try:
                            data = json.load(f)
                            profile = TargetProfile(**data)
                            profile.workspace_dir = str(target_dir)
                            targets.append(profile)
                        except Exception:
                            pass
        return targets

    def delete_target(self, target_id_or_name: str) -> bool:
        """Deletes a target and its entire workspace directory. Returns True if deleted."""
        target = self.load_target(target_id_or_name)
        if not target:
            return False
        workspace = Path(target.workspace_dir)
        if workspace.exists():
            shutil.rmtree(workspace)
        return True
