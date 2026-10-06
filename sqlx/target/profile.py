from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
import uuid

class TargetScope(BaseModel):
    allowed_domains: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=list)
    allow_subdomains: bool = False

class TargetProfile(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    target_url: str
    scope: TargetScope = Field(default_factory=TargetScope)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    workspace_dir: str = ""
    
    class Config:
        validate_assignment = True
