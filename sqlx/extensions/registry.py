"""
sqlx/extensions/registry.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Extension registry — tracks loaded extensions by name and category.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

_CATEGORIES = ("ai_provider", "analysis", "proxy", "reporter", "tamper", "tool")


class ExtensionRegistry:
    """Central registry for SQLX extensions."""

    CATEGORIES = _CATEGORIES

    def __init__(self):
        self._extensions: Dict[str, dict] = {}

    def register(self, name: str, category: str, obj: Any,
                 description: str = "", version: str = "1.0") -> None:
        if category not in self.CATEGORIES:
            raise ValueError(
                f"Unknown category: {category!r}. Valid: {self.CATEGORIES}"
            )
        self._extensions[name] = {
            "name":        name,
            "category":    category,
            "obj":         obj,
            "description": description,
            "version":     version,
        }

    def get(self, name: str) -> Optional[Any]:
        entry = self._extensions.get(name)
        return entry["obj"] if entry else None

    def list_by_category(self, category: str) -> List[dict]:
        return [e for e in self._extensions.values() if e["category"] == category]

    def list_all(self) -> List[dict]:
        return list(self._extensions.values())

    def is_registered(self, name: str) -> bool:
        return name in self._extensions

    def unregister(self, name: str) -> bool:
        if name in self._extensions:
            del self._extensions[name]
            return True
        return False

    def summary(self) -> str:
        if not self._extensions:
            return "No extensions loaded"
        lines = [f"Extensions ({len(self._extensions)}):"]
        for cat in self.CATEGORIES:
            exts = self.list_by_category(cat)
            if exts:
                lines.append("  " + cat + ": " + ", ".join(e["name"] for e in exts))
        return "\n".join(lines)


# Module-level singleton
_registry = ExtensionRegistry()
