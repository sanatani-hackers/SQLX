"""
sqlx/extensions/loader.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Extension loader — discovers and loads Python extension modules
from the project's extensions/ directory (or any configured path).

Extension format
----------------
An extension is a .py file in the extensions/ directory that optionally
defines a top-level ``register(api, registry)`` function::

    def register(api, registry):
        registry.register('my_ext', 'analysis', MyAnalyser(), 'Custom analyser')
"""
from __future__ import annotations
import importlib.util
import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Default location: project_root/extensions/
DEFAULT_EXT_DIR = Path(__file__).parent.parent.parent / "extensions"


class ExtensionLoader:
    """Discovers and loads SQLX extension modules."""

    def __init__(self, ext_dir: str = None):
        self.ext_dir = Path(ext_dir) if ext_dir else DEFAULT_EXT_DIR
        self._loaded: List[str] = []
        self._failed: List[str] = []

    def discover(self) -> List[Path]:
        """Return sorted list of .py files in the extensions directory."""
        if not self.ext_dir.exists():
            return []
        return sorted(p for p in self.ext_dir.glob("*.py")
                      if not p.name.startswith("_"))

    def load(self, module_path: Path) -> bool:
        """Load a single extension module. Returns True on success."""
        try:
            spec   = importlib.util.spec_from_file_location(
                f"sqlx_ext_{module_path.stem}", str(module_path)
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "register"):
                from sqlx.extensions.api import api
                from sqlx.extensions.registry import _registry
                module.register(api, _registry)

            self._loaded.append(module_path.stem)
            logger.info("Loaded extension: %s", module_path.stem)
            return True
        except Exception as exc:
            logger.error("Failed to load extension %s: %s", module_path.name, exc)
            self._failed.append(module_path.stem)
            return False

    def load_all(self) -> int:
        """Load all discovered extensions. Returns count of successfully loaded."""
        count = 0
        for path in self.discover():
            if self.load(path):
                count += 1
        return count

    def summary(self) -> str:
        parts = [f"Extensions dir: {self.ext_dir}"]
        if self._loaded:
            parts.append(f"Loaded:  {', '.join(self._loaded)}")
        if self._failed:
            parts.append(f"Failed:  {', '.join(self._failed)}")
        if not self._loaded and not self._failed:
            parts.append("No extensions found")
        return "\n".join(parts)

    @property
    def loaded(self) -> List[str]:
        return list(self._loaded)
