"""
sqlx/sqlmap/adapter.py
~~~~~~~~~~~~~~~~~~~~~~
Formal adapter layer between SQLX and the SQLMap subprocess.
Provides a high-level API that builds args, launches the process,
and returns structured results — without callers needing to know the
full SQLMap CLI interface.
"""
from __future__ import annotations
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SQLMapConfig:
    """Fluent builder for SQLMap argument lists."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self._args: List[str] = ["-u", target_url, "--batch"]

    def level(self, n: int) -> "SQLMapConfig":
        self._args += ["--level", str(min(max(1, n), 5))]
        return self

    def risk(self, n: int) -> "SQLMapConfig":
        self._args += ["--risk", str(min(max(1, n), 3))]
        return self

    def tamper(self, *scripts: str) -> "SQLMapConfig":
        self._args += ["--tamper", ",".join(scripts)]
        return self

    def proxy(self, proxy_url: str) -> "SQLMapConfig":
        self._args += ["--proxy", proxy_url]
        return self

    def dbs(self) -> "SQLMapConfig":
        self._args.append("--dbs")
        return self

    def tables(self, db: str = None) -> "SQLMapConfig":
        self._args.append("--tables")
        if db:
            self._args += ["-D", db]
        return self

    def dump(self, db: str = None, table: str = None) -> "SQLMapConfig":
        self._args.append("--dump")
        if db:
            self._args += ["-D", db]
        if table:
            self._args += ["-T", table]
        return self

    def flush_session(self) -> "SQLMapConfig":
        self._args.append("--flush-session")
        return self

    def delay(self, seconds: float) -> "SQLMapConfig":
        self._args += ["--delay", str(seconds)]
        return self

    def threads(self, n: int) -> "SQLMapConfig":
        self._args += ["--threads", str(min(n, 10))]
        return self

    def extra(self, *args: str) -> "SQLMapConfig":
        """Append arbitrary extra args."""
        self._args.extend(args)
        return self

    def build(self) -> List[str]:
        """Return final arg list (deduplicates keyed flags like --level)."""
        seen_flags = set()
        result: List[str] = []
        i = 0
        while i < len(self._args):
            tok = self._args[i]
            if (tok.startswith("--")
                    and i + 1 < len(self._args)
                    and not self._args[i + 1].startswith("-")):
                if tok not in seen_flags:
                    seen_flags.add(tok)
                    result += [tok, self._args[i + 1]]
                i += 2
            else:
                result.append(tok)
                i += 1
        return result


class SQLMapAdapter:
    """High-level adapter: create a SQLMapConfig, run it, get structured results."""

    def __init__(self, target):
        self.target = target

    def quick_scan(self, level: int = 1, risk: int = 1,
                   tamper_scripts: List[str] = None) -> dict:
        """Run a safe reconnaissance scan."""
        from sqlx.sqlmap.runner import SQLMapRunner
        cfg = (SQLMapConfig(self.target.target_url)
               .level(level).risk(risk).flush_session())
        if tamper_scripts:
            cfg.tamper(*tamper_scripts)
        return SQLMapRunner(self.target).run_and_collect(cfg.build())

    def enumerate_dbs(self) -> dict:
        from sqlx.sqlmap.runner import SQLMapRunner
        cfg = SQLMapConfig(self.target.target_url).dbs().level(1).risk(1)
        return SQLMapRunner(self.target).run_and_collect(cfg.build())

    def enumerate_tables(self, db: str = None) -> dict:
        from sqlx.sqlmap.runner import SQLMapRunner
        cfg = SQLMapConfig(self.target.target_url).tables(db).level(1).risk(1)
        return SQLMapRunner(self.target).run_and_collect(cfg.build())

    def dump_table(self, db: str, table: str) -> dict:
        """Requires DATA_DUMP permission — caller must verify."""
        from sqlx.sqlmap.runner import SQLMapRunner
        cfg = SQLMapConfig(self.target.target_url).dump(db, table)
        return SQLMapRunner(self.target).run_and_collect(cfg.build())
