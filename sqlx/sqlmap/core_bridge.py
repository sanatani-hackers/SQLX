"""Direct wrapper around SQLMap core functionality."""

import sys
import os
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a discovered SQL injection."""
    url: str
    parameter: str
    parameter_type: str
    injection_type: str
    payload: str
    dbms: Optional[str] = None
    os: Optional[str] = None
    tamper_scripts: Optional[List[str]] = None
    confidence: float = 0.0
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class SQLMapCoreBridge:
    """Direct wrapper around SQLMap core functionality."""

    def __init__(self, target_profile, proxy_handler=None):
        self.target_profile = target_profile
        self.proxy_handler = proxy_handler
        self._sqlmap_available = False
        self._init_sqlmap()

    def _init_sqlmap(self):
        """Initialize SQLMap with minimal config."""
        try:
            # Locate SQLMap in target workspace
            sqlmap_dir = Path(self.target_profile.workspace_dir) / "sqlmap"
            sqlmap_script = sqlmap_dir / "sqlmap.py"

            if not sqlmap_script.exists():
                logger.warning(f"SQLMap not found in workspace: {sqlmap_dir}")
                self._sqlmap_available = False
                return

            # Add SQLMap directory to Python path so we can import it
            if str(sqlmap_dir) not in sys.path:
                sys.path.insert(0, str(sqlmap_dir))

            # Now try to import SQLMap modules
            from lib.core.data import kb, paths, conf, cmdLineOptions
            from lib.core.common import setPaths, dataToStdout
            from lib.core.datatype import AttribDict

            self._sqlmap_available = True

            # Initialize knowledge base
            if not hasattr(kb, 'data'):
                kb.data = {}
            if not hasattr(kb, 'injections'):
                kb.injections = []

            # Set paths
            paths.SQLMAP_ROOT_PATH = str(sqlmap_dir)
            paths.SQLMAP_DATA_PATH = str(sqlmap_dir / "data")

            # Initialize cmdLineOptions if not already done
            if cmdLineOptions is None or not isinstance(cmdLineOptions, dict):
                from lib.core.data import cmdLineOptions as clo
                # Create a minimal cmdLineOptions dict
                pass

            # Configure for programmatic use with all required attributes
            conf.verbose = 0
            conf.batch = True
            conf.wizard = False  # Disable wizard mode
            conf.threads = 4
            conf.timeout = 10
            conf.answers = None
            conf.eta = False
            conf.updateAll = False
            conf.smokeTest = False
            conf.liveTest = False

            logger.info(f"SQLMap core initialized successfully from {sqlmap_dir}")

        except ImportError as e:
            logger.warning(f"SQLMap core not available: {e}. Falling back to subprocess mode.")
            self._sqlmap_available = False
        except Exception as e:
            logger.error(f"Failed to initialize SQLMap: {e}")
            self._sqlmap_available = False

    def is_available(self) -> bool:
        """Check if SQLMap core is available."""
        return self._sqlmap_available

    def detect_injection(self, url: str, params: Optional[Dict[str, str]] = None,
                        technique: str = 'BEUSTQ', timeout: int = 300) -> List[Finding]:
        """
        Detect SQL injection in target URL.

        Args:
            url: Target URL
            params: Dict of parameters to test (optional; if None, test all)
            technique: Technique flags (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline)
            timeout: Max execution time in seconds

        Returns:
            List of Finding objects
        """
        if not self._sqlmap_available:
            raise RuntimeError("SQLMap core not available. Install sqlmap package or use subprocess mode.")

        try:
            from lib.core.data import kb, conf, cmdLineOptions, logger as sqlmapLogger
            from lib.parse.cmdline import cmdLineParser
            from lib.core.option import init
            from lib.controller.controller import start

            # Build command-line arguments
            args = [
                '--batch',
                '--url', url,
                '--technique', technique,
                '--timeout', str(timeout),
                '--threads', '4'
            ]

            if params:
                args.extend(['--testParameter', ','.join(params.keys())])

            # Hook proxy if provided
            if self.proxy_handler:
                proxy_url = f"http://{self.proxy_handler.host}:{self.proxy_handler.port}"
                args.extend(['--proxy', proxy_url])

            # Parse arguments as if from command line
            cmdLineOptions.update(cmdLineParser().__dict__)

            # Override parsed options with our values
            for i in range(0, len(args), 2):
                if i + 1 < len(args):
                    key = args[i].lstrip('-')
                    value = args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith('--') else True
                    cmdLineOptions[key] = value

            # Reset state
            kb.injections = []

            # Initialize SQLMap with parsed options
            init(cmdLineOptions)

            # Start detection
            start()

            # Collect findings
            findings = []
            if hasattr(kb, 'injections') and kb.injections:
                for injection in kb.injections:
                    findings.append(self._injection_to_finding(injection))

            return findings

        except Exception as e:
            logger.error(f"SQLMap detection error: {e}", exc_info=True)
            raise

    def _injection_to_finding(self, injection) -> Finding:
        """Convert SQLMap injection object to SQLX Finding."""
        try:
            return Finding(
                url=getattr(injection, 'url', ''),
                parameter=getattr(injection, 'parameter', ''),
                parameter_type=getattr(injection, 'ptype', ''),
                injection_type=getattr(injection, 'stype', ''),
                payload=getattr(injection, 'data', {}).get('payload', ''),
                dbms=getattr(injection, 'dbms', None),
                os=getattr(injection, 'os', None),
                tamper_scripts=getattr(injection, 'tamper', None),
                confidence=getattr(injection, 'conf', 0),
                timestamp=datetime.utcnow()
            )
        except Exception as e:
            logger.error(f"Error converting injection to finding: {e}")
            return Finding(
                url='',
                parameter='',
                parameter_type='',
                injection_type='',
                payload='',
                timestamp=datetime.utcnow()
            )

    def _hook_proxy_handler(self):
        """Redirect SQLMap requests through our proxy."""
        if not self.proxy_handler:
            return

        try:
            import urllib.request
            proxy_url = f"http://{self.proxy_handler.host}:{self.proxy_handler.port}"
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy_url,
                'https': proxy_url
            })
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

            logger.info(f"SQLMap traffic routed through proxy: {proxy_url}")
        except Exception as e:
            logger.warning(f"Failed to hook proxy handler: {e}")

    def enumerate_databases(self, injection: Finding) -> List[str]:
        """Enumerate databases using a known injection."""
        if not self._sqlmap_available:
            raise RuntimeError("SQLMap core not available")

        try:
            from lib.core.data import kb
            from lib.request.connect import Connect

            # Use SQLMap's database enumeration
            databases = []
            if hasattr(kb, 'data') and 'dbs' in kb.data:
                databases = kb.data['dbs']

            return databases
        except Exception as e:
            logger.error(f"Database enumeration error: {e}")
            return []

    def enumerate_tables(self, injection: Finding, database: str) -> List[str]:
        """Enumerate tables in a database."""
        if not self._sqlmap_available:
            raise RuntimeError("SQLMap core not available")

        try:
            from lib.core.data import kb

            tables = []
            if hasattr(kb, 'data') and database in kb.data:
                tables = kb.data[database].get('tables', [])

            return tables
        except Exception as e:
            logger.error(f"Table enumeration error: {e}")
            return []

    def enumerate_columns(self, injection: Finding, database: str, table: str) -> List[str]:
        """Enumerate columns in a table."""
        if not self._sqlmap_available:
            raise RuntimeError("SQLMap core not available")

        try:
            from lib.core.data import kb

            columns = []
            if hasattr(kb, 'data') and database in kb.data:
                if table in kb.data[database].get('tables', {}):
                    columns = kb.data[database]['tables'][table].get('columns', [])

            return columns
        except Exception as e:
            logger.error(f"Column enumeration error: {e}")
            return []

    def read_data(self, injection: Finding, database: str, table: str,
                  columns: List[str]) -> List[Dict[str, Any]]:
        """Read data from a table."""
        if not self._sqlmap_available:
            raise RuntimeError("SQLMap core not available")

        try:
            from lib.core.data import kb

            data = []
            if hasattr(kb, 'data') and database in kb.data:
                table_data = kb.data[database].get('tables', {}).get(table, {}).get('data', [])
                data = table_data

            return data
        except Exception as e:
            logger.error(f"Data extraction error: {e}")
            return []
