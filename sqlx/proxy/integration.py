"""Proxy integration for SQLMap traffic routing."""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ProxySQLMapIntegration:
    """Route all SQLMap traffic through SQLX proxy."""

    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 8081):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self._original_env = {}
        self._setup_complete = False

    def setup(self):
        """Configure SQLMap core to use our proxy."""
        if self._setup_complete:
            logger.debug("Proxy integration already set up")
            return

        proxy_url = f"http://{self.proxy_host}:{self.proxy_port}"

        # Save original environment
        self._original_env = {
            'HTTP_PROXY': os.environ.get('HTTP_PROXY'),
            'HTTPS_PROXY': os.environ.get('HTTPS_PROXY'),
            'http_proxy': os.environ.get('http_proxy'),
            'https_proxy': os.environ.get('https_proxy')
        }

        # Set environment variables for all HTTP libraries
        os.environ['HTTP_PROXY'] = proxy_url
        os.environ['HTTPS_PROXY'] = proxy_url
        os.environ['http_proxy'] = proxy_url
        os.environ['https_proxy'] = proxy_url

        # Hook Python's urllib
        try:
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy_url,
                'https': proxy_url
            })
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)
            logger.info(f"urllib configured to use proxy: {proxy_url}")
        except Exception as e:
            logger.warning(f"Failed to configure urllib proxy: {e}")

        # Hook requests library if available
        try:
            import requests
            requests.adapters.DEFAULT_POOLSIZE = 1  # Single connection for proxy
            logger.info("requests library configured for proxy")
        except Exception as e:
            logger.debug(f"requests library not available: {e}")

        # Hook SQLMap's connection handler
        try:
            from lib.core.data import conf
            conf.proxy = proxy_url
            logger.info(f"SQLMap conf.proxy set to: {proxy_url}")
        except Exception as e:
            logger.debug(f"SQLMap not available for proxy configuration: {e}")

        self._setup_complete = True
        logger.info(f"Proxy integration setup complete: {proxy_url}")

    def teardown(self):
        """Restore original proxy settings."""
        if not self._setup_complete:
            return

        # Restore environment variables
        for key, value in self._original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

        # Reset urllib opener to default
        try:
            import urllib.request
            opener = urllib.request.build_opener()
            urllib.request.install_opener(opener)
        except Exception as e:
            logger.warning(f"Failed to restore urllib opener: {e}")

        self._setup_complete = False
        logger.info("Proxy integration torn down")

    def is_setup(self) -> bool:
        """Check if proxy integration is set up."""
        return self._setup_complete

    def get_proxy_url(self) -> str:
        """Get the proxy URL."""
        return f"http://{self.proxy_host}:{self.proxy_port}"

    def verify_proxy_connectivity(self) -> bool:
        """Verify that the proxy is accessible."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.proxy_host, self.proxy_port))
            sock.close()

            if result == 0:
                logger.info(f"Proxy is accessible at {self.proxy_host}:{self.proxy_port}")
                return True
            else:
                logger.warning(f"Proxy not accessible at {self.proxy_host}:{self.proxy_port}")
                return False
        except Exception as e:
            logger.error(f"Failed to verify proxy connectivity: {e}")
            return False

    @staticmethod
    def configure_sqlmap_proxy(proxy_url: str):
        """Configure SQLMap to use a specific proxy URL."""
        try:
            from sqlmap.lib.core.data import conf
            conf.proxy = proxy_url
            logger.info(f"SQLMap configured with proxy: {proxy_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to configure SQLMap proxy: {e}")
            return False

    def __enter__(self):
        """Context manager entry."""
        self.setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.teardown()
        return False
