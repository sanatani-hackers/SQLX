# Bootstrap: initialize singletons and wire up default event handlers
from sqlx.events.bus import bus
from sqlx.events.handlers import register_default_handlers
from sqlx.analysis.http import analyzer
from sqlx.proxy.history import ProxyHistory
from sqlx.analysis.correlation import PayloadCorrelator

# Register audit log handler for all events
register_default_handlers()

# Global persistent proxy history (auto-subscribes to ProxyResponseReceived)
proxy_history = ProxyHistory()

# Global payload correlator (auto-subscribes to ProxyResponseReceived)
payload_correlator = PayloadCorrelator()

__all__ = ["bus", "analyzer", "proxy_history", "payload_correlator"]
