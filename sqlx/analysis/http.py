from typing import Dict, Any, List, Optional
from datetime import datetime

class HTTPTransaction:
    def __init__(self, req_data: Dict[str, Any], res_data: Dict[str, Any] = None):
        self.timestamp = datetime.utcnow()
        self.request = req_data
        self.response = res_data
        self.id = id(self)
        self.latency_ms = 0.0

class TrafficAnalyzer:
    def __init__(self):
        self.history: List[HTTPTransaction] = []
        self.pending_requests: Dict[str, HTTPTransaction] = {}
        
        # Subscribe to Event Bus
        from sqlx.events.bus import bus
        bus.subscribe("ProxyRequestCaptured", self._on_request_captured)
        bus.subscribe("ProxyResponseReceived", self._on_response_received)
        
    def _on_request_captured(self, req_data: Dict[str, Any]):
        self.add_request(req_data)
        
    def _on_response_received(self, data: Dict[str, Any]):
        req_data = data.get("req_data")
        res_data = data.get("res_data")
        if req_data and res_data:
            self.add_response(req_data, res_data)
            
    def add_request(self, req_data: Dict[str, Any]) -> HTTPTransaction:
        txn = HTTPTransaction(req_data)
        # Using a simple combination of URL and method to track for response matching
        # In a real proxy, a connection/stream ID is better
        key = f"{req_data.get('method')}_{req_data.get('url')}"
        self.pending_requests[key] = txn
        return txn
        
    def add_response(self, req_data: Dict[str, Any], res_data: Dict[str, Any]) -> Optional[HTTPTransaction]:
        key = f"{req_data.get('method')}_{req_data.get('url')}"
        txn = self.pending_requests.pop(key, None)
        
        if txn:
            txn.response = res_data
            txn.latency_ms = (datetime.utcnow() - txn.timestamp).total_seconds() * 1000
            self.history.append(txn)
            return txn
        else:
            # Unmatched response
            txn = HTTPTransaction(req_data, res_data)
            self.history.append(txn)
            return txn

    def get_recent(self, limit: int = 10) -> List[HTTPTransaction]:
        return self.history[-limit:]
        
    def analyze_txn(self, txn: HTTPTransaction) -> Dict[str, Any]:
        """Performs basic analysis on a single transaction."""
        analysis = {
            "status": txn.response.get("status") if txn.response else None,
            "latency": txn.latency_ms,
            "has_waf_headers": False,
            "suspicious_status": False
        }
        
        if txn.response:
            status = txn.response.get("status", 200)
            if status in [403, 406, 429, 500, 503]:
                analysis["suspicious_status"] = True
                
            headers = {k.lower(): v for k, v in txn.response.get("headers", {}).items()}
            waf_indicators = ["x-waf", "x-firewall", "cf-ray", "server"]
            for h in waf_indicators:
                if h in headers:
                    if h == "server" and any(w in str(headers[h]).lower() for w in ["cloudflare", "akamai", "f5", "imperva", "sucuri"]):
                        analysis["has_waf_headers"] = True
                    elif h != "server":
                        analysis["has_waf_headers"] = True
                        
        return analysis

# Global traffic analyzer instance
analyzer = TrafficAnalyzer()
