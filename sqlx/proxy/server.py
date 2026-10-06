import http.server
import socketserver
import urllib.request
import urllib.error
import threading
import ssl
from typing import Callable, Any
from sqlx.proxy.cert import get_cert_for_domain

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.scheme = 'http'
        super().__init__(request, client_address, server)

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def log_message(self, format, *args):
        # Mute default BaseHTTPRequestHandler sys.stderr logging
        pass

    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def do_PUT(self): self.handle_request()
    def do_DELETE(self): self.handle_request()
    def do_OPTIONS(self): self.handle_request()
    def do_HEAD(self): self.handle_request()

    def do_CONNECT(self):
        """Handle HTTPS CONNECT by intercepting (TLS Bumping)"""
        hostname = self.path.split(":")[0]
        
        try:
            # 1. Generate/Fetch the spoofed certificate for this domain
            cert_path = get_cert_for_domain(hostname)
            
            # 2. Tell the client we are connected
            self.send_response(200, "Connection Established")
            self.end_headers()
            
            # 3. Upgrade the local socket to TLS using the spoofed cert
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert_path))
            
            self.connection = context.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile("rb", self.rbufsize)
            self.wfile = self.connection.makefile("wb", self.wbufsize)
            
            self.scheme = 'https'
            
            # 4. Read the decrypted inner HTTP requests (keep-alive loop)
            self.close_connection = False
            while not self.close_connection:
                self.handle_one_request()
                
        except (ssl.SSLError, BrokenPipeError, ConnectionResetError):
            # Client disconnected abruptly or TLS handshake aborted
            return
        except Exception as e:
            try:
                self.send_error(502, f"MITM Connect failed: {e}")
            except Exception:
                pass
            return

    @staticmethod
    def open_in_editor(req_data: dict) -> dict:
        import os
        import tempfile
        import subprocess
        import urllib.parse
        
        url_decoded = urllib.parse.unquote(req_data.get("url", ""))
        body_str = req_data.get("body", b"")
        if isinstance(body_str, bytes):
            body_str = body_str.decode("utf-8", errors="replace")
            
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
            f.write(f"{req_data.get('method', 'GET')} {url_decoded}\n")
            for k, v in req_data.get("headers", {}).items():
                f.write(f"{k}: {v}\n")
            f.write("\n")
            f.write(body_str)
            tmp_name = f.name
            
        editor = os.environ.get("EDITOR", "nano")
        print(f"[*] Opening {editor}...")
        subprocess.run([editor, tmp_name])
        
        try:
            with open(tmp_name, 'r', encoding='utf-8') as f:
                content = f.read()
                
            lines = content.split('\n')
            first_line = lines[0].strip()
            method, url = first_line.split(' ', 1)
            
            headers = {}
            idx = 1
            while idx < len(lines):
                line = lines[idx].rstrip('\r\n')
                if not line:
                    idx += 1
                    break
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
                idx += 1
                
            body = '\n'.join(lines[idx:])
            
            new_data = dict(req_data)
            new_data["method"] = method.strip().upper()
            new_data["url"] = urllib.parse.quote(url.strip(), safe=":/?&=@")
            new_data["headers"] = headers
            new_data["body"] = body.encode("utf-8")
            
            # Automatically fix Content-Length if body changed
            if "Content-Length" in new_data["headers"]:
                new_data["headers"]["Content-Length"] = str(len(new_data["body"]))
                
            return new_data
        except Exception as e:
            print(f"[!] Failed to parse edited request, using original: {e}")
            return req_data
        finally:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)

    def _interactive_edit(self, req_data: dict) -> dict:
        import threading
        
        # If queue exists, hand off to main thread dashboard
        if hasattr(self.server, "intercept_queue"):
            event = threading.Event()
            result_box = {}
            self.server.intercept_queue.put((req_data, event, result_box))
            event.wait()
            
            if result_box.get("drop"):
                raise ConnectionAbortedError("Dropped by user via intercept dashboard")
            
            return result_box.get("req_data", req_data)
        
        # Fallback if no queue
        return self.open_in_editor(req_data)

    def handle_request(self):
        from sqlx.events.bus import bus
        req_header = self.headers
        
        # Build full URL if relative
        url = self.path
        if url.startswith("/"):
            host = req_header.get('Host', '')
            url = f"{self.scheme}://{host}{url}"
            
        content_length = int(req_header.get('Content-Length', 0))
        try:
            body = self.rfile.read(content_length) if content_length > 0 else b""
        except (BrokenPipeError, ConnectionResetError):
            return
        
        req_data = {
            "method": self.command,
            "url": url,
            "headers": dict(req_header),
            "body": body,
            "proxy_port": self.server.server_address[1]
        }
        
        # 1. Apply automated agent transforms
        if hasattr(self.server, "interceptor") and self.server.interceptor:
            req_data = self.server.interceptor.apply(req_data)

        # 2. Apply interactive user intercept (if enabled)
        if getattr(self.server, "interactive_intercept", False) and req_data["method"] in ("GET", "POST"):
            req_data = self._interactive_edit(req_data)

        bus.publish("ProxyRequestCaptured", req_data)
        
        if hasattr(self.server, "on_request"):
            self.server.on_request(req_data)
            
        try:
            req = urllib.request.Request(req_data["url"], data=req_data["body"] if req_data["body"] else None, method=req_data["method"])
            for k, v in req_data["headers"].items():
                if k.lower() not in ("host", "accept-encoding"):
                    req.add_header(k, v)
                    
            # Disable certificate verification for upstream
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ctx) as response:
                resp_body = response.read()
                self.send_response(response.status)
                for k, v in response.headers.items():
                    if k.lower() != 'transfer-encoding':
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_body)
                
                res_data = {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": resp_body
                }

                # Emit event and capture the stored record's ID for logging
                event_payload = {"req_data": req_data, "res_data": res_data}
                bus.publish("ProxyResponseReceived", event_payload)

                # Log with request ID if history is available
                try:
                    from sqlx import proxy_history
                    recent = proxy_history.get_recent(1)
                    rid = recent[0]["id"] if recent else "?"
                    print(f"  [ID={rid}] \u2192 {req_data['method']} {req_data['url']}", flush=True)
                except Exception:
                    print(f"  \u2192 {req_data['method']} {req_data['url']}", flush=True)

                if hasattr(self.server, "on_response"):
                    self.server.on_response(res_data)
                    
        except urllib.error.HTTPError as e:
            try:
                resp_body = e.read()
                self.send_response(e.code)
                for k, v in e.headers.items():
                    if k.lower() != 'transfer-encoding':
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_body)
                
                res_data = {
                    "status": e.code,
                    "headers": dict(e.headers),
                    "body": resp_body
                }
                bus.publish("ProxyResponseReceived", {"req_data": req_data, "res_data": res_data})
                if hasattr(self.server, "on_response"):
                    self.server.on_response(res_data)
                    
            except (BrokenPipeError, ConnectionResetError):
                pass
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self.send_error(500, f"Proxy Error: {str(e)}")
            except Exception:
                pass

class SharedProxyServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8081, interactive_intercept: bool = False):
        import queue
        self.host = host
        self.port = port
        self.interactive_intercept = interactive_intercept
        self.intercept_queue = queue.Queue()
        
        from sqlx.proxy.interceptor import RequestInterceptor
        self.interceptor = RequestInterceptor()
        
        # Delay bind and activate so importing the module doesn't lock the port
        self.server = socketserver.ThreadingTCPServer((self.host, self.port), ProxyHandler, bind_and_activate=False)
        self.server.allow_reuse_address = True
        self.server.interceptor = self.interceptor
        self.server.interactive_intercept = self.interactive_intercept
        self.server.intercept_queue = self.intercept_queue
        self.thread = None

    def set_request_callback(self, cb: Callable[[dict], Any]):
        self.server.on_request = cb

    def set_response_callback(self, cb: Callable[[dict], Any]):
        self.server.on_response = cb

    def start(self):
        try:
            self.server.server_bind()
            self.server.server_activate()
        except Exception:
            pass # Already bound or other error handled by caller
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        # Unblock any pending intercepted requests so their threads can exit
        if getattr(self, "interactive_intercept", False) and hasattr(self, "intercept_queue"):
            import queue
            while True:
                try:
                    req_data, event, result_box = self.intercept_queue.get_nowait()
                    result_box["drop"] = True
                    event.set()
                except queue.Empty:
                    break
                    
        self.server.shutdown()
        self.server.server_close()
        if self.thread:
            self.thread.join()

# Global singleton proxy instance
_proxy = SharedProxyServer()

def get_proxy() -> SharedProxyServer:
    return _proxy
