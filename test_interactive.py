from sqlx.proxy.server import ProxyHandler

class MockServer:
    server_address = ("127.0.0.1", 8081)

class MockHandler:
    def __init__(self):
        self.server = MockServer()

req = {
    "method": "POST",
    "url": "http://example.com/login?u=admin%20or%201%3D1",
    "headers": {"Host": "example.com", "Content-Length": "13"},
    "body": b"user=admin123"
}

import os
os.environ["EDITOR"] = "cat"

h = MockHandler()
h._interactive_edit = ProxyHandler._interactive_edit.__get__(h)
res = h._interactive_edit(req)
print("\n=== Result ===")
import json
res["body"] = res["body"].decode("utf-8")
print(json.dumps(res, indent=4))
