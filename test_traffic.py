import sqlx
import time
import subprocess
from sqlx.proxy import SharedProxyServer
from sqlx.agent.tools import analyze_recent_traffic

proxy = SharedProxyServer(port=8082)
proxy.start()

subprocess.run(["curl", "-s", "-x", "http://127.0.0.1:8082", "http://example.com"], capture_output=True)

time.sleep(1)
print("Result:", analyze_recent_traffic())
proxy.stop()
