import subprocess
import time

p = subprocess.Popen(["./sqlx.py", "proxy", "--intercept"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(1)

# Send a request
import threading
def curl():
    subprocess.run(["curl", "-s", "-x", "http://127.0.0.1:8081", "http://example.com/"])
t = threading.Thread(target=curl)
t.start()
time.sleep(0.5)

# Simulate Ctrl-C at prompt by closing stdin, which raises EOFError in Python
p.stdin.close()

# The proxy should catch EOFError, drop the request, and continue
time.sleep(1)
p.terminate()
out, _ = p.communicate()
print(out)
