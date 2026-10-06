import sys
import subprocess
import time

def run():
    p = subprocess.Popen(["./sqlx.py", "proxy", "--intercept"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2)
    
    # Fire off a request
    import threading
    def curl():
        subprocess.run(["curl", "-s", "-x", "http://127.0.0.1:8081", "http://example.com/login?a=b"], capture_output=True)
    t = threading.Thread(target=curl)
    t.start()
    
    time.sleep(1)
    
    # Provide 'A' to accept
    p.stdin.write("A\n")
    p.stdin.flush()
    
    time.sleep(1)
    p.kill()
    out, _ = p.communicate()
    print("OUTPUT:")
    print(out)

run()
