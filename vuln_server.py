import http.server
import socketserver
import sqlite3
import urllib.parse
import json

# Setup in-memory vulnerable database
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT, password TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin', 'supersecret_admin_pass')")
    c.execute("INSERT INTO users VALUES (2, 'guest', 'user', 'guest123')")
    c.execute("INSERT INTO users VALUES (3, 'test', 'user', 'test321')")
    conn.commit()
    return conn

conn = init_db()

class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        
        # Fake WAF: Block requests containing "UNION" to test AI analysis
        if "UNION" in urllib.parse.unquote(self.path).upper():
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.send_header('X-WAF', 'Blocked by FakeWAF')
            self.send_header('Server', 'cloudflare')
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>Malicious request blocked.</p>")
            return
            
        if parsed_path.path == '/user':
            query = urllib.parse.parse_qs(parsed_path.query)
            user_id = query.get('id', [''])[0]
            
            if not user_id:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing id parameter")
                return
                
            try:
                # VULNERABLE: Direct string interpolation (SQL Injection)
                sql = f"SELECT username, role FROM users WHERE id = {user_id}"
                c = conn.cursor()
                c.execute(sql)
                results = c.fetchall()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"query": sql, "data": results}).encode())
                
            except sqlite3.Error as e:
                # VULNERABLE: Leaks database errors to the user
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Database Error: {str(e)}".encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

if __name__ == "__main__":
    PORT = 8090
    Handler = VulnerableHandler
    
    # allow_reuse_address to prevent Address already in use errors
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Vulnerable Server running at http://127.0.0.1:{PORT}")
        httpd.serve_forever()
