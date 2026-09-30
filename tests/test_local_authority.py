import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "local-engine"))
import web_session_audit as wsa

FLAG = "academy{local_authority_mock_verified}"
USER, PASS, ADMIN_HASH = "admin", "strongPassword098765", "mock-admin-hash"
state = {"authenticated": False, "posts": []}

ROOT_PAGE = b'''<html><title>Secure Customer Portal</title>
<form action="login.php" method="post">
<input name="username"><input name="password" type="password"><button type="submit">Login</button>
</form></html>'''
LOGIN_PAGE = f'''<html><script src="secure.js"></script>
<form hidden action="admin.php" method="post" id="hiddenAdminForm"><input type="text" name="hash" required id="adminFormHash"></form>
<script>window.username = ""; window.password = "";</script></html>'''.encode()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/": out, ctype = ROOT_PAGE, "text/html"
        elif self.path == "/login.php": out, ctype = LOGIN_PAGE, "text/html"
        elif self.path == "/secure.js":
            out = f"function checkPassword(username, password) {{ if (username === '{USER}' && password === '{PASS}') return true; return false; }}".encode()
            ctype = "application/javascript"
        else: out, ctype = b"not found", "text/plain"
        self.send_response(200 if self.path in {"/", "/login.php", "/secure.js"} else 404)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(out)))
        self.end_headers(); self.wfile.write(out)

    def do_POST(self):
        data = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
        state["posts"].append((self.path, data))
        if self.path == "/login.php":
            ok = data.get("username") == [USER] and data.get("password") == [PASS]
            state["authenticated"] = ok
            body = LOGIN_PAGE.decode().replace('window.username = ""', f'window.username = "{USER}"').replace('window.password = ""', f'window.password = "{PASS}"')
            body = body.replace('</script></html>', f"document.getElementById('adminFormHash').value = '{ADMIN_HASH}';</script></html>")
            out = body.encode()
        elif self.path == "/admin.php":
            out = ("Your Flag: " + FLAG).encode() if state["authenticated"] and data.get("hash") == [ADMIN_HASH] else b"Denied"
        else: out = b"not found"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(out)))
        self.end_headers(); self.wfile.write(out)

    def log_message(self, *args): pass


def test_local_authority_reads_js_credentials_and_follows_observed_form():
    state.update(authenticated=False, posts=[])
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        res = wsa.run_audit(f"http://127.0.0.1:{server.server_port}/", challenge_text="## Local Authority\nWeb Exploitation Easy")
    finally:
        server.shutdown(); thread.join(timeout=2); server.server_close()
    assert res["recognized"] and res["analyzer"] == "local-authority", res
    assert res["success"] and res["flag"] == FLAG, res
    assert state["posts"][0][0] == "/login.php" and state["posts"][1][0] == "/admin.php", state
    rendered = " ".join(s["body_snippet"] for s in res["steps"])
    assert PASS not in rendered and ADMIN_HASH not in rendered, "sensitive values leaked into response timeline"

if __name__ == "__main__":
    test_local_authority_reads_js_credentials_and_follows_observed_form()
    print("Local Authority analyzer tests passed")
