import hashlib
import http.server
import threading
import urllib.parse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "local-engine"))
import web_session_audit as audit

EMAIL = "learner@example.test"
PASSWORD = "source-only-demo-password"
FLAG = "picoCTF{hashgate_test_found}"
ADMIN_HASH = hashlib.md5(b"3013").hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = (f'<!-- Email: {EMAIL} Password: {PASSWORD} -->'
                    '<script>fetch("/login", {method:"POST", headers:{"Content-Type":"application/json"}, '
                    'body:JSON.stringify({email,password})});</script>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/profile/user/" + ADMIN_HASH and self.headers.get("Cookie") == "auth=1":
            body = f"<h1>Admin</h1><p>{FLAG}</p>".encode()
            self.send_response(200)
        elif self.path.startswith("/profile/user/"):
            body = b"<h1>Employee profile</h1>"
            self.send_response(200)
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode()
        if "application/json" in self.headers.get("Content-Type", ""):
            import json
            fields = json.loads(raw)
            valid = fields.get("email") == EMAIL and fields.get("password") == PASSWORD
        else:
            fields = urllib.parse.parse_qs(raw)
            valid = fields.get("email") == [EMAIL] and fields.get("password") == [PASSWORD]
        self.send_response(302 if valid else 401)
        if valid:
            self.send_header("Set-Cookie", "auth=1; Path=/; HttpOnly")
            self.send_header("Location", "/profile/")
        self.end_headers()

    def log_message(self, *_args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    result = audit.run_audit(f"http://127.0.0.1:{server.server_port}/",
                             challenge_text="Hashgate\nWeb Exploitation\nabout 20 employees")
    assert result["success"] and result["flag"] == FLAG, result
    assert result["discovered"]["admin_employee_id"] == 3013
    assert result["discovered"]["tested_ids"] == list(range(3000, 3014))
    assert PASSWORD not in str(result["steps"])
    print("Hashgate MD5 IDOR analysis test passed")
finally:
    server.shutdown()
