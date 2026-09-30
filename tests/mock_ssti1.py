"""Local-only SSTI1 challenge mock for regression tests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs
FLAG = "academy{mock_ssti1_flag_only}"
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def _send(self, body):
        data=body.encode(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self): self._send('<h1>Announce!</h1><form method="POST" action="/"><textarea name="content"></textarea><button>Announce</button></form>')
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); value=parse_qs(self.rfile.read(n).decode()).get("content",[""])[0]
        if value == "{{7*7}}": return self._send("<p>49</p>")
        if "cycler.__init__" in value and "cat flag" in value: return self._send("<p>"+FLAG+"</p>")
        self._send("<p>"+value+"</p>")
def start_server():
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler);Thread(target=server.serve_forever,daemon=True).start();return server,f"http://127.0.0.1:{server.server_port}/"

class RedirectHandler(Handler):
    def do_POST(self):
        if self.path == "/":
            self.send_response(307); self.send_header("Location", "/announce"); self.send_header("Content-Length", "0"); self.end_headers(); return
        if self.path == "/announce": return super().do_POST()
        self.send_error(404)

def start_redirect_server():
    server=ThreadingHTTPServer(("127.0.0.1",0),RedirectHandler);Thread(target=server.serve_forever,daemon=True).start();return server,f"http://127.0.0.1:{server.server_port}/"
