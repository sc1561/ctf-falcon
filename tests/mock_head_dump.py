"""Local-only model of picoCTF head-dump and its published API documentation."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

FLAG = "academy{mock_head_dump_flag_only}"
PADDING = "x" * (2 * 1024 * 1024 + 200)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def _send(self, body, status=200, content_type="text/html; charset=utf-8", headers=()):
        data=body.encode(); self.send_response(status); self.send_header("Content-Type",content_type)
        for k,v in headers:self.send_header(k,v)
        self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path == "/":
            return self._send('<a href="/api-docs">#API Documentation</a>')
        if self.path == "/api-docs":
            self.send_response(301);self.send_header("Location","/api-docs/");self.send_header("Content-Length","0");self.end_headers();return
        if self.path == "/api-docs/":
            return self._send('<html><script src="./swagger-ui-init.js"></script></html>')
        if self.path == "/api-docs/swagger-ui-init.js":
            return self._send('var options = {"swaggerDoc":{"paths":{"/heapdump":{"get":{"summary":"Diagnosing the memory allocation."}}}}};',content_type="application/javascript")
        if self.path == "/heapdump":
            return self._send(PADDING+FLAG,content_type="application/octet-stream",headers=(("Content-Disposition",'attachment; filename="heapdump.heapsnapshot"'),))
        return self._send("not found",404)

def start_server():
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler);Thread(target=server.serve_forever,daemon=True).start()
    return server,f"http://127.0.0.1:{server.server_port}/"
