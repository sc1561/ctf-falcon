# -*- coding: utf-8 -*-
"""
خادم وهمي يحاكي تحدي "Crack the Gate 1" لاختبار المحلل محليًا (stdlib فقط).

يعيد إنتاج:
  GET  /         -> 200 + تعليق ROT13 يكشف ترويسة مطوّر + سكربت fetch('/login') JSON
  POST /login    -> إن كانت الترويسة X-Dev-Access: yes موجودة => {success, flag}
                    وإلا 401. JSON غير صالح => 400.
  /register /sessions -> 404 (يجب ألا يطلبهما محلل هذا التحدي)

الأوضاع (mode):
  ok        : الترويسة تُنجح الدخول وتعيد العلم (الوضع الافتراضي).
  no_flag   : الدخول ناجح لكن بلا علم في الاستجابة.
  reject    : يرفض دائمًا (401) بصرف النظر عن الترويسة.
  text_flag : يعيد العلم كنص عادي (لا JSON) لاختبار الالتقاط بالنمط.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = "academy{r0t13_h34d3r_byp4ss}"
EMAIL = "ctf-player@cylabacademy.org"
DEV_HEADER = ("X-Dev-Access", "yes")

# التعليق كما يظهر في الصفحة (مُرمّز ROT13) — يفكّ إلى:
#   NOTE: Jack - temporary bypass: use header "X-Dev-Access: yes"
ROT13_COMMENT = 'ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"'

PAGE = (
    "<!doctype html><html><head><title>Crack the Gate</title></head><body>"
    "<h1>Members Area</h1>"
    "<!-- " + ROT13_COMMENT + " -->"
    "<p>Login email: " + EMAIL + "</p>"
    "<form id='f'><input name='email'><input name='password' type='password'>"
    "<button>Enter</button></form>"
    "<script>"
    "async function login(email,password){"
    "const r=await fetch('/login',{method:'POST',"
    "headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({email:email,password:password})});"
    "const d=await r.json(); if(d.success){show(d.flag)} else {show('denied')}}"
    "</script></body></html>"
)


def make_handler(mode="ok"):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, status, body="", ctype="text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/":
                return self._send(200, PAGE)
            return self._send(404, "<h1>404</h1>")

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n).decode("utf-8") if n else ""
            if path != "/login":
                return self._send(404, "<h1>404</h1>")
            try:
                json.loads(raw)   # نتحقق من صحة JSON
            except (json.JSONDecodeError, ValueError):
                return self._send(400, json.dumps({"success": False, "error": "bad json"}),
                                  "application/json")
            has_header = self.headers.get(DEV_HEADER[0], "") == DEV_HEADER[1]
            if mode == "reject" or not has_header:
                return self._send(401, json.dumps({"success": False, "error": "unauthorized"}),
                                  "application/json")
            if mode == "error_flag":
                return self._send(401, json.dumps({"success": False, "flag": FLAG}), "application/json")
            if mode == "no_flag":
                return self._send(200, json.dumps({"success": True}), "application/json")
            if mode == "text_flag":
                return self._send(200, "Welcome insider! " + FLAG, "text/plain; charset=utf-8")
            return self._send(200, json.dumps({"success": True, "flag": FLAG}),
                              "application/json")

    return Handler


PLAIN_PAGE = "<!doctype html><html><body><h1>Just a homepage</h1><p>Nothing here.</p></body></html>"


class PlainHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        data = PLAIN_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()


def start_server(mode="ok", host="127.0.0.1", port=0):
    srv = ThreadingHTTPServer((host, port), make_handler(mode))
    real = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://{host}:{real}/"


def start_plain(host="127.0.0.1", port=0):
    srv = ThreadingHTTPServer((host, port), PlainHandler)
    real = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://{host}:{real}/"


if __name__ == "__main__":
    srv, base = start_server(port=8798)
    print(f"Mock Crack the Gate at {base} (flag hidden). Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
