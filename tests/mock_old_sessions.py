# -*- coding: utf-8 -*-
"""
خادم وهمي يحاكي تحدي "Old Sessions" لاختبار المدقّق محليًا (stdlib فقط).
Faithful-enough mock of the Old Sessions challenge for offline testing.

يعيد إنتاج:
  GET  /            بلا جلسة  -> 302 /login + كوكي جلسة (Expires 2058, HttpOnly)
  GET  /login       -> 200 + حذف الكوكي (Max-Age=0) + نموذج + رابط /register
  GET  /register    -> 200 + نموذج (username, password, conf_password)
  POST /register    -> 400 إن نقص conf_password، وإلا 302 /login
  POST /login       -> 302 / + كوكي جلسة طويلة (مستخدم عادي)
  GET  / (مستخدم)   -> 200 + Welcome + تعليق "strange page at /sessions"
  GET  /sessions    -> 200 + تسريب كل جلسات الخادم (ومنها جلسة المشرف)
  GET  / (مشرف)     -> 200 + العلم
"""
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

FLAG = "picoCTF{c00ki3s_4nd_s3ssi0ns_2058}"

# مخزن الجلسات: token -> dict، ومخزن المستخدمين: username -> password
SESSIONS = {}
USERS = {}

# جلسة المشرف "القديمة" الدائمة — جوهر التحدي
ADMIN_TOKEN = "adm_" + secrets.token_hex(16)
SESSIONS[ADMIN_TOKEN] = {"_permanent": True, "username": "admin", "admin": True}
USERS["admin"] = secrets.token_hex(12)

FAR_FUTURE = "Expires=Tue, 19 Jan 2058 03:14:07 GMT"


def _cookie(name, value, delete=False):
    if delete:
        return f"{name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/"
    return f"{name}={value}; {FAR_FUTURE}; HttpOnly; Path=/"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # صامت أثناء الاختبار
        pass

    # -- أدوات ------------------------------------------------------------- #
    def _session(self):
        raw = self.headers.get("Cookie", "")
        m = re.search(r"session=([^;]+)", raw)
        if not m:
            return None, None
        tok = m.group(1)
        return tok, SESSIONS.get(tok)

    def _send(self, status, body="", cookies=None, location=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for c in (cookies or []):
            self.send_header("Set-Cookie", c)
        if location:
            self.send_header("Location", location)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _read_form(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8") if n else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    # -- GET --------------------------------------------------------------- #
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        tok, sess = self._session()

        if path == "/":
            if sess and sess.get("admin"):
                return self._send(200, f"<h1>Admin panel</h1><p>Welcome admin.</p><p>{FLAG}</p>")
            if sess:
                return self._send(
                    200,
                    f"<h1>Welcome {sess.get('username','user')}</h1>"
                    "<a href='/logout'>logout</a>"
                    "<!-- general comments -->"
                    "<p>Hey I found a strange page at /sessions</p>",
                )
            # بلا جلسة صالحة: أنشئ كوكي وحوّل إلى /login
            newtok = "anon_" + secrets.token_hex(8)
            SESSIONS[newtok] = {"_permanent": True, "anon": True}
            return self._send(302, "", cookies=[_cookie("session", newtok)], location="/login")

        if path == "/login":
            return self._send(
                200,
                "<h1>Login</h1><form method='POST' action='/login'>"
                "<input name='username'><input name='password' type='password'>"
                "<button>login</button></form><a href='/register'>register</a>",
                cookies=[_cookie("session", "", delete=True)],
            )

        if path == "/register":
            return self._send(
                200,
                "<h1>Register</h1><form method='POST' action='/register'>"
                "<input name='username'><input name='password' type='password'>"
                "<input name='conf_password' type='password'><button>register</button></form>",
            )

        if path == "/sessions":
            if not sess:
                return self._send(302, "", location="/login")
            lines = ["<h1>Sessions</h1>"]
            for i, (t, d) in enumerate(SESSIONS.items(), 1):
                lines.append(f"<p>{i}) session:{t}, {d}</p>")
            return self._send(200, "".join(lines))

        if path == "/logout":
            if tok in SESSIONS:
                del SESSIONS[tok]
            return self._send(302, "", cookies=[_cookie("session", "", delete=True)], location="/login")

        return self._send(404, "<h1>404</h1>")

    # -- POST -------------------------------------------------------------- #
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        form = self._read_form()

        if path == "/register":
            if "conf_password" not in form or form.get("password") != form.get("conf_password"):
                return self._send(400, "<h1>400</h1><p>conf_password required / mismatch</p>")
            USERS[form.get("username", "")] = form.get("password", "")
            return self._send(302, "", location="/login")

        if path == "/login":
            u, p = form.get("username"), form.get("password")
            if u in USERS and USERS[u] == p:
                newtok = "usr_" + secrets.token_hex(12)
                SESSIONS[newtok] = {"_permanent": True, "username": u, "admin": False}
                return self._send(302, "", cookies=[_cookie("session", newtok)], location="/")
            return self._send(200, "<h1>Login</h1><p>invalid</p>")

        return self._send(404, "<h1>404</h1>")


def start_server(host="127.0.0.1", port=0):
    """يشغّل الخادم في خيط ويعيد (server, base_url)."""
    srv = ThreadingHTTPServer((host, port), Handler)
    real_port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://{host}:{real_port}/"


if __name__ == "__main__":
    srv, base = start_server(port=8799)
    print(f"Mock Old Sessions running at {base} (flag hidden). Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
