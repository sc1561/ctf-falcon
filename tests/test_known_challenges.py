import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "local-engine"))
import web_session_audit as wsa

FLAG = "academy{web_succ3ssfully_d3c0ded_07989b25}"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'<html><head><link rel="stylesheet" href="/assets/site.css"></head><body><a href="about.html">About</a> WebDecode</body></html>'
            status, ctype = 200, "text/html"
        elif self.path == "/about.html":
            body = b'<section notify_true="YWNhZGVteXt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfMDc5ODliMjV9"></section>'
            status, ctype = 200, "text/html"
        elif self.path == "/assets/site.css":
            body = b'ul{ padding: 0; margin: 0; }'
            status, ctype = 200, "text/css"
        else:
            body, status, ctype = b"not found", 404, "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

class CookieHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if self.path == "/check" and "name=7" in cookie:
            status, location, body = 200, None, b'<p>picoCTF{numbered_cookie_verified}</p>'
        elif self.path == "/check":
            status, location, body = 302, "/", b""
        elif self.path == "/":
            status, location, body = 302, "/check", b""
        else:
            status, location, body = 404, None, b"not found"
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

class IncludesHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body, ctype = b'<link rel="stylesheet" href="style.css"><script src="script.js"></script>', "text/html"
        elif self.path == "/style.css":
            body, ctype = b'body { background: lightblue; }\n/* academy{1nclu51v17y_1of2_ */', "text/css"
        elif self.path == "/script.js":
            body, ctype = b'function greetings(){ alert("Separate file"); }\n// f7w_2of2_64d6df37}', "application/javascript"
        else:
            body, ctype = b"not found", "text/plain"
        self.send_response(200 if self.path in {"/", "/style.css", "/script.js"} else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass

SCAVENGER_FLAG = "academy{th4ts_4_l0t_0f_pl4c3s_2_lO0k_f7ce8828}"

class ScavengerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        pages = {
            "/": (b'<!-- Here\'s the first part of the flag: academy{t -->'
                  b'<link rel="stylesheet" href="/mycss.css"><script src="/myjs.js"></script>', "text/html"),
            "/mycss.css": (b'/* CSS part 2: h4ts_4_l0 */', "text/css"),
            "/myjs.js": (b'/* How can I keep Google from indexing my website? */', "application/javascript"),
            "/robots.txt": (b'User-agent: *\nDisallow: /index.html\n# Part 3: t_0f_pl4c\n# Apache server: Access the next flag', "text/plain"),
            "/.htaccess": (b'# Part 4: 3s_2_lO0k\n# On my Mac I can Store a lot of information', "text/plain"),
            "/.DS_Store": (b'Congrats! Part 5: _f7ce8828}', "application/octet-stream"),
            "/index.html": (b"ordinary index", "text/html"),
        }
        body, ctype = pages.get(self.path, (b"not found", "text/plain"))
        self.send_response(200 if self.path in pages else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass

HEAD_FLAG = "academy{head_method_verified}"

class GetAheadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b'<form action="/index.php" method="GET"><button>Red</button></form>'
                b'<form action="/index.php" method="POST"><button>Blue</button></form>')
        self.send_response(200 if self.path == "/" else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_HEAD(self):
        self.send_response(200 if self.path == "/index.php" else 404)
        if self.path == "/index.php": self.send_header("flag", HEAD_FLAG)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args): pass

CLIENT_FLAG = "academy{never_trust_client}"

class DontUseClientSideHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'''<input id="pass"><script>
function verify() { var checkpass = document.getElementById("pass").value; split = 4;
if (checkpass.substring(split*5, split*6) == 'clie') {}
if (checkpass.substring(0, split) == 'acad') {}
if (checkpass.substring(split*6, split*7) == 'nt}') {}
if (checkpass.substring(split, split*2) == 'emy{') {}
if (checkpass.substring(split*3, split*4) == 'r_tr') {}
if (checkpass.substring(split*2, split*3) == 'neve') {}
if (checkpass.substring(split*4, split*5) == 'ust_') {}
}
</script><script src="/md5.js"></script>'''
            status = 200
        else:
            body, status = b"not found", 404
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass


def test_webdecode_linked_assets():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        result = wsa.run_audit(f"http://127.0.0.1:{srv.server_port}/", challenge_text="## WebDecode")
    finally:
        srv.shutdown()
        thread.join(timeout=2)
        srv.server_close()
    assert result["recognized"] is True, result
    assert result["analyzer"] == "webdecode", result
    assert result["success"] is True and result["flag"] == FLAG, result
    assert "/about.html" in result["discovered"]["resources_checked"], result


def test_css_rule_is_not_misreported_as_flag():
    assert wsa.extract_flag([("stylesheet", "ul{   padding: 0;   margin: 0; }")], wsa.DEFAULT_FLAG_PATTERNS)[0] is None


def test_includes_reconstructs_only_comment_fragments():
    srv = HTTPServer(("127.0.0.1", 0), IncludesHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
    try:
        result = wsa.run_audit(f"http://127.0.0.1:{srv.server_port}/", challenge_text="## Includes\nWeb Exploitation")
    finally:
        srv.shutdown(); thread.join(timeout=2); srv.server_close()
    assert result["success"] and result["flag"] == "academy{1nclu51v17y_1of2_f7w_2of2_64d6df37}", result
    assert result["flag_source"] == "includes comment fragments", result


def test_challenge_detection_is_specific():
    assert wsa.detect_named_challenge("## WebDecode\nWeb ExploitationEasy") == ("WebDecode", "webdecode")
    assert wsa.detect_named_challenge("ordinary page with no challenge name") is None
    # Longest key wins: Cookie Monster must not be confused with Cookies 2021.
    assert wsa.detect_named_challenge("Cookie Monster Secret Recipe") == ("Cookie Monster Secret Recipe", "cookie-monster")
    assert wsa.detect_named_challenge("## GET aHEAD\nWeb ExploitationEasy") == ("GET aHEAD", "get-ahead")

def test_cookies_numeric_range_is_bounded_and_stops_on_flag():
    srv = HTTPServer(("127.0.0.1", 0), CookieHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        result = wsa.run_audit(f"http://127.0.0.1:{srv.server_port}/", challenge_text="## Cookies picoCTF 2021")
    finally:
        srv.shutdown()
        thread.join(timeout=2)
        srv.server_close()
    assert result["success"] is True and result["flag"] == "picoCTF{numbered_cookie_verified}", result
    assert len(result["steps"]) <= 24, len(result["steps"])
    assert any(step["url"].endswith("/check") for step in result["steps"]), result["steps"]
    assert any(step["location"] == "/check" for step in result["steps"]), result["steps"]

def test_scavenger_hunt_reconstructs_numbered_parts_from_discovered_files():
    srv = HTTPServer(("127.0.0.1", 0), ScavengerHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
    try:
        result = wsa.run_audit(f"http://127.0.0.1:{srv.server_port}/", challenge_text="## Scavenger Hunt\nWeb Exploitation")
    finally:
        srv.shutdown(); thread.join(timeout=2); srv.server_close()
    assert result["success"] and result["flag"] == SCAVENGER_FLAG, result
    assert result["flag_source"] == "Scavenger Hunt ordered parts", result
    source_names = [label.rsplit("/", 1)[-1] for label in result["discovered"]["flag_fragment_sources"]]
    assert source_names == ["", "mycss.css", "robots.txt", ".htaccess", ".DS_Store"], result
    assert "/index.html" in result["discovered"]["resources_checked"], result

def test_get_ahead_uses_head_on_form_action_and_reads_headers():
    srv = HTTPServer(("127.0.0.1", 0), GetAheadHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
    try:
        result = wsa.run_audit(f"http://127.0.0.1:{srv.server_port}/", challenge_text="## GET aHEAD\nWeb Exploitation")
    finally:
        srv.shutdown(); thread.join(timeout=2); srv.server_close()
    assert result["recognized"] and result["analyzer"] == "get-ahead", result
    assert result["success"] and result["flag"] == HEAD_FLAG, result
    assert result["flag_source"].startswith("HEAD response headers"), result
    assert any(step["method"] == "HEAD" and step["url"].endswith("/index.php") for step in result["steps"]), result

def test_dont_use_client_side_reassembles_substring_checks():
    srv = HTTPServer(("127.0.0.1", 0), DontUseClientSideHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
    try:
        result = wsa.run_audit(f"http://127.0.0.1:{srv.server_port}/", challenge_text="## dont-use-client-side\nWeb ExploitationEasy")
    finally:
        srv.shutdown(); thread.join(timeout=2); srv.server_close()
    assert result["recognized"] and result["analyzer"] == "dont-use-client-side", result
    assert result["success"] and result["flag"] == CLIENT_FLAG, result
    assert result["flag_source"] == "client-side substring checks", result
    assert result["discovered"]["client_side_check_segments"] == 7, result

if __name__ == "__main__":
    test_webdecode_linked_assets()
    test_css_rule_is_not_misreported_as_flag()
    test_includes_reconstructs_only_comment_fragments()
    test_challenge_detection_is_specific()
    test_cookies_numeric_range_is_bounded_and_stops_on_flag()
    test_scavenger_hunt_reconstructs_numbered_parts_from_discovered_files()
    test_get_ahead_uses_head_on_form_action_and_reads_headers()
    test_dont_use_client_side_reassembles_substring_checks()
    print("known challenge tests passed")
