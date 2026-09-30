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
        body = b'<p>Cookie challenge</p>'
        if "name=7" in cookie:
            body = b'<p>picoCTF{numbered_cookie_verified}</p>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass


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


def test_challenge_detection_is_specific():
    assert wsa.detect_named_challenge("## WebDecode\nWeb ExploitationEasy") == ("WebDecode", "webdecode")
    assert wsa.detect_named_challenge("ordinary page with no challenge name") is None
    # Longest key wins: Cookie Monster must not be confused with Cookies 2021.
    assert wsa.detect_named_challenge("Cookie Monster Secret Recipe") == ("Cookie Monster Secret Recipe", "cookie-monster")

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
    assert len(result["steps"]) <= 10, len(result["steps"])

if __name__ == "__main__":
    test_webdecode_linked_assets()
    test_css_rule_is_not_misreported_as_flag()
    test_challenge_detection_is_specific()
    test_cookies_numeric_range_is_bounded_and_stops_on_flag()
    print("known challenge tests passed")
