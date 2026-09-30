import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "local-engine"))
import web_session_audit as wsa

FLAG = "academy{intro_burp_missing_otp_verified}"
state = {"otp_body": None, "registered": False}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'''<form method="POST">
              <input type="hidden" name="csrf_token" value="csrf-test">
              <input name="full_name"><input name="username"><input name="phone_number">
              <input name="city"><input name="password" type="password">
              <input name="submit" type="submit" value="Register"></form>'''
        elif self.path == "/dashboard" and state["registered"]:
            body = b'<form method="POST"><input type="text" name="otp"><button>Submit</button></form>'
        else:
            body = b"not found"
        self.send_response(200 if body != b"not found" else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        if self.path == "/":
            fields = parse_qs(body)
            if fields.get("csrf_token") == ["csrf-test"] and fields.get("username"):
                state["registered"] = True
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", "session=mock; Path=/; HttpOnly")
                self.end_headers()
            else:
                self.send_response(400); self.end_headers()
        elif self.path == "/dashboard":
            state["otp_body"] = body
            if "otp" not in parse_qs(body, keep_blank_values=True):
                out = ("Your Flag: " + FLAG).encode()
            else:
                out = b"Invalid OTP"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers(); self.wfile.write(out)
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *args):
        pass


def run(text):
    state.update(otp_body=None, registered=False)
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        result = wsa.run_audit(f"http://127.0.0.1:{server.server_port}/", challenge_text=text)
    finally:
        server.shutdown(); thread.join(timeout=2); server.server_close()
    return result


def test_empty_otp_bypass_only_after_observed_registration_and_otp_forms():
    res = run("## IntroToBurp\nWeb Exploitation Easy")
    assert res["recognized"] and res["analyzer"] == "intro-to-burp", res
    assert res["success"] and res["flag"] == FLAG, res
    assert state["registered"] is True and state["otp_body"] == "", state
    assert [s["method"] for s in res["steps"]] == ["GET", "POST", "GET", "POST"], res["steps"]


def test_unrecognized_page_never_submits_registration():
    res = run("ordinary unrelated page")
    assert res["recognized"] is False and len(res["steps"]) == 1, res
    assert state["registered"] is False and state["otp_body"] is None, state

if __name__ == "__main__":
    test_empty_otp_bypass_only_after_observed_registration_and_otp_forms()
    test_unrecognized_page_never_submits_registration()
    print("IntroToBurp analyzer tests passed")
