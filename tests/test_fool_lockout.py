import http.server
import sys
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs
from unittest.mock import patch

sys.path.insert(0, "local-engine")
import fool_lockout as fl
import web_session_audit

CHALLENGE = r'''Fool the Lockout
http\://chatelaine.cylabacademy.net:47111/
https\://challenge-files.cylabacademy.net/library/'''+"a"*64+r'''/app.py
https\://challenge-files.cylabacademy.net/library/'''+"a"*64+r'''/creds-dump.txt'''
MOCK_SOURCE = """MAX_REQUESTS = 10\nEPOCH_DURATION = 30\nLOCKOUT_DURATION = 120
if curr_time - epoch_start_time > EPOCH_DURATION:\n    request_rates[client_ip]['num_requests'] = 0
if request_rates[client_ip]['num_requests'] > MAX_REQUESTS:\n    request_rates[client_ip][\"lockout_until\"] = curr_time + LOCKOUT_DURATION\n    return True
"""


class LoginMock(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/login":
            body = b'<form><input name="username"><input name="password"></form>'
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        elif self.path == "/":
            body = b"picoCTF{mock_lockout_success}" if "session=ok" in self.headers.get("Cookie", "") else b"login required"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        fields = parse_qs(body)
        self.server.counter += 1
        if self.server.counter > 10:
            data = b"Rate Limited Exceeded"
            self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        elif fields.get("username") == ["right"] and fields.get("password") == ["secret"]:
            self.send_response(302); self.send_header("Set-Cookie", "session=ok; Path=/"); self.send_header("Location", "/"); self.end_headers()
        else:
            data = b"Invalid username or password"
            self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def log_message(self, *_): pass


class FoolLockoutTests(unittest.TestCase):
    def test_prompt_and_scope_parsing(self):
        self.assertEqual(web_session_audit.detect_named_challenge(CHALLENGE)[1], "fool-the-lockout")
        self.assertEqual(fl.parse_target(CHALLENGE), "http://chatelaine.cylabacademy.net:47111/")
        self.assertIsNone(fl.parse_target("Fool the Lockout http://example.com:47111/"))
        self.assertTrue(all(fl._artifact_urls(CHALLENGE)))

    def test_source_guided_batches_recover_mock_flag(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LoginMock)
        server.counter = 0
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with TemporaryDirectory() as td:
                def fake_download(url, dest, limit):
                    if dest.name == "app.py": dest.write_text(MOCK_SOURCE, encoding="utf-8")
                    else:
                        rows = [f"wrong{i};bad" for i in range(10)] + ["right;secret"]
                        dest.write_text("\n".join(rows), encoding="utf-8")
                def fake_sleep(seconds): server.counter = 0
                with patch.object(fl, "_download", side_effect=fake_download), \
                     patch.object(fl, "parse_target", return_value=f"http://127.0.0.1:{server.server_port}/"):
                    result = fl.solve(CHALLENGE, Path(td), sleeper=fake_sleep)
            self.assertTrue(result["success"], result)
            self.assertEqual(result["flag"], "picoCTF{mock_lockout_success}")
            self.assertEqual(result["checked"], 11)
            self.assertEqual(server.counter, 1)  # the wait reset the test server counter before record 11
        finally:
            server.shutdown(); server.server_close()


if __name__ == "__main__": unittest.main()
