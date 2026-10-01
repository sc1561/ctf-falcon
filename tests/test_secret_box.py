import http.server
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, "local-engine")
import secret_box
import web_session_audit


class MockVault(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_html(200, getattr(self.server, "my_secret", "My Secrets"))
        elif self.path == "/signup":
            self.send_html(200, '<form><input name="username"><input name="password"></form>')
        elif self.path == "/secrets/create":
            self.send_html(200, '<form><textarea name="content"></textarea></form>')
        else:
            self.send_html(404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        if self.path == "/signup":
            self.send_html(200, "Create User Successful")
        elif self.path == "/login":
            self.send_response(302); self.send_header("Set-Cookie", "auth_token=mock-session; Path=/")
            self.send_header("Location", "/"); self.end_headers()
        elif self.path == "/secrets/create":
            from urllib.parse import parse_qs
            content = parse_qs(body).get("content", [""])[0]
            if "SELECT user_id FROM tokens WHERE id='mock-session'" in content and secret_box.ADMIN_ID in content:
                self.server.my_secret = "picoCTF{mock_secret_copied}"
                self.send_response(302); self.send_header("Location", "/"); self.end_headers()
            else:
                self.send_html(400, "bad payload")
        else:
            self.send_html(404, "not found")

    def send_html(self, status, text):
        raw = text.encode(); self.send_response(status); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def log_message(self, *_):
        pass


class SecretBoxTests(unittest.TestCase):
    def test_detect_prompt_without_title_and_escaped_url(self):
        text = "This secret box is designed to conceal your secrets http\\://xebec.cylabacademy.net:44859/"
        self.assertEqual(web_session_audit.detect_named_challenge(text)[1], "secret-box")
        self.assertEqual(secret_box.parse_target(text), "http://xebec.cylabacademy.net:44859/")

    def test_source_guided_solver_on_mock_vault(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockVault)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with patch.object(secret_box, "parse_target", return_value=f"http://127.0.0.1:{server.server_port}/"):
                result = secret_box.solve("Secret Box CTF test")
            self.assertTrue(result["success"], result)
            self.assertEqual(result["flag"], "picoCTF{mock_secret_copied}")
            self.assertEqual([s["path"] for s in result["steps"]],
                ["/", "/signup", "/signup", "/login", "/secrets/create", "/secrets/create", "/"])
        finally:
            server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
