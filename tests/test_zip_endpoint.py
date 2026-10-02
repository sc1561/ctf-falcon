import base64
import importlib.util
import json
import sys
import threading
import urllib.error
import urllib.request
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "local-engine"))
spec = importlib.util.spec_from_file_location("falcon_zip_engine", ROOT / "local-engine" / "falcon_local.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

ENCRYPTED_ZIP = base64.b64decode(
    "UEsDBAoACQAAAMFrQl0RztUMKwAAAB8AAAAIABwAZmxhZy50eHRVVAkAA1pBv2paQb9qdXgLAAEEAAAAAAQAAAAAYEYQuMYiPh+M5ORM7+uJY79wymMzawbnmrKJQHJUe97aOuJWpd+q9VRG+VBLBwgRztUMKwAAAB8AAABQSwECHgMKAAkAAADBa0JdEc7VDCsAAAAfAAAACAAYAAAAAAABAAAApIEAAAAAZmxhZy50eHRVVAUAA1pBv2p1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBOAAAAfQAAAAAA"
)


class ZipEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = engine.ThreadingHTTPServer(("127.0.0.1", 0), engine.H)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%s" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)

    def post(self, path, payload, headers=None):
        req = urllib.request.Request(self.url + path, data=payload,
                                     headers=headers or {"Content-Type": "application/json"})
        return urllib.request.urlopen(req, timeout=5)

    def test_artifact_endpoint_recognizes_encrypted_zip(self):
        with self.post("/artifacts/analyze", ENCRYPTED_ZIP,
                       {"Content-Type": "application/octet-stream", "X-Filename": "lock.zip"}) as response:
            data = json.load(response)
        self.assertEqual(data["encrypted_archives"][0]["algorithm"], "ZipCrypto")

    def test_candidate_endpoint_recovers_and_scans_flag(self):
        request = {"confirm": True, "filename": "lock.zip",
                   "archive_b64": base64.b64encode(ENCRYPTED_ZIP).decode(),
                   "candidates": ["wrong", "falcon123"]}
        with self.post("/archives/crack", json.dumps(request).encode()) as response:
            data = json.load(response)
        self.assertTrue(data["success"])
        self.assertEqual(data["password"], "falcon123")
        self.assertEqual(data["analysis"]["flags"][0]["flag"], "picoCTF{zip_password_recovered}")

    def test_candidate_endpoint_requires_explicit_start(self):
        request = {"confirm": False, "archive_b64": base64.b64encode(ENCRYPTED_ZIP).decode(), "candidates": ["x"]}
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post("/archives/crack", json.dumps(request).encode())
        self.assertEqual(caught.exception.code, 400)

    def test_evidence_endpoint_recovers_without_supplied_wordlist(self):
        request = {"confirm": True, "filename": "falcon123.zip",
                   "archive_b64": base64.b64encode(ENCRYPTED_ZIP).decode()}
        with self.post("/archives/recover", json.dumps(request).encode()) as response:
            data = json.load(response)
        self.assertTrue(data["success"])
        self.assertEqual(data["password"], "falcon123")
        self.assertEqual(data["analysis"]["flags"][0]["flag"], "picoCTF{zip_password_recovered}")

    def test_health_advertises_zip_capabilities(self):
        with urllib.request.urlopen(self.url + "/health", timeout=5) as response:
            data = json.load(response)
        self.assertTrue(data["encrypted_zip_detection"])
        self.assertTrue(data["zipcrypto_wordlist_recovery"])
        self.assertTrue(data["zip_evidence_password_recovery"])

    def test_health_allows_loopback_ui_origin_only(self):
        req = urllib.request.Request(self.url + "/health", headers={"Origin": "http://127.0.0.1:8000"})
        with urllib.request.urlopen(req, timeout=5) as response:
            self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "http://127.0.0.1:8000")
        self.assertEqual(engine.allowed_origin(type("Request", (), {"headers": {"Origin": "https://attacker.example"}})()),
                         "https://sc1561.github.io")


if __name__ == "__main__":
    unittest.main()
