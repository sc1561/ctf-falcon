import base64
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "local-engine"))
from no_fa_analysis import analyze_artifacts, decode_flask_session


class NoFaAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        (self.folder / "app.py").write_text(
            "hashlib.sha256(password.encode()).hexdigest()\n"
            "session['otp_secret'] = otp\n"
            "otp = str(random.randint(1000, 9999))\n"
            "(time.time() - timestamp) < 120\n",
            encoding="utf-8",
        )
        with sqlite3.connect(self.folder / "users.db") as connection:
            connection.execute("CREATE TABLE users (username TEXT, password TEXT, two_fa INTEGER)")
            connection.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                ("admin", hashlib.sha256(b"apple@123").hexdigest(), 1),
            )
            connection.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                ("student", hashlib.sha256(b"student-password").hexdigest(), 0),
            )

    def tearDown(self):
        self.temp.cleanup()

    def test_analyzes_only_expected_artifacts_and_finds_candidate(self):
        result = analyze_artifacts(self.folder)
        self.assertTrue(result["files"]["app.py"]["exists"])
        self.assertTrue(result["files"]["users.db"]["exists"])
        self.assertEqual(result["account_count"], 2)
        self.assertTrue(result["admin"]["two_fa"])
        self.assertEqual(result["admin"]["password_candidate"], "apple@123")
        self.assertIn("otp_stored_in_flask_session", result["source_findings"])
        self.assertIn("otp_valid_for_120_seconds", result["source_findings"])

    def test_missing_artifacts_are_reported_without_failure(self):
        result = analyze_artifacts(self.folder / "missing")
        self.assertFalse(result["files"]["app.py"]["exists"])
        self.assertFalse(result["files"]["users.db"]["exists"])

    def test_decodes_compressed_flask_cookie_payload(self):
        payload = zlib.compress(json.dumps({
            "username": "admin", "logged": "false", "otp_secret": "4821", "otp_timestamp": 123.5
        }).encode())
        encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        cookie = "." + encoded + ".signature"
        decoded = decode_flask_session("Cookie: other=value; session=" + cookie + "; Path=/")
        self.assertEqual(decoded["username"], "admin")
        self.assertEqual(decoded["otp_secret"], "4821")
        self.assertFalse(decoded["signature_verified"])

    def test_incomplete_compressed_cookie_has_clear_error(self):
        with self.assertRaisesRegex(ValueError, "غير مكتملة"):
            decode_flask_session("session=.")


if __name__ == "__main__":
    unittest.main()
