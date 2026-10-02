import base64
import io
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "local-engine"))
from artifact_extractor import analyze_artifact
from zip_challenge import derive_candidates, inspect_zip, recover_zip, recover_zip_auto

# Tiny classic ZipCrypto fixture generated for tests; no external cracker is required.
ENCRYPTED_ZIP = base64.b64decode(
    "UEsDBAoACQAAAMFrQl0RztUMKwAAAB8AAAAIABwAZmxhZy50eHRVVAkAA1pBv2paQb9qdXgLAAEEAAAAAAQAAAAAYEYQuMYiPh+M5ORM7+uJY79wymMzawbnmrKJQHJUe97aOuJWpd+q9VRG+VBLBwgRztUMKwAAAB8AAABQSwECHgMKAAkAAADBa0JdEc7VDCsAAAAfAAAACAAYAAAAAAABAAAApIEAAAAAZmxhZy50eHRVVAUAA1pBv2p1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBOAAAAfQAAAAAA"
)


class EncryptedZipTests(unittest.TestCase):
    def test_detects_zipcrypto_and_reports_student_next_step(self):
        result = analyze_artifact(ENCRYPTED_ZIP, "lockbreaker.zip")
        self.assertEqual(result["encrypted_archives"][0]["algorithm"], "ZipCrypto")
        self.assertEqual(result["encrypted_archives"][0]["files"], ["flag.txt"])
        self.assertIn("كلمة مرور", result["summary"])
        self.assertFalse(any("تعذر قراءة عنصر ZIP" in x for x in result["findings"]))

    def test_only_supplied_candidates_are_tried_and_flag_is_recovered(self):
        failed = recover_zip(ENCRYPTED_ZIP, ["wrong", "nope"])
        self.assertFalse(failed["success"])
        self.assertEqual(failed["attempts"], 2)
        result = recover_zip(ENCRYPTED_ZIP, ["wrong", "falcon123"])
        self.assertTrue(result["success"])
        self.assertEqual(result["password"], "falcon123")
        self.assertEqual(result["members"][0][1], b"picoCTF{zip_password_recovered}")

    def test_rejects_empty_or_excessive_candidate_list(self):
        result = recover_zip(ENCRYPTED_ZIP, [])
        self.assertFalse(result.get("success", False))
        self.assertEqual(result["attempts"], 0)

    def test_auto_search_derives_and_uses_password_from_archive_filename(self):
        candidates, sources = derive_candidates(ENCRYPTED_ZIP, "falcon123.zip")
        self.assertIn("falcon123", candidates)
        self.assertIn("اسم الأرشيف", sources)
        result = recover_zip_auto(ENCRYPTED_ZIP, "falcon123.zip")
        self.assertTrue(result["success"])
        self.assertEqual(result["password"], "falcon123")

    def test_auto_search_explains_when_archive_has_no_password_clue(self):
        result = recover_zip_auto(ENCRYPTED_ZIP, "lock.zip")
        self.assertFalse(result["success"])
        self.assertIn("ليست محفوظة", result["error"])

    def test_plain_zip_is_not_misclassified_as_encrypted(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("flag.txt", "picoCTF{plain_zip}")
        self.assertFalse(inspect_zip(data.getvalue())["encrypted"])


if __name__ == "__main__":
    unittest.main()
