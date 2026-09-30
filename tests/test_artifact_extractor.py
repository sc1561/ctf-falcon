import base64
import gzip
import io
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "local-engine"))
from artifact_extractor import MAX_INPUT_BYTES, analyze_artifact


def make_zip(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return data.getvalue()


class ArtifactExtractorTests(unittest.TestCase):
    def test_finds_flag_through_nested_zip_and_base64_with_provenance(self):
        flag = b"picoCTF{nested_artifact_found}"
        inner = make_zip({"proof.txt": base64.b64encode(flag).decode("ascii")})
        outer = make_zip({"folder/inner.zip": inner})

        result = analyze_artifact(outer, "challenge.zip")

        self.assertEqual([x["flag"] for x in result["flags"]], [flag.decode()])
        self.assertIn("inner.zip", result["flags"][0]["path"])
        self.assertIn("proof.txt", result["flags"][0]["path"])
        self.assertIn("decoded.base64", result["flags"][0]["path"])
        self.assertGreaterEqual(result["extracted_count"], 2)

    def test_decompresses_gzip_and_scans_text(self):
        payload = gzip.compress(b"log entry: picoCTF{gzip_found}")
        result = analyze_artifact(payload, "evidence.gz")
        self.assertEqual(result["flags"][0]["flag"], "picoCTF{gzip_found}")
        self.assertIn("evidence.gz → evidence", result["flags"][0]["path"])

    def test_embedded_zip_after_binary_prefix_is_scanned(self):
        payload = b"MZ\x00binary-prefix" + make_zip({"flag.txt": b"picoCTF{embedded_zip_found}"})
        result = analyze_artifact(payload, "polyglot.bin")
        self.assertIn("picoCTF{embedded_zip_found}", [x["flag"] for x in result["flags"]])

    def test_oversized_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "64 ميغابايت"):
            analyze_artifact(b"x" * (MAX_INPUT_BYTES + 1), "large.bin")


if __name__ == "__main__":
    unittest.main()
