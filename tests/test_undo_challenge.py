import sys
import base64
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "local-engine"))
import undo_challenge as undo
import web_session_audit


def main():
    announcement = ("Can you reverse a series of Linux text transformations to recover the original flag?\n"
        "Start searching for the flag here nc chatelaine.cylabacademy.net 40561\nHints\n"
        "For text translation and character replacement, see\ntr\ncommand documentation\n"
        "https://man7.org/linux/man-pages/man1/tr.1.html")
    assert web_session_audit.detect_named_challenge(announcement) == ("Undo", "undo")
    assert undo.parse_target(announcement) == ("chatelaine.cylabacademy.net", 40561)
    assert undo.parse_target("Undo\nnc attacker.example 40561") is None
    class FakeSocket:
        def __init__(self): self.sent = 0
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def settimeout(self, _): pass
        def recv(self, _):
            if self.sent: return b""
            self.sent = 1
            return b"Stage 1: ROT13\n"
    def connector(address, timeout):
        assert address == ("chatelaine.cylabacademy.net", 40561) and timeout == 4.0
        return FakeSocket()
    banner = undo.connect_transcript(announcement, connector=connector)
    assert banner["ok"] and banner["transcript"] == "Stage 1: ROT13" and banner["sent_bytes"] == 0, banner

    result = undo.analyze("Undo\npicoCTF", "Stage 1: encoded with ROT13\nStage 2: reversed using rev")
    assert result["ok"] and result["analyzer"] == "undo", result
    assert [s["operation"] for s in result["inverse_steps"]] == ["rev", "rot13"], result
    assert result["inverse_steps"][0]["inverse_command"] == "rev", result
    assert result["inverse_steps"][1]["inverse_command"] == "tr 'A-Za-z' 'N-ZA-Mn-za-m'", result

    original = "picoCTF{undo_chain_test}"
    final = base64.b64encode(original[::-1].encode()).decode()
    recovered = undo.analyze("Undo", f"Stage 1: applied rev\nStage 2: applied base64\nTransformed flag: {final}")
    assert recovered["flag"] == original, recovered
    assert [s["operation"] for s in recovered["recovery_steps"]] == ["base64", "rev"], recovered

    mapped = undo.analyze("Undo", "The original string was translated using tr 'abc' 'xyz'")
    assert mapped["inverse_steps"][0]["inverse_command"] == "tr 'xyz' 'abc'", mapped
    rot_command = undo.analyze("Undo", "Run tr 'A-Za-z' 'N-ZA-Mn-za-m' on the text")
    assert rot_command["inverse_steps"][0]["inverse_command"] == "tr 'N-ZA-Mn-za-m' 'A-Za-z'", rot_command
    lossy = undo.analyze("Undo", "The string was translated using tr 'aabc' 'xyzz'")
    assert "غير قابل للعكس" in lossy["inverse_steps"][0]["inverse_command"], lossy
    collision = undo.analyze("Undo", "tr 'ab' 'cc'")
    assert "غير قابل للعكس" in collision["inverse_steps"][0]["inverse_command"], collision

    empty = undo.analyze("Undo", "  ")
    assert not empty["ok"]
    print("Undo challenge explanation tests passed")


if __name__ == "__main__":
    main()
