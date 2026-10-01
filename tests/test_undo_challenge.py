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


def test_interactive_solver_answers_one_known_transform_per_stage():
    import socket
    import threading
    import undo_challenge

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received = []

    def service():
        conn, _ = listener.accept()
        with conn:
            commands = [
                ("Base64 encoded the string.", "base64 -d"),
                ("Reversed the text.", "rev"),
                ("Replaced underscores with dashes.", "tr '-' '_'"),
                ("Replaced curly braces with parentheses.", "tr '()' '{}'"),
                ("Applied ROT13 to letters.", "tr 'A-Za-z' 'N-ZA-Mn-za-m'"),
            ]
            reader = conn.makefile("rb")
            for idx, (hint, expected) in enumerate(commands, 1):
                conn.sendall(f"--- Step {idx} ---\nCurrent flag: transformed-{idx}\nHint: {hint}\nEnter the Linux command to reverse it: ".encode())
                answer = reader.readline().decode().strip()
                received.append(answer)
                assert answer == expected
            conn.sendall(b"picoCTF{undo_mock_success}\n")
        listener.close()

    worker = threading.Thread(target=service, daemon=True)
    worker.start()
    challenge = f"Undo nc chatelaine.cylabacademy.net {port}"
    result = undo_challenge.solve_interactive(
        challenge, connector=lambda _target, timeout: socket.create_connection(("127.0.0.1", port), timeout),
        total_timeout=5,
    )
    worker.join(timeout=2)
    assert received == ["base64 -d", "rev", "tr '-' '_'", "tr '()' '{}'",
                        "tr 'A-Za-z' 'N-ZA-Mn-za-m'"]
    assert [step["operation"] for step in result["steps"]] == [
        "base64", "rev", "tr-map", "tr-map", "rot13"]
    assert result["flag"] == "picoCTF{undo_mock_success}"
    assert result["success"] is True


def test_interactive_solver_inverts_only_explicit_bijective_tr_mapping():
    import undo_challenge
    assert undo_challenge._command_for_hint("Applied tr 'A-Za-z' 'N-ZA-Mn-za-m'.") == (
        "tr-map", "tr 'N-ZA-Mn-za-m' 'A-Za-z'")
    assert undo_challenge._command_for_hint("Applied tr 'abc' 'xxx'.") is None


def test_interactive_hint_wording_and_manual_log_guard():
    import undo_challenge
    assert undo_challenge._command_for_hint("Reversed the text.") == ("rev", "rev")
    assert undo_challenge._command_for_hint("Replaced underscores with dashes.") == (
        "tr-map", "tr '-' '_'")
    assert undo_challenge._command_for_hint("Replaced curly braces with parentheses.") == (
        "tr-map", "tr '()' '{}'")
    result = undo_challenge.analyze(
        "Undo nc chatelaine.cylabacademy.net 1",
        "===Welcome to the Text Transformations Challenge!===\n--- Step 1 ---\nCurrent flag: abc\n"
        "Hint: Base64 encoded the string.\n--- Step 2 ---\nCurrent flag: def\nHint: Reversed the text."
    )
    assert result["recovered_text"] is None
    assert result["flag"] is None
    assert any("سجل تفاعلي" in warning for warning in result["warnings"])
